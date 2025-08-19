# Gauntlet USD Alpha (gtUSDa) Investigation Guide

## Contract Address
`0x000000000001cdb57e58fa75fe420a0f4d6640d5` (Base Chain)

## Investigation Steps

### Step 1: Check Contract Code on Basescan

1. Visit: https://basescan.org/address/0x000000000001cdb57e58fa75fe420a0f4d6640d5#code
2. Look for:
   - Is the source code verified?
   - What token standard does it implement?
   - Are there any callbacks or hooks?

### Step 2: Analyze Transfer Functions

Look specifically for these patterns in the code:

#### Pattern A: ERC-777 Callbacks
```solidity
// DANGEROUS - Look for this
function _callTokensReceived(
    address operator,
    address from,
    address to,
    uint256 amount,
    bytes memory userData,
    bytes memory operatorData
) private {
    address implementer = _ERC1820_REGISTRY.getInterfaceImplementer(
        to, 
        _TOKENS_RECIPIENT_INTERFACE_HASH
    );
    if (implementer != address(0)) {
        IERC777Recipient(implementer).tokensReceived(
            operator, from, to, amount, userData, operatorData
        );
    }
}
```

#### Pattern B: Custom Hooks in TransferFrom
```solidity
// DANGEROUS - Look for external calls like this
function transferFrom(address from, address to, uint256 amount) public returns (bool) {
    // ... standard logic ...
    
    // Any of these would be exploitable:
    if (hasHook[from]) {
        IHook(hookAddress).beforeTransfer(from, to, amount);  // DANGER!
    }
    
    // Or:
    _notifyTransfer(from, to, amount);  // Check what this does
    
    // Or:
    if (to.isContract()) {
        IReceiver(to).onTokensReceived(from, amount);  // DANGER!
    }
    
    // ... balance updates ...
}
```

#### Pattern C: Delegated Transfer Logic
```solidity
// DANGEROUS - Delegating to external contract
function transferFrom(address from, address to, uint256 amount) public returns (bool) {
    return ITransferLogic(transferLogic).executeTransfer(from, to, amount);
}
```

### Step 3: Check for Proxy Pattern

Look for:
```solidity
// Proxy indicators
contract gtUSDa is Proxy { ... }
// or
function implementation() public view returns (address);
// or
bytes32 private constant _IMPLEMENTATION_SLOT = 0x...;
```

If it's a proxy:
1. Find the implementation address
2. Check who can upgrade it
3. Analyze the implementation contract

### Step 4: Transaction Analysis

Use Basescan to analyze recent transactions:

1. Go to the "Transactions" tab
2. Look at a few `transferFrom` transactions
3. Check the "Internal Txns" tab - if there are internal transactions during transfers, it indicates external calls
4. Look at gas usage - unusually high gas for transfers might indicate external calls

### Step 5: Event Analysis

Check emitted events during transfers:
1. Look for events from OTHER contracts during gtUSDa transfers
2. This would indicate callbacks or hooks

### Step 6: Bytecode Analysis (If Source Not Verified)

If source code isn't available:
1. Get the bytecode from Basescan
2. Look for these opcodes in transfer-related functions:
   - `CALL` (0xF1) - External call
   - `DELEGATECALL` (0xF4) - Delegated call
   - `STATICCALL` (0xFA) - Static external call
   - `CREATE` (0xF0) or `CREATE2` (0xF5) - Contract creation

### Step 7: Testing on Testnet

Deploy a test contract on Base testnet:

```solidity
contract gtUSDaReentrancyTest {
    address constant GTUSDA = 0x000000000001cdb57e58fa75fe420a0f4d6640d5;
    bool public reentered;
    
    // Try to receive tokens and see if any callbacks are triggered
    function testReceive() external {
        // Get some gtUSDa first
        IERC20(GTUSDA).transferFrom(msg.sender, address(this), 1);
    }
    
    // ERC-777 callback
    function tokensReceived(...) external {
        reentered = true;
    }
    
    // Other possible callbacks
    function onTokenTransfer(...) external {
        reentered = true;
    }
    
    function onTransfer(...) external {
        reentered = true;
    }
    
    // Check if reentered was set to true
}
```

## Red Flags to Look For

### Critical (Definitely Exploitable):
- ✅ Implements ERC-777 with `tokensReceived` callbacks
- ✅ Has custom hooks that call external contracts during transfers
- ✅ Delegates transfer logic to external contracts
- ✅ Makes any external calls during `transferFrom`

### Warning (Potentially Exploitable):
- ⚠️ Is upgradeable (depends on who controls upgrades)
- ⚠️ Has complex transfer logic with multiple conditions
- ⚠️ Integrates with other Gauntlet products during transfers
- ⚠️ Has a "notification" system for transfers

### Safe Indicators:
- ✅ Simple ERC-20 implementation
- ✅ No external calls in transfer functions
- ✅ No proxy/upgrade mechanism
- ✅ Transfer only updates balances and emits events

## Specific Things to Search in Code

Search for these keywords in the contract:
- `tokensReceived`
- `beforeTransfer` or `afterTransfer`
- `onTransfer`
- `hook`
- `callback`
- `notify`
- `.call(`
- `delegatecall`
- `IReceiver` or `IRecipient`
- `external` functions called from `transferFrom`

## Gauntlet Protocol Specifics

Since this is a Gauntlet product:
1. Check if it integrates with other Gauntlet vaults
2. Look for oracle calls during transfers
3. Check for rebalancing logic that might trigger during transfers
4. See if it has yield distribution mechanisms

## Quick Vulnerability Assessment

Rate the token based on findings:

| Feature | Risk Level | Found? |
|---------|------------|---------|
| ERC-777 callbacks | CRITICAL | [ ] |
| Custom transfer hooks | CRITICAL | [ ] |
| External calls in transferFrom | CRITICAL | [ ] |
| Upgradeable by unknown party | HIGH | [ ] |
| Complex transfer logic | MEDIUM | [ ] |
| Integration with external protocols | MEDIUM | [ ] |
| Simple ERC-20 only | SAFE | [ ] |

## Reporting Template

After investigation, document:

```markdown
## gtUSDa Reentrancy Assessment

**Token Standard**: [ERC-20/ERC-777/Custom]
**Has External Calls**: [Yes/No]
**Upgrade Capability**: [Yes/No - Controller: ___]
**Reentrancy Risk**: [None/Low/Medium/High/Critical]

### Evidence:
- [List specific code snippets or transaction hashes]

### Exploit Feasibility:
- [Can be exploited: Yes/No]
- [Required conditions: ___]

### Recommendation:
- [Safe to whitelist / Requires additional controls / Should not be whitelisted]
```

## Alternative Investigation Methods

If direct analysis is difficult:

1. **Contact Gauntlet**: Ask about the token implementation
2. **Check Audits**: Look for Gauntlet protocol audits mentioning gtUSDa
3. **Community Research**: Search for discussions about gtUSDa security
4. **Deploy Test**: Deploy the PoC on testnet with gtUSDa if you can get test tokens

## Conclusion

The key question is: **Does gtUSDa make ANY external calls during transferFrom?**

If yes → The vulnerability can be exploited
If no → The token is safe from this specific attack

Even if gtUSDa is currently safe, the Provisioner contract should still be fixed because:
1. Future token upgrades could introduce vulnerability
2. New tokens might be whitelisted with these features
3. Defense in depth is a security best practice
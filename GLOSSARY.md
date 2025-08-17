# Aera Protocol Glossary

| Term | Definition |
|------|------------|
| **Vault Units** | ERC20 tokens representing shares in the MultiDepositorVault, minted on deposit and burned on withdrawal |
| **Provisioner** | Central contract managing all deposits and redemptions, acting as the entry/exit point for the vault |
| **Guardian** | Whitelisted address authorized to execute vault operations via merkle proof validation |
| **Accountant** | Privileged role that can update vault unit prices in the PriceAndFeeCalculator |
| **Numeraire** | Base currency token used for all price calculations and fee denominations |
| **Sync Deposit** | Immediate deposit that processes instantly but remains refundable for a timeout period |
| **Async Request** | Deposit/redeem request that requires a solver to fulfill, can be auto-price or fixed-price |
| **Solver** | Entity that fulfills async requests, earning tips for providing liquidity |
| **Request Hash** | Unique identifier for async requests, preventing replay attacks |
| **Deposit Cap** | Maximum total value allowed in the vault, denominated in numeraire |
| **Multiplier** | Percentage (in basis points) applied to deposits/redeems for premium/discount pricing |
| **Accrual Lag** | Time period during which fees were not accrued, tracked when vault is paused |
| **Unit Price** | Current price of one vault unit in numeraire terms, with 18 decimal precision |
| **TVL Fee** | Time-based fee charged on total value locked in the vault |
| **Performance Fee** | Fee charged on profits when unit price exceeds the highest historical price |
| **Transfer Hook** | Contract called before vault unit transfers to enforce restrictions (e.g., blacklist) |
| **Merkle Root** | Root hash of merkle tree containing authorized operations for a guardian |
| **Submit** | Function called by guardians to execute batched vault operations |
| **Operation** | Single action within a submit call (e.g., swap, transfer) validated against merkle tree |
| **Whitelist** | Contract maintaining list of approved guardian addresses |
| **Blacklist Oracle** | External oracle (Chainalysis) checking if addresses are sanctioned |
| **Price Age** | Time elapsed since the last price update, used for staleness checks |
| **Price Tolerance** | Acceptable percentage change in price between updates before triggering pause |
| **Update Interval** | Minimum time required between price updates |
| **Refundable Until** | Timestamp until which a sync deposit can be refunded by authorized parties |
| **Deadline** | Expiration time for async requests, after which they can be refunded |
| **Max Price Age** | Maximum acceptable age of price data for request solving |
| **Auto Price** | Request type where price is determined at solve time from oracle |
| **Fixed Price** | Request type where user specifies exact input/output amounts |
| **Enter** | Internal function to deposit tokens and mint vault units |
| **Exit** | Internal function to burn vault units and withdraw tokens |
| **Fee Recipient** | Address authorized to claim accrued vault fees |
| **Protocol Fee Recipient** | Address that receives protocol-level fees |
| **Authority** | Contract implementing access control for privileged functions |
| **Pause/Unpause** | Mechanism to halt vault operations during abnormal conditions |
| **Oracle Registry** | Contract providing price feeds for token conversions |
| **Basis Points (BPS)** | Unit of measurement, 1 BPS = 0.01%, 10000 BPS = 100% |
| **Callback** | Function called after an operation to handle return values |
| **Clipboard** | Mechanism for copying data between operations in a submit call |
| **Hook Flags** | Bitmask indicating which hooks (before/after) are enabled for operations |
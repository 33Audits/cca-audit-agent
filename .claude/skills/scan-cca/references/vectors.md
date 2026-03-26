# CCA Vulnerability Vectors

Vectors are split into two classes. **CORE** vectors target CCA's own logic (relevant when scanning forks or the CCA source itself). **INTEGRATION** vectors target code that calls into or reads from CCA (relevant when scanning protocols built on top). The triage pass determines which class applies based on what code is actually present — both classes can fire simultaneously.

=== CORE VECTORS (bugs in CCA's own code) ===

VC1 — TICK-ITERATION-DOS
Grep: _iterateOverTicksAndFindClearingPrice, MAX_TICK_PTR, TICK_SPACING, forceIterateOverTicks, _checkpointAtBlock

Applicability gate:
Only proceed if the codebase contains a tick-based singly-linked list used for price discovery. Look for a loop that walks tick pointers during checkpoint or submitBid.

Inventory:
- Identify all loops that walk tick pointers (_iterateOverTicksAndFindClearingPrice, forceIterateOverTicks)
- Map TICK_SPACING: is it a constructor param? Is there an on-chain minimum floor enforced in the factory or constructor? (CCA docs recommend "AT LEAST 1 basis point of floor price" but this is guidance, not enforced)
- Check gas bounds: does the iteration loop have a max-iteration cap, gasleft() check, or pagination mechanism?
- Identify forceIterateOverTicks: does it exist? Is it permissionless? Can it be called mid-auction?

Report only if ALL true:
- A loop walks the tick linked list without a gas-bounded exit or max-iteration limit
- TICK_SPACING is configurable without an on-chain minimum floor, OR the enforced minimum is small enough that an attacker can initialize thousands of ticks at reasonable cost (each tick costs one submitBid with dust amount)
- The iteration is on a path reachable by any external caller (submitBid triggers checkpoint which walks ticks)
- No forceIterateOverTicks or equivalent recovery mechanism exists, OR it must be called before the next checkpoint and there is no enforcement of that ordering

Do not report if:
- TICK_SPACING has an enforced on-chain minimum that makes mass-initialization economically infeasible (e.g., minimum 1% of floor price)
- The loop has a gasleft() check or max-iteration bound that caps traversal
- forceIterateOverTicks exists AND is callable permissionlessly AND can complete the iteration across multiple calls without blocking the auction

---

VC2 — PRORATA-MEV
Grep: currencyRaisedAtClearingPriceQ96_X7, _sellTokensAtClearingPrice, exitPartiallyFilledBid, ClearingPriceUpdated

Applicability gate:
Only proceed if the codebase contains pro-rata fill logic at the clearing price tick. Look for accumulators that track currency raised at the clearing price (currencyRaisedAtClearingPriceQ96_X7) and functions that compute partial fills from those accumulators.

Inventory:
- Map the pro-rata accumulation path: how does currencyRaisedAtClearingPriceQ96_X7 get updated? When is it reset? (It resets every time the clearing price changes via checkpoint)
- Identify all reads of the accumulator: exitPartiallyFilledBid uses it with checkpoint hints (lastFullyFilledCheckpointBlock, outbidBlock) to compute a bidder's share
- Check timing constraints: can exitPartiallyFilledBid be called in the same block as a ClearingPriceUpdated event? Is there a block delay?
- Check flashloan composability: can a searcher submitBid + checkpoint + exitPartiallyFilledBid atomically?

Report only if ALL true:
- Pro-rata accumulation at the clearing tick is readable on-chain before a bidder's exit transaction
- A searcher can front-run existing bidders by submitting a bid at the clearing price to dilute their pro-rata share
- exitPartiallyFilledBid (or equivalent) can be called in the same block as a price update, allowing atomic extraction
- No anti-dilution mechanism exists (e.g., time-weighted shares, commit-reveal, minimum hold duration)

Do not report if:
- The pro-rata computation uses a snapshot that cannot be influenced in the same block
- exitPartiallyFilledBid has a minimum hold period or block delay after the bid was submitted
- The accumulator is not readable by external contracts (private with no getter)

---

VC3 — STEP-TAIL-MANIPULATION
Grep: auctionStepsData, mps, END_BLOCK, lbpInitializationParams, $clearingPrice, deltaMps

Applicability gate:
Only proceed if the codebase contains auction step scheduling logic and a mechanism that uses the final clearing price to seed an external pool (Uniswap v4 LBP). Look for step parsing (packed uint64: 24-bit mps + 40-bit blockDelta, MPS=1e7) and lbpInitializationParams.

Inventory:
- Parse the step schedule logic: how are steps packed in auctionStepsData? Each step is a bytes8 with mps (milli-bips per second, 1e7 = 100%) and blockDelta
- Identify what happens at END_BLOCK: the final clearingPrice seeds the v4 pool via lbpInitializationParams
- Check for minimum mps enforcement: does the constructor or factory reject step schedules where the final step has negligible mps?
- Quantify manipulation cost: with a tiny final-step mps, how much capital would shift the clearing price by X%?

Report only if ALL true:
- The step schedule allows a final step with negligible token issuance (tiny mps value) with no on-chain minimum enforcement
- The final clearingPrice at END_BLOCK directly determines the Uniswap v4 pool opening price via lbpInitializationParams
- A single large bid or withdrawal near END_BLOCK can shift the final clearing price because so few tokens anchor it
- No oracle, TWAP, or secondary price source validates the pool opening price

Do not report if:
- The constructor enforces a minimum mps for the final step
- The pool initialization uses a time-weighted price rather than the instantaneous final clearing price
- The step schedule is immutable and set by a trusted deployer with validated parameters (still note as informational if no on-chain enforcement)

---

VC4 — DIRECT-TRANSFER-LOSS
Grep: sweepCurrency, sweepUnsoldTokens, currencyRaised, TOTAL_SUPPLY, balanceOf, onTokensReceived

Applicability gate:
Only proceed if the codebase contains sweep/withdrawal functions that use internal accounting rather than actual token balances. Look for divergence between accounted values (currencyRaised, TOTAL_SUPPLY - totalCleared) and actual balanceOf(address(this)).

Inventory:
- Map all sweep functions: sweepCurrency transfers currencyRaised() (internal counter), sweepUnsoldTokens computes TOTAL_SUPPLY - totalCleared (internal counters)
- Check onTokensReceived: does it silently ignore tokens beyond TOTAL_SUPPLY? Does it revert?
- Identify all paths that increase actual balance without updating internal accounting: direct ERC20.transfer(), direct ETH send, accidental over-transfer
- Check for any rescue/recovery function that can extract the difference between actual balance and accounted balance

Report only if ALL true:
- sweep functions use internally accounted values (currencyRaised, TOTAL_SUPPLY - totalCleared) rather than actual contract balanceOf
- No recovery mechanism exists to extract the difference between actual balance and accounted totals
- onTokensReceived silently ignores excess tokens (does not revert) OR there is no receive guard at all
- Direct transfers to the contract address are possible (no receive() revert for ETH, no transfer hook blocking for ERC20)

Do not report if:
- A rescue/admin function can extract unaccounted balances
- The contract reverts on any transfer not through the designated entry points
- sweepCurrency and sweepUnsoldTokens use balanceOf(address(this)) directly

---

VC5 — OVERFLOW-BOUNDS
Grep: MAX_BID_PRICE, maxBidPrice, TOTAL_SUPPLY, InvalidBidUnableToClear, nextActiveTickPrice_

Applicability gate:
Only proceed if the codebase contains Q96 fixed-point arithmetic for price/supply calculations. Look for products of TOTAL_SUPPLY and tick prices, especially in the clearing price iteration loop. CCA uses Q96 (2^96) for prices: a price of 1.0 = 2^96.

Inventory:
- Identify all multiplication paths: TOTAL_SUPPLY * nextActiveTickPrice_ in the tick iteration, and any Q96 multiplication in checkpoint accounting
- Map the guard: InvalidBidUnableToClear — where is it checked relative to the overflow-prone multiplication?
- Compute bounds from docs: max TOTAL_SUPPLY = 1e30 wei. For 1e30 supply, MAX_BID_PRICE = 2^110. For 1e15 supply (1B 6-dec tokens), MAX_BID_PRICE = 2^160.
- Check if the guard fires BEFORE or AFTER the dangerous multiplication

Report only if ALL true:
- A product of TOTAL_SUPPLY and a tick price can approach or exceed uint256 max (2^256) for a deployable combination of supply and price
- The InvalidBidUnableToClear guard (or equivalent) is checked AFTER the multiplication, allowing the overflow to occur first
- The overflow is not caught by Solidity 0.8+ checked arithmetic (i.e., it's in an unchecked block or uses assembly)
- A realistic deployment scenario exists where these bounds are hit (not just theoretical extremes)

Do not report if:
- Solidity 0.8+ checked arithmetic catches the overflow before any state change
- The InvalidBidUnableToClear guard fires before the multiplication
- MAX_BID_PRICE enforcement in submitBid prevents any bid from reaching overflow-prone territory
- The overflow only occurs for supply/price combos that are unrealistic (e.g., TOTAL_SUPPLY > 1e30 which the factory rejects)

---

VC6 — LOWDEC-FOT-SILENT-MISALLOCATION
Grep: transferFrom, balanceOf, TOTAL_SUPPLY, constructor, initialize, CURRENCY, TOKEN

Applicability gate:
Only proceed if the codebase handles ERC20 tokens (transferFrom, balanceOf, IERC20). The bug is the ABSENCE of validation — do NOT skip just because `decimals()` doesn't appear in the code. That IS the vulnerability: the auction creation path accepts any token without checking its decimals. CCA docs state "Do NOT use with low-decimal (< 6) tokens" and "Fee On Transfer tokens are explicitly not supported" — but neither is enforced on-chain.

Inventory:
- Check the auction creation path (constructor, factory): is there a require(token.decimals() >= 6) or equivalent?
- Map all transferFrom/transfer calls: do they use the argument amount for accounting, or do they check balanceOf before/after to compute the actual received amount?
- Identify Q96 arithmetic paths where low decimals cause significant precision loss: price * amount / Q96 where amount has few significant digits
- Check if fee-on-transfer tokens cause immediate accounting drift: does currencyRaised increment by the nominal amount or the received amount?

Report if EITHER condition set is true (low-dec and FOT are independent bugs):

Low-decimal condition (report if ALL true):
- No decimal floor check exists in the auction creation path (constructor or factory)
- Q96 arithmetic produces rounding errors that exceed dust thresholds for tokens with < 6 decimals (quantify: for a 2-decimal token, what's the maximum per-bid loss?)
- The auction creation path does not revert or warn — it silently proceeds with broken math

FOT condition (report if ALL true):
- Transfer accounting uses the argument amount rather than a balanceOf delta (before/after pattern)
- The first submitBid already creates a gap between currencyRaised and actual balance that compounds with each subsequent bid
- No balance-delta verification exists anywhere in the transfer path

Do not report if:
- The factory or constructor enforces a minimum decimals check (for low-dec)
- Transfer accounting uses SafeERC20 with balance-delta verification (for FOT)
- The factory prevents deployment with such tokens via on-chain enforcement (documentation disclaimers alone do NOT count — the check must be enforced in code)

---

VC7 — PERMISSIONLESS-CLAIM-ZEROING
Grep: claimTokens, _internalClaimTokens, tokensFilled, $bid.tokensFilled = 0

Applicability gate:
Only proceed if the codebase contains a claim function callable by any address that permanently modifies bid state. This is by design in CCA — "Anyone can call this function for any valid bid id" — but is the #1 source of integration bugs.

Inventory:
- Map claimTokens and claimTokensBatch: confirm no msg.sender == bid.owner check exists
- Trace _internalClaimTokens: does it set bid.tokensFilled = 0 BEFORE or AFTER the token transfer? What event is emitted?
- Check the TokensClaimed event: does it emit the original tokensFilled value, or is it emitted after zeroing? (Critical for off-chain indexers)
- Identify any integration contract that reads tokensFilled — every such read is a potential VI1 downstream

Report only if ALL true:
- claimTokens has no access control — any address can call it for any bidId
- _internalClaimTokens permanently zeros bid.tokensFilled with no way to recover the original value from on-chain state
- The TokensClaimed event does NOT include the original tokensFilled value (or emits it after zeroing, making it zero in the event too)
- At least one code path exists where an integration or user could be harmed by a third party calling claimTokens first (grief vector)

Do not report if:
- claimTokens checks msg.sender == bid.owner
- tokensFilled is preserved in a separate mapping or the event reliably emits the original value
- The permissionless design is intentional AND the codebase is CCA core (not an integration) AND no integration code is in scope — in this case, note as informational for integration awareness only

---

VC8 — BID-LOCK-V1
Grep: 0x0000ccaDF55C911a2FbC0BB9d2942Aa77c6FAa1D

Applicability gate:
Only proceed if the codebase contains a hardcoded factory address or references to CCA factory deployment. This is a simple literal-match check.

Inventory:
- Search for the v1.0.0-candidate factory address: 0x0000ccaDF55C911a2FbC0BB9d2942Aa77c6FAa1D
- Search deployment scripts, constructor arguments, constants, and configuration files
- Check if the v1.1.0 factory address (0xCCccCcCAE7503Cac057829BF2811De42E16e0bD5) is used instead

Report only if ALL true:
- The literal address 0x0000ccaDF55C911a2FbC0BB9d2942Aa77c6FAa1D appears in source code, deployment config, or constructor arguments
- The address is used to deploy or interact with CCA auctions (not just referenced in comments or documentation)

Do not report if:
- The address only appears in comments, documentation, or test files
- The v1.1.0 factory address is used instead
- The v1.0.0 address is referenced in a migration/deprecation context that explicitly warns against its use

---

VC9 — TSTORE-POISON
Grep: transient, delete, pragma solidity 0.8.28, pragma solidity 0.8.29, pragma solidity 0.8.30, pragma solidity 0.8.31, pragma solidity 0.8.32, pragma solidity 0.8.33, via-ir

Applicability gate:
Only proceed if ALL of these conditions are present: (1) pragma solidity version is 0.8.28–0.8.33, (2) the contract uses the transient keyword, (3) the project uses --via-ir compilation. If any condition is absent, skip entirely. CCA core is on 0.8.26 and is not affected, but forks and integrations may be.

Inventory:
- Check pragma solidity version in every in-scope file
- Search for the transient keyword (transient storage variables)
- Search for delete statements on both persistent and transient variables
- Check foundry.toml, hardhat.config, or compiler settings for via-ir / viaIR = true
- Map type collisions: identify cases where a persistent and transient variable share the same underlying type (uint256, address, bool, etc.) AND both have delete operations

Report only if ALL true:
- pragma solidity is 0.8.28–0.8.33 (the affected compiler range)
- The contract declares both persistent and transient variables of the same underlying type
- Both the persistent and transient variable of the same type are deleted (delete keyword or = 0 / = address(0) assignment) somewhere in the contract
- The project compiles with --via-ir (check foundry.toml viaIR, hardhat config, or compilation flags)
- Note: array element clearing (bool[], address[], uint8[]) all funnel to uint256 zeroing and count as same-type collisions

Do not report if:
- pragma solidity is outside 0.8.28–0.8.33 (including 0.8.26 used by CCA core, or >=0.8.34 where the fix landed)
- No transient keyword is used anywhere in the codebase
- The project does not use --via-ir compilation
- Persistent and transient variables exist but are never both deleted, or are of different types

=== INTEGRATION VECTORS (bugs in code that uses CCA) ===

VI1 — STALE-TOKENSFILLED-READ
Grep: tokensFilled, claimTokens, bidId, allocation, filled

Applicability gate:
Only proceed if the integration reads bid.tokensFilled from CCA state (directly or via a getter). This is the most common CCA integration bug. claimTokens() is permissionless — "Anyone can call this function for any valid bid id" — and permanently zeros tokensFilled.

Inventory:
- Map every function that reads tokensFilled from the CCA contract (direct storage read, getter call, or interface call)
- Identify WHEN the read happens relative to claimBlock: before claimBlock (safe — claims can't happen yet), at/after claimBlock (vulnerable — a griefing bot can call claimTokens first)
- Check if the integration caches tokensFilled in its own storage before claimBlock
- Check if the integration calls claimTokens itself: even with try/catch, if a third party already called it, the storage is already zeroed and the integration's call returns 0

Report only if ALL true:
- The integration reads bid.tokensFilled from CCA state to compute allocations, vesting, bonuses, transfers, or any downstream accounting
- The read can occur at or after claimBlock (when claimTokens becomes callable by anyone)
- The integration does NOT cache tokensFilled in its own storage before claimBlock
- A third party calling claimTokens before the integration reads would cause the integration to compute against zero, resulting in loss of user allocations or funds

Do not report if:
- The integration caches tokensFilled in its own storage before claimBlock and uses the cached value for all accounting
- The integration only reads tokensFilled before claimBlock (when claims are blocked)
- The integration is the exclusive caller of claimTokens AND receives tokens directly AND does not rely on the tokensFilled value after claiming

---

VI2 — UNSAFE-AUCTION-DEPLOYMENT
Grep: createAuction, deploy, AuctionParameters, floorPrice, startBlock, endBlock, requiredCurrencyRaised, positionRecipient, tickSpacing, auctionStepsData

Applicability gate:
Only proceed if the integration deploys or configures CCA auctions (calls the factory's initializeDistribution or directly constructs auction contracts). CCA validates none of its own parameters — the AuctionParameters struct has 11 fields and all are trust-the-deployer.

Inventory:
- Map the deployment path: does the integration call initializeDistribution, create auctions via CREATE2, or pass AuctionParameters to a constructor?
- For each parameter, check if the integration enforces bounds:
  - floorPrice: is there a min/max? (extreme floorPrice = overpay trap)
  - requiredCurrencyRaised: is there a realistic ceiling? (impossibly high = funds locked forever, auction can't graduate)
  - positionRecipient / fundsRecipient / tokensRecipient: are they validated to not be attacker-controlled? (attacker as positionRecipient = LP rug post-graduation)
  - tickSpacing: is there a minimum? (tiny spacing = DoS via VC1)
  - auctionStepsData: is the final step's mps validated? (negligible final mps = price manipulation via VC3)
  - startBlock / endBlock / claimBlock: are they within reasonable ranges?
- Check who can set these parameters: is it an admin, any user, or an untrusted caller?

Report only if ALL true:
- The integration calls CCA's auction creation/deployment functions
- At least one critical parameter (floorPrice, requiredCurrencyRaised, positionRecipient, tickSpacing, or final-step mps) is NOT validated by the integration
- An untrusted party can influence the unvalidated parameter(s) — either by calling the deployment function directly or by manipulating inputs upstream
- The lack of validation enables a concrete attack: honeypot (requiredCurrencyRaised too high), LP rug (attacker positionRecipient), DoS (tiny tickSpacing), or price manipulation (negligible final mps)

Do not report if:
- All deployment parameters are set by a trusted admin through a governance/multisig flow
- The integration validates all critical parameters with on-chain bounds checks
- The integration only deploys auctions with hardcoded, safe parameter values

---

VI3 — DIRECT-CURRENCY-TRANSFER
Grep: transfer, safeTransfer, CURRENCY, TOKEN, submitBid, onTokensReceived

Applicability gate:
Only proceed if the integration transfers ERC20 tokens to a CCA auction contract address. The ONLY safe paths into CCA are submitBid (for currency) and onTokensReceived (for tokens via ERC777/callback). Any direct ERC20.transfer or safeTransfer to the auction address is permanently irrecoverable — sweep functions only return accounted amounts.

Inventory:
- Map all ERC20 transfer/safeTransfer calls in the integration
- For each transfer, check the recipient: is it the CCA auction contract address?
- Distinguish between: transfers to the auction via submitBid (safe — uses payable or transferFrom internally), direct transfers to the auction address (unsafe — bypasses accounting), and transfers to other addresses (irrelevant)
- Check for ETH: if CURRENCY is address(0), does the integration send ETH via call/transfer/send to the auction instead of through submitBid{value: amount}?

Report only if ALL true:
- The integration sends ERC20 tokens (or ETH) directly to the CCA auction contract address via transfer/safeTransfer/call
- The transfer is NOT routed through submitBid (for currency) or onTokensReceived (for tokens)
- The transferred funds are permanently irrecoverable because CCA's sweep functions only return internally accounted amounts
- The code path is reachable (not dead code, not guarded by impossible conditions)

Do not report if:
- All transfers to the auction go through submitBid or onTokensReceived
- The integration never sends tokens to the auction address directly
- A rescue function exists on the auction that can recover unaccounted balances

---

VI4 — FILL-AMOUNT-STABILITY-ASSUMPTION
Grep: clearingPrice, filledAmount, proRata, allocation, share

Applicability gate:
Only proceed if the integration reads CCA fill amounts or clearing price to compute allocations, distribute rewards, or make economic decisions. Fills at the clearing tick change every block as new bids arrive and pro-rata shares shift via checkpoint. The currencyRaisedAtClearingPriceQ96_X7 accumulator resets every time the clearing price changes.

Inventory:
- Identify all reads of fill-related CCA state: tokensFilled, clearingPrice, currencyRaisedAtClearingPriceQ96_X7, or any derived fill/allocation value
- Determine if the integration treats these values as stable (reads once and uses for downstream math) or accounts for their mutability
- Check timing: does the integration read fill amounts during the auction (unstable) or after END_BLOCK (more stable, but still shiftable by exitPartiallyFilledBid)?
- Check if a searcher can profitably manipulate the fill amount between the integration's read and its use

Report only if ALL true:
- The integration reads fill amounts or pro-rata shares from CCA and uses them for allocation math, reward distribution, or economic decisions
- The integration does NOT snapshot the values at a specific block or account for the possibility that they change
- A searcher can submit a bid at the clearing tick to dilute existing bidders' shares between the integration's read and its use of the value
- The manipulation results in measurable economic loss for users (not just dust-level rounding)

Do not report if:
- The integration snapshots fill amounts at a specific block and uses the snapshot
- The integration only reads fill amounts after the auction has ended AND all bids have been exited (values are final)
- The integration accounts for dilution risk by using time-weighted or commit-reveal mechanisms

---

VI5 — PARAM-HONEYPOT-EXPOSURE
Grep: floorPrice, requiredCurrencyRaised, positionRecipient, startBlock, endBlock, AuctionParameters, validate

Applicability gate:
Only proceed if the integration lets users interact with arbitrary CCA auctions whose parameters are not validated. This applies to frontends, aggregators, wrappers, or any contract that accepts an auction address as input. CCA docs warn under "Bidder responsibilities" that auctions can be configured with excessively high floor prices, extreme block ranges, honeypot tokens, unrealistic requiredCurrencyRaised, or attacker-controlled positionRecipient.

Inventory:
- Does the integration accept an auction address as an input parameter from users?
- Before interacting with the auction, does the integration read and validate its parameters?
- Specific honeypot parameters to check:
  - requiredCurrencyRaised: set impossibly high → auction never graduates → funds locked forever
  - positionRecipient: owned by deployer → LP rug post-graduation
  - floorPrice: excessively high → users overpay
  - startBlock/endBlock: extreme ranges → funds locked for unreasonable duration
  - token: malicious/honeypot ERC20

Report only if ALL true:
- The integration accepts an arbitrary auction address as input and interacts with it (submits bids, reads state, or facilitates user participation)
- The integration does NOT validate the auction's parameters before interacting
- A malicious deployer could create a honeypot auction that traps user funds through any of the parameter vectors listed above
- Users of the integration have no on-chain protection against interacting with the honeypot auction

Do not report if:
- The integration only interacts with a hardcoded, pre-validated auction address
- The integration reads and validates all critical auction parameters before allowing user interaction
- The integration is a simple pass-through that does not custody or intermediate user funds (users interact directly with the auction)

---

VI6 — VERSION-MISMATCH
Grep: factory, CCAFactory, 0x0000ccaDF55C, 0xCCccCcCAE7503

Applicability gate:
Only proceed if the integration references a CCA factory address. This is a simple literal-match check for the v1.0.0-candidate factory (0x0000ccaDF55C911a2FbC0BB9d2942Aa77c6FAa1D) which has a bid-locking bug. The fixed v1.1.0 factory is 0xCCccCcCAE7503Cac057829BF2811De42E16e0bD5.

Inventory:
- Search for both factory addresses in source code, constants, deployment scripts, and configuration
- Check if the integration deploys auctions via the factory or just reads from existing auctions
- If both addresses appear, check which one is active (the other may be in a migration/deprecation path)

Report only if ALL true:
- The v1.0.0 factory address (0x0000ccaDF55C911a2FbC0BB9d2942Aa77c6FAa1D) appears in the integration's source, constants, or deployment configuration
- The address is actively used to deploy or interact with CCA auctions (not just in comments or docs)
- Auctions deployed via this factory are subject to the bid-locking bug

Do not report if:
- Only the v1.1.0 factory address is used
- The v1.0.0 address only appears in comments, documentation, or deprecation warnings
- The integration explicitly checks the factory version and rejects v1.0.0

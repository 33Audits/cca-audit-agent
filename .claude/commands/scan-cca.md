# CCA Vulnerability Scanner

Scan Solidity contracts for Uniswap Continuous Clearing Auction vulnerabilities — both in CCA's own code (forks, deployments) and in contracts that integrate with CCA. Detects what's in scope automatically based on what's present.

## Scope

Target: `$ARGUMENTS` (defaults to current working directory if empty). Scan all `.sol` files under the target, **excluding** `test/`, `script/`, and `lib/` directories.

## Workflow

### Step 0 — Banner

Before doing anything else, print this banner exactly as shown:

```
 ██████╗  ██████╗ ██╗      █████╗ ██████╗ ███████╗
 ╚════██╗ ╚════██╗██║     ██╔══██╗██╔══██╗██╔════╝
  █████╔╝  █████╔╝██║     ███████║██████╔╝███████╗
  ╚═══██╗  ╚═══██╗██║     ██╔══██║██╔══██╗╚════██║
 ██████╔╝ ██████╔╝███████╗██║  ██║██████╔╝███████║
 ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝

  ██████╗ ██████╗  █████╗      █████╗  ██████╗ ███████╗███╗   ██╗████████╗
 ██╔════╝██╔════╝ ██╔══██╗    ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
 ██║     ██║      ███████║    ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║
 ██║     ██║      ██╔══██║    ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║
 ╚██████╗╚██████╗ ██║  ██║    ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║
  ╚═════╝ ╚═════╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝

 ◈ Double-pass audit engine for Uniswap CCA
 ◈ 9 core vectors ∙ 6 integration vectors ∙ parallel analysis
```

### Step 1 — Prepare

1. Glob for all in-scope `.sol` files.
2. Count total lines across all files. If zero, stop and tell the user no Solidity files were found.
3. Concatenate all in-scope `.sol` files into `/tmp/cca-scan-bundle.sol` using bash, with `// === FILE: <path> ===` separators between each file. Record the total line count.

### Step 2 — Double Pass (parallel)

Launch **both** agents simultaneously using two Task tool calls in a single message. Both use `subagent_type: "general-purpose"` and `model: "sonnet"`.

---

**Agent A — Vector Scan**

Prompt the agent with the Vector Scan Agent Prompt below. Interpolate:
- `{BUNDLE_PATH}` → `/tmp/cca-scan-bundle.sol`
- `{LINE_COUNT}` → the total line count
- `{VECTORS}` → the full "CCA Vulnerability Vectors" section below (copy it verbatim into the prompt)
- `{FP_GATE}` → the "FP Gate" section below
- `{REPORT_FORMAT}` → the "Report Format" section below

**Agent B — Adversarial Reasoning**

Prompt the agent with the Adversarial Reasoning Agent Prompt below. Interpolate:
- `{FILE_LIST}` → the list of in-scope `.sol` file paths, one per line
- `{FP_GATE}` → the "FP Gate" section below
- `{REPORT_FORMAT}` → the "Report Format" section below

---

### Step 3 — Merge & Report

1. Collect findings from both agents.
2. Deduplicate: if both agents found the same issue (same affected function + same root cause), keep the higher-confidence version.
3. Re-number findings sequentially.
4. Sort by confidence descending.
5. Present the final report to the user with a summary header:
   - Files scanned: N
   - Lines analyzed: N
   - Findings: N (breakdown by severity)
6. If no findings survived: "No findings — the scanned contracts passed all CCA checks and adversarial analysis."

---

## CCA Vulnerability Vectors

Vectors are split into two classes. **CORE** vectors target CCA's own logic (relevant when scanning forks or the CCA source itself). **INTEGRATION** vectors target code that calls into or reads from CCA (relevant when scanning protocols built on top). The triage pass determines which class applies based on what code is actually present — both classes can fire simultaneously.

```
=== CORE VECTORS (bugs in CCA's own code) ===

VC1 — TICK-ITERATION-DOS
Grep: _iterateOverTicksAndFindClearingPrice, MAX_TICK_PTR, TICK_SPACING, forceIterateOverTicks, _checkpointAtBlock
CCA walks a singly-linked list of initialized ticks on every checkpoint. An attacker who initializes thousands of ticks at minimum TICK_SPACING intervals forces every subsequent submitBid to iterate all of them, exhausting gas. forceIterateOverTicks (v1.1.0) is manual recovery but must be called before the next checkpoint.
CONFIRM IF: The tick iteration loop exists without a gas-bounded exit, or tick spacing is configurable without a minimum floor.

VC2 — PRORATA-MEV
Grep: currencyRaisedAtClearingPriceQ96_X7, _sellTokensAtClearingPrice, exitPartiallyFilledBid, ClearingPriceUpdated
Bids at exactly the clearing price fill pro-rata via on-chain-readable accumulators. A searcher front-runs to dilute existing bidders' share. Back-running ClearingPriceUpdated to call exitPartiallyFilledBid in the same block extracts value. Composable with flashloans.
CONFIRM IF: Pro-rata accumulation at the clearing tick has no anti-dilution mechanism, and exitPartiallyFilledBid can be called in the same block as a price update.

VC3 — STEP-TAIL-MANIPULATION
Grep: auctionStepsData, mps, END_BLOCK, lbpInitializationParams, $clearingPrice, deltaMps
The final clearingPrice at END_BLOCK seeds the v4 pool via lbpInitializationParams. If the last auction step has a tiny mps (milli-bips per second), almost no supply anchors the final price — a single large bid/withdrawal near END_BLOCK can shift the pool opening price.
CONFIRM IF: The step schedule allows a final step with negligible token issuance, and there is no minimum mps enforcement.

VC4 — DIRECT-TRANSFER-LOSS
Grep: sweepCurrency, sweepUnsoldTokens, currencyRaised, TOTAL_SUPPLY, balanceOf, onTokensReceived
sweepCurrency transfers currencyRaised() not actual balanceOf. sweepUnsoldTokens computes from TOTAL_SUPPLY - totalCleared, ignoring excess. onTokensReceived silently ignores tokens beyond TOTAL_SUPPLY. Any direct transfer is permanently irrecoverable.
CONFIRM IF: sweep functions use accounted values rather than actual contract balance, with no mechanism to recover the difference.

VC5 — OVERFLOW-BOUNDS
Grep: MAX_BID_PRICE, maxBidPrice, TOTAL_SUPPLY, InvalidBidUnableToClear, nextActiveTickPrice_
For extreme supply/price combos, TOTAL_SUPPLY * nextActiveTickPrice_ in the iteration loop can approach uint256 max. The InvalidBidUnableToClear guard exists but may fire too late depending on the specific supply and decimals.
CONFIRM IF: The product of TOTAL_SUPPLY and maximum possible tick price can exceed uint256 before the guard check in _submitBid.

VC6 — LOWDEC-FOT-SILENT-MISALLOCATION
Grep: decimals, transferFrom, balanceOf
Tokens below 6 decimals lose significant value to rounding — CCA does not revert, it silently misallocates. Fee-on-transfer tokens cause accounting drift from the first bid (nominal vs received). Neither is caught.
CONFIRM IF: No decimal floor check exists in the auction creation path, and transfer accounting uses the argument amount rather than balanceOf delta.

VC7 — PERMISSIONLESS-CLAIM-ZEROING
Grep: claimTokens, _internalClaimTokens, tokensFilled, $bid.tokensFilled = 0
claimTokens() has no ownership check. Anyone can call it for any bidId. _internalClaimTokens resets bid.tokensFilled = 0 permanently with no on-chain record of the original fill. This is by design in CCA, but is the #1 source of integration bugs.
CONFIRM IF: claimTokens has no access control (msg.sender != bid.owner check), and tokensFilled is zeroed without emitting the original value in an event.

VC8 — BID-LOCK-V1
Grep: 0x0000ccaDF55C911a2FbC0BB9d2942Aa77c6FAa1D
v1.0.0-candidate factory had a rare-case bug permanently locking bids. Fixed in v1.1.0 (factory 0xCCccCcCAE7503Cac057829BF2811De42E16e0bD5). If the v1.0.0 address appears in the codebase, the risk is live.
CONFIRM IF: The v1.0.0 factory address literal appears in source, deployment config, or constructor arguments.

VC9 — TSTORE-POISON
Grep: transient, delete, pragma solidity 0.8.28, pragma solidity 0.8.29, pragma solidity 0.8.30, pragma solidity 0.8.31, pragma solidity 0.8.32, pragma solidity 0.8.33, via-ir
Solidity compiler bug (0.8.28–0.8.33, --via-ir only). The MultiUseYulFunctionCollector caches storageSetToZeroFunction by type name only — without distinguishing sstore vs tstore domains. When a contract has both a persistent and a transient variable of the same type, and both are deleted, the first delete encountered during IR generation poisons the cache. All subsequent deletes of that type use the wrong opcode. A persistent delete may silently use tstore (value returns next tx), or a transient delete may use sstore (nukes a persistent slot). Collision surface is wider than expected — array element clearing for bool[], address[], uint8[] all funnel to the same uint256 zeroing function. CCA itself is on 0.8.26, but forks upgrading to 0.8.28+ and integration contracts built on top of CCA that use the transient keyword for gas optimization are directly exposed. Ref: https://hexens.io/research/solidity-compiler-bug-tstore-poison
CONFIRM IF: (1) pragma solidity is 0.8.28–0.8.33 AND (2) contract uses both transient and persistent variables of the same type AND (3) both are deleted somewhere in the contract AND (4) project compiles with --via-ir. All four conditions must hold.

=== INTEGRATION VECTORS (bugs in code that uses CCA) ===

VI1 — STALE-TOKENSFILLED-READ
Grep: tokensFilled, claimTokens, bidId, allocation, filled
The integration reads bid.tokensFilled from CCA state to compute user allocations, vesting, bonuses, or transfers. Because claimTokens is permissionless and zeros tokensFilled, a griefing bot (or front-runner) can call claimTokens for every bidId at claimBlock before the integration reads. All downstream accounting computes against zero. try/catch around the integration's own claimTokens call does not help — storage is already zeroed.
CONFIRM IF: Any function reads tokensFilled from CCA after the claim window, or the integration does not cache tokensFilled in its own storage before claimBlock.

VI2 — UNSAFE-AUCTION-DEPLOYMENT
Grep: createAuction, deploy, AuctionParameters, floorPrice, startBlock, endBlock, requiredCurrencyRaised, positionRecipient, tickSpacing, auctionStepsData
The integration deploys CCA auctions without validating parameters. Attack surface: extreme floorPrice (overpay trap), unrealistic requiredCurrencyRaised (funds never unlock — auction can't graduate), positionRecipient set to attacker (rugs LP post-graduation), tiny tickSpacing (DoS), negligible final-step mps (price manipulation).
CONFIRM IF: The integration calls CCA's creation/deployment functions and does not enforce bounds on any of these parameters.

VI3 — DIRECT-CURRENCY-TRANSFER
Grep: transfer, safeTransfer, CURRENCY, TOKEN, submitBid, onTokensReceived
The integration sends currency or tokens directly to the CCA contract address via ERC20 transfer instead of using submitBid (for currency) or onTokensReceived (for tokens). Funds sent this way are permanently irrecoverable — sweep functions only return accounted amounts.
CONFIRM IF: Any code path transfers ERC20 tokens to the CCA contract address outside of the submitBid/onTokensReceived flow.

VI4 — FILL-AMOUNT-STABILITY-ASSUMPTION
Grep: clearingPrice, filledAmount, proRata, allocation, share
The integration computes allocations or distributes rewards based on CCA fill amounts, assuming they are stable. But fills at the clearing tick change every block as new bids arrive and pro-rata shares shift. A searcher can submit a bid at the expected clearing tick to dilute all existing bidders' shares.
CONFIRM IF: The integration reads fill amounts and uses them for allocation math without snapshotting at a specific block or accounting for dilution.

VI5 — PARAM-HONEYPOT-EXPOSURE
Grep: floorPrice, requiredCurrencyRaised, positionRecipient, startBlock, endBlock, AuctionParameters, validate
The integration lets users interact with arbitrary CCA auctions (e.g., a frontend, aggregator, or wrapper) without validating auction parameters. Users can be lured into honeypot auctions with: requiredCurrencyRaised set impossibly high (funds locked forever), positionRecipient owned by the deployer (LP rug), extreme block ranges.
CONFIRM IF: The integration accepts an auction address as input and interacts with it without checking these parameters.

VI6 — VERSION-MISMATCH
Grep: factory, CCAFactory, 0x0000ccaDF55C, 0xCCccCcCAE7503
The integration references or deploys against the v1.0.0-candidate CCA factory (0x0000ccaDF55C911a2FbC0BB9d2942Aa77c6FAa1D) which has the bid-locking bug. Should use v1.1.0 (0xCCccCcCAE7503Cac057829BF2811De42E16e0bD5).
CONFIRM IF: The v1.0.0 factory address appears in the integration's source, constants, or deployment configuration.
```

---

## FP Gate (3 Checks)

Every potential finding MUST pass all three checks before being reported. If any check fails, DROP immediately.

1. **Concrete attack path**: Can you trace a specific sequence of transactions from an external entry point to a harmful state change or fund loss? Not theoretical — name the exact functions.
2. **Reachable**: Is the path actually reachable given modifiers, require statements, access control, and state prerequisites? If fully guarded, DROP.
3. **Impact**: Does the attacker profit, or do users lose funds, or is a core invariant broken? Pure inconvenience without fund risk → DROP (unless permanent DoS of core functionality).

---

## Report Format

Each finding uses this exact format:

```
<severity> **<N>. <title>**
<file>:<lines> · Confidence: <0-100>

**Description:** <one-sentence explanation>

**Attack path:**
1. <step>
2. <step>
...

**Fix:**
\`\`\`diff
- <vulnerable code>
+ <fixed code>
\`\`\`
```

Severity indicators: 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low
Omit Fix for findings below 80 confidence.

---

## Vector Scan Agent Prompt

```
You are a security auditor scanning Solidity contracts for CCA (Continuous Clearing Auction) vulnerabilities. The codebase may contain CCA core code, integration code that calls into CCA, or both. There are bugs here — find them.

CRITICAL OUTPUT RULE: Return findings ONLY in your final text response. Do NOT write any files.

WORKFLOW:
1. Read the bundle file at {BUNDLE_PATH} in parallel 1000-line chunks on your first turn. Total lines: {LINE_COUNT}. Compute offsets and issue all Read calls at once. These are your ONLY file reads.

2. TRIAGE PASS. For each vector (VC1-VC9 core, VI1-VI6 integration), classify into Skip / Borderline / Survive:
   - Skip: the construct AND underlying concept are both absent from this codebase.
   - Borderline: no direct match but the concept could manifest differently. 1-sentence check: name the specific function where it manifests AND describe the exploit. Promote only if both are concrete, otherwise drop.
   - Survive: the construct or pattern is clearly present.
   Output all three tiers. Every vector in exactly one. End with total count to verify.

3. DEEP PASS. Only surviving vectors. Structured one-liners:
   V#: path: fn() → fn() → vulnerable line | guard: <guards> | verdict: CONFIRM [confidence] or DROP (reason)
   Trace the call chain from external entry point to the vulnerable line. Check every modifier, caller restriction, state guard. If no match or fully guarded → DROP in one line. If match → apply FP Gate (3 checks). Only if all 3 pass → expand into formatted finding.
   Budget: 1 line per drop, 3 lines max per confirm before formatted finding.

4. COMPOSABILITY CHECK. If 2+ confirmed: do any compound? Note in the higher-confidence finding.

5. HARD STOP. After the deep pass, do not re-examine eliminated vectors or revisit anything. Return ALL formatted findings, or "No findings."

{VECTORS}
{FP_GATE}
{REPORT_FORMAT}
```

---

## Adversarial Reasoning Agent Prompt

```
You are an adversarial security researcher trying to exploit these contracts. The codebase may contain CCA core code, integration code, or both. There are bugs here — find them. Your goal is to find every way to steal funds, lock funds, grief users, or break invariants. Do not give up. If your first pass finds nothing, assume you missed something and look again from a different angle.

CRITICAL OUTPUT RULE: Return findings ONLY in your final text response. Do NOT write any files.

CCA KNOWN HAZARDS (keep in mind while reading):
- claimTokens() is permissionless — permanently zeros tokensFilled for any bidId
- Tick iteration can DoS if spacing is too small (gas exhaustion on every checkpoint)
- Clearing tick fills are pro-rata and shift every block — MEV-susceptible
- sweep functions use accounted values not actual balanceOf — direct transfers are lost
- The final auction step's mps controls how anchored the pool opening price is
- v1.0.0 factory has a bid-locking bug (address: 0x0000ccaDF55C...)
- Auction parameters are never validated by CCA — honeypots are trivial to deploy
- Q96 fixed-point math can overflow at extreme supply/price combinations
- Tokens below 6 decimals silently misallocate; fee-on-transfer tokens drift accounting

WORKFLOW:
1. Read ALL in-scope files in a single parallel batch:
{FILE_LIST}

2. Determine what you're looking at:
   - Is this CCA core code (a fork or the original)?
   - Is this integration code that calls into CCA?
   - Both?

3. For CCA core: reason about internal logic — clearing price computation, tick iteration, checkpoint accounting, Q96 arithmetic, state transitions. Look for edge cases the known hazards list doesn't cover.

4. For integration code: map the CCA surface — which CCA functions does it call? What state does it read? When? Every call into CCA and every read of CCA state is a potential footgun. Ask:
   - What if a third party calls claimTokens before this code?
   - What if CCA state changes between this code's read and its use of the value?
   - What if the auction params are malicious?
   - What if a searcher front-runs or back-runs this code's CCA transactions?
   - Are there reentrancy paths through CCA callbacks?
   - Does this code handle Q96 fixed-point correctly?
   - Can a user grief other users through this code's CCA interactions?

5. For each potential finding, apply the FP Gate. If any check fails → drop. Only if all 3 pass → format.

6. Return ALL formatted findings, or "No findings."

{FP_GATE}
{REPORT_FORMAT}
```

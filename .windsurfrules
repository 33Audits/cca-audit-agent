# 33Labs CCA Vulnerability Scanner

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

 ◈ Single-pass audit engine for Uniswap CCA
 ◈ 9 core vectors ∙ 6 integration vectors
```

When the user asks to scan for CCA vulnerabilities or run a CCA audit, follow this workflow against all `.sol` files in the project (excluding `test/`, `script/`, `lib/`).

## Workflow

### Step 1 — Read
Read all in-scope `.sol` files. Prioritize main contracts first, then libraries and interfaces.

### Step 2 — Triage
For each of the 14 vectors below (VC1-VC8 core, VI1-VI6 integration), classify as Skip / Borderline / Survive. Output all tiers.

### Step 3 — Deep Analysis
Only surviving vectors. Trace call chain from entry point to vulnerable line. Check all guards. Apply FP Gate. DROP if any check fails, CONFIRM if all pass.

### Step 4 — Adversarial Pass
Reason freely about the code beyond the checklist. Focus on: logic errors in clearing price computation, unsafe external interactions, access control gaps, economic exploits (MEV, sandwich), integration footguns (stale state reads), arithmetic edge cases (Q96 overflow), DoS vectors.

For integrations: What if a third party calls claimTokens first? What if CCA state changes between read and use? What if auction params are malicious? What if a searcher front/back-runs transactions?

### Step 5 — Report
Summary header (files, lines, finding count by severity), then findings sorted by confidence.

## Core Vectors (CCA's own code)

**VC1 — TICK-ITERATION-DOS**: _iterateOverTicksAndFindClearingPrice walks linked list of ticks per checkpoint. Attacker initializes thousands at minimum spacing → gas exhaustion on every submitBid. CONFIRM IF: no gas-bounded exit or no minimum tick spacing.

**VC2 — PRORATA-MEV**: Clearing tick fills pro-rata via on-chain accumulators. Searcher front-runs to dilute, back-runs exitPartiallyFilledBid same block. Flashloan-composable. CONFIRM IF: no anti-dilution and same-block exit allowed.

**VC3 — STEP-TAIL-MANIPULATION**: Final clearingPrice seeds v4 pool. Tiny last-step mps = almost no supply anchors price. Single bid near END_BLOCK shifts pool opening. CONFIRM IF: no minimum mps enforcement on final step.

**VC4 — DIRECT-TRANSFER-LOSS**: sweep functions use accounted values not balanceOf. Direct transfers permanently lost. CONFIRM IF: sweep uses accounted values.

**VC5 — OVERFLOW-BOUNDS**: TOTAL_SUPPLY * nextActiveTickPrice_ can approach uint256 max. Guard may fire late. CONFIRM IF: product can overflow before guard.

**VC6 — LOWDEC-FOT-SILENT-MISALLOCATION**: <6 decimal tokens silently misallocate. Fee-on-transfer tokens drift accounting. CONFIRM IF: no decimal floor or balanceOf-delta check.

**VC7 — PERMISSIONLESS-CLAIM-ZEROING**: claimTokens() permissionless, zeros tokensFilled permanently. #1 integration bug source. CONFIRM IF: no access control on claimTokens.

**VC8 — BID-LOCK-V1**: v1.0.0 factory (0x0000ccaDF55C911a2FbC0BB9d2942Aa77c6FAa1D) locks bids. CONFIRM IF: v1.0.0 address in codebase.

**VC9 — TSTORE-POISON**: Solidity compiler bug (0.8.28–0.8.33, --via-ir). Compiler caches storageSetToZeroFunction by type name without distinguishing sstore vs tstore. Contract with both persistent + transient variable of same type where both are deleted → first delete poisons cache, wrong opcode for all subsequent deletes. Persistent delete may tstore (value returns next tx), transient delete may sstore (nukes persistent slot). Array element clearing widens collision surface. CCA forks upgrading from 0.8.26 to 0.8.28+ are directly exposed. CONFIRM IF: pragma 0.8.28–0.8.33 AND transient + persistent same type AND both deleted AND --via-ir.

## Integration Vectors (code that uses CCA)

**VI1 — STALE-TOKENSFILLED-READ**: Reading tokensFilled post-claim → zero. Griefing bot front-runs claimTokens. CONFIRM IF: reads tokensFilled after claim window without caching.

**VI2 — UNSAFE-AUCTION-DEPLOYMENT**: Deploying auctions without validating params (floorPrice, requiredCurrencyRaised, positionRecipient, tickSpacing, mps). CONFIRM IF: no parameter bounds enforcement.

**VI3 — DIRECT-CURRENCY-TRANSFER**: Sending funds via ERC20 transfer instead of submitBid/onTokensReceived. Permanently lost. CONFIRM IF: any transfer to CCA outside correct paths.

**VI4 — FILL-AMOUNT-STABILITY-ASSUMPTION**: Assuming fill amounts are stable — they change every block at clearing tick. CONFIRM IF: uses fill amounts without snapshot.

**VI5 — PARAM-HONEYPOT-EXPOSURE**: Letting users interact with arbitrary auctions without param validation. CONFIRM IF: accepts auction address without checking params.

**VI6 — VERSION-MISMATCH**: References v1.0.0 factory. CONFIRM IF: v1.0.0 address in source.

## FP Gate

ALL three must pass or DROP:
1. **Concrete path**: Trace specific transactions entry→harm. Name functions.
2. **Reachable**: Past all guards? If fully guarded → DROP.
3. **Impact**: Attacker profits or users lose funds? Inconvenience only → DROP.

## Report Format

```
<severity> **<N>. <title>**
<file>:<lines> · Confidence: <0-100>

**Description:** <one-sentence explanation>

**Attack path:**
1. <step>
...

**Fix:**
\`\`\`diff
- <vulnerable>
+ <fixed>
\`\`\`
```

Severity: 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low. Omit Fix below 80 confidence.

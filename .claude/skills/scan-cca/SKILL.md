---
name: scan-cca
description: Double-pass CCA vulnerability scanner for Uniswap Continuous Clearing Auction contracts. Detects 9 core vectors (VC1-VC9) and 6 integration vectors (VI1-VI6) with parallel agent analysis. Scope is auto-detected; findings reported by severity and confidence.
---

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

Full vector definitions are in [references/vectors.md](references/vectors.md). Read that file and paste its full content verbatim wherever `{VECTORS}` is interpolated.

---

## FP Gate (3 Checks)

Every potential finding MUST pass all three checks before being reported. If any check fails, DROP immediately.

1. **Concrete path**: Can you trace a specific sequence of transactions from an external entry point to a harmful state change or fund loss? For missing-validation bugs (no attacker required), the path can be: unsafe deployment/configuration → normal usage → silent incorrect result. Not theoretical — name the exact functions.
2. **Reachable**: Is the path actually reachable given modifiers, require statements, access control, and state prerequisites? If fully guarded, DROP.
3. **Impact**: Do users lose funds, does an attacker profit, or is a core invariant broken? Pure inconvenience without fund risk → DROP (unless permanent DoS of core functionality).

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

SILENT MISCONFIGURATIONS (no attacker required — missing validation that silently produces wrong results):
These bugs have NO obvious failure signal. Nothing reverts. Nothing breaks. The math just quietly gives wrong answers for a class of inputs that nobody explicitly rejects. Look for these even when there is no adversary to reason about:
- No decimal floor check on auction token: tokens below 6 decimals lose significant value to Q96 fixed-point rounding. A 2-decimal token can lose 90%+ of value per operation. The auction proceeds normally — it just silently misallocates.
- No minimum tickSpacing enforcement: deploying with tiny tick spacing enables gas-exhaustion DoS on every checkpoint. CCA docs recommend "at least 1 basis point of floor price" but this is guidance only — not enforced on-chain by the factory or constructor.
- No minimum mps on final auction step: if the last step has near-zero token issuance, the final clearing price is trivially manipulable with minimal capital.
- No bounds on floorPrice relative to tick extremes: extreme floorPrice values can create auctions where the math works but the economics are broken (overpay traps, unreachable graduation thresholds).

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

# scan-cca

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
```

A Claude Code skill that scans Solidity contracts for [Uniswap Continuous Clearing Auction](https://github.com/Uniswap/continuous-clearing-auction) vulnerabilities. Finds bugs in CCA forks, protocols built on CCA, and unsafe auction deployments.

## What it does

Runs two parallel analysis agents against your Solidity codebase:

| Agent | Strategy | What it catches |
|-------|----------|-----------------|
| **Vector Scan** | Systematic triage of 14 known CCA vulnerability patterns | Known footguns — fast, cheap, high recall |
| **Adversarial Reasoning** | Free-form adversarial bug hunting | Novel bugs, logic errors, economic exploits the vector list doesn't cover |

Results are deduplicated, scored by confidence, and presented as a single report.

### Vulnerability coverage

**Core vectors** (bugs in CCA's own code — relevant for forks):

| ID | Name | Severity |
|----|------|----------|
| VC1 | Tick iteration gas exhaustion (DoS) | High |
| VC2 | Pro-rata MEV at clearing tick | High |
| VC3 | Step schedule tail manipulation | High |
| VC4 | Direct transfer fund loss | Medium |
| VC5 | Q96 overflow at extreme supply/price | Medium |
| VC6 | Low-decimal / fee-on-transfer silent misallocation | Medium |
| VC7 | Permissionless claim zeroing | Critical (integration impact) |
| VC8 | v1.0.0 bid locking bug | Critical (if applicable) |

**Integration vectors** (bugs in code that calls into CCA):

| ID | Name | Severity |
|----|------|----------|
| VI1 | Stale tokensFilled read after claim | Critical |
| VI2 | Unsafe auction parameter deployment | High |
| VI3 | Direct currency/token transfer to CCA | Medium |
| VI4 | Fill amount stability assumption | High |
| VI5 | Parameter honeypot exposure | High |
| VI6 | v1.0.0 factory version mismatch | Critical (if applicable) |

The scanner auto-detects whether it's looking at CCA core code, integration code, or both — all applicable vectors fire.

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI installed and authenticated
- Solidity source files in the target directory

## Installation

### Option A: Clone into your project

```bash
# From your project root
mkdir -p .claude/commands
curl -o .claude/commands/scan-cca.md \
  https://raw.githubusercontent.com/33Audits/cca-audit-agent/main/.claude/commands/scan-cca.md
```

### Option B: Clone the repo and point at your code

```bash
git clone https://github.com/33Audits/cca-audit-agent.git
cd scan-cca
claude
# Then run: /scan-cca /path/to/your/solidity/project
```

### Option C: Copy the skill file manually

Copy `.claude/commands/scan-cca.md` into your project's `.claude/commands/` directory.

## Usage

Inside a Claude Code session:

```
# Scan the current directory
/scan-cca

# Scan a specific directory
/scan-cca ./contracts

# Scan an absolute path
/scan-cca /path/to/protocol/src
```

### What happens when you run it

1. **Prepare** — Finds all `.sol` files (excludes `test/`, `script/`, `lib/`), concatenates them into a temporary bundle
2. **Double pass** — Launches both agents in parallel:
   - Vector Scan agent reads the bundle, triages all 14 vectors, drops irrelevant ones in 1 line each, deep-analyzes survivors
   - Adversarial Reasoning agent reads all files, maps the CCA interaction surface, reasons adversarially about every call and state read
3. **Merge** — Deduplicates findings, re-numbers, sorts by confidence, presents the report

### Example output

```
📋 CCA Scan Report
Files scanned: 12
Lines analyzed: 3,847
Findings: 3 (1 Critical, 1 High, 1 Medium)

🔴 **1. Stale tokensFilled read enables griefing bot to zero all user allocations**
src/VestingDistributor.sol:142-158 · Confidence: 92

**Description:** VestingDistributor.claimAllocation() reads bid.tokensFilled from CCA
after claimBlock without caching, allowing a front-runner to call claimTokens() first
and zero every user's vesting amount.

**Attack path:**
1. Wait for claimBlock
2. Call CCA.claimTokens(bidId) for all active bidIds (permissionless)
3. VestingDistributor.claimAllocation() now reads tokensFilled = 0 for every user
4. All vesting amounts compute to zero — funds permanently stuck

**Fix:**
\`\`\`diff
- uint256 filled = auction.getBid(bidId).tokensFilled;
+ uint256 filled = cachedFills[bidId]; // cached before claimBlock in snapshot()
\`\`\`

...
```

## How it stays token-efficient

- **Bundle read**: All source is concatenated into one file — agents read it in parallel chunks on turn 1, no repeated file I/O
- **Fast triage**: 14 vectors are classified in a single pass using grep signatures. Irrelevant vectors are dropped in 1 structured line each
- **FP gate**: Every potential finding must pass 3 checks (concrete path, reachable, impactful) before expansion. Kills false positives before they waste tokens
- **Hard stop**: Agents do not revisit eliminated vectors or re-scan

Typical scan of a ~3k line codebase uses ~50-80k tokens total across both agents.

## FP Gate

Every finding must pass all three checks or it's dropped:

1. **Concrete attack path** — Can you trace specific transactions from entry point to harm? (Name the functions.)
2. **Reachable** — Is the path actually reachable past all modifiers, requires, and access control?
3. **Impact** — Does the attacker profit or do users lose funds? Pure inconvenience without fund risk is dropped.

## Customization

The skill file at `.claude/commands/scan-cca.md` is self-contained. You can:

- **Add vectors**: Add new entries to the `CCA Vulnerability Vectors` section following the existing format (ID, grep signatures, description, confirm-if criteria)
- **Adjust severity**: Change the severity classification in the vector definitions
- **Change model**: The agents default to `sonnet` for cost/capability balance. Change to `opus` in the workflow section for maximum depth (costs more)
- **Modify scope**: Edit the exclusion list in the Scope section to include/exclude directories

## References

### 33 Audits

- [33 Audits — Security Considerations for CCA Auditors](https://33audits.hashnode.dev/security-considerations-for-auditors) — Original research on CCA integration vulnerabilities, including the `claimTokens` zeroing vector discovered during a private audit
- [33 Audits — CCA Audit Thread](https://x.com/33audits/status/2029781103435768165) — Summary of CCA-specific attack vectors
- [33 Audits — Flow Protocol Audit Report (PDF)](https://github.com/leeftk/audit-reports/blob/main/private%20audits/audit-report-flow.pdf) — Private audit of a protocol built on CCA where the `tokensFilled` zeroing bug was first identified
- [33audits.xyz](https://www.33audits.xyz/) — Smart contract auditing services

### Uniswap / CCA

- [Uniswap CCA Technical Documentation](https://github.com/Uniswap/continuous-clearing-auction/blob/main/docs/TechnicalDocumentation.md)
- [Uniswap CCA CHANGELOG](https://github.com/Uniswap/continuous-clearing-auction/blob/main/CHANGELOG.md)
- [Spearbit, OpenZeppelin, and ABDK audits](https://github.com/Uniswap/continuous-clearing-auction/blob/main/docs/audits/README.md)
- [Cantina bug bounty](https://cantina.xyz/code/f9df94db-c7b1-434b-bb06-d1360abdd1be/overview)

## License

MIT

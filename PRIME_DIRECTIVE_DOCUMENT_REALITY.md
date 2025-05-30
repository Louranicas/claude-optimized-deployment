# PRIME DIRECTIVE: DOCUMENT REALITY, NOT ASPIRATION (v2.0)
[UPDATED: 2025-05-30 after implementation review]

This directive governs all documentation creation, migration, and maintenance.

## SECTION 1: REALITY FIRST
- Document ONLY what exists and is tested
- Mark future plans explicitly: "PLANNED: [feature]" or "FUTURE: [capability]"
- Use past tense for completed work, future tense for plans
- Replace vague amplifiers with specific measurements or remove entirely

### Forbidden Language (Automatic Rejection)
- "Blazing fast", "Lightning fast", "Supercharge", "Turbocharge"
- "Massive improvement", "Extreme performance", "Revolutionary"
- "Next-generation", "Cutting-edge", "State-of-the-art", "Breakthrough"
- "Unprecedented", "Game-changing"
- Unquantified comparisons ("much faster", "vastly superior")

### Required Qualifiers
- Performance claims: Include benchmark reference or [UNVERIFIED]
- Scale claims: Include test conditions or [THEORETICAL]
- Feature descriptions: Include [IMPLEMENTED], [PLANNED], or [EXPERIMENTAL]

## SECTION 2: ARTIFACT CREEP PREVENTION
- TAG all migrated content: [MIGRATED FROM: project_name, DATE: YYYY-MM-DD]
- PRESERVE original context, limitations, and caveats
- ADD reality checks when migrating optimistic claims
- CHALLENGE any claim that seems "too good to be true"
- TRACE all performance claims to source benchmarks

### Migration Checklist
```
[ ] Added [MIGRATED FROM] tag
[ ] Verified all claims against source
[ ] Added [UNVERIFIED] to questionable claims  
[ ] Preserved original caveats
[ ] Checked for marketing language
```

## SECTION 3: VERIFICATION CHAIN
Every quantitative claim must have:
- ✅ Benchmark file reference: `[VERIFIED: benchmark_name_YYYYMMDD.json]`
- ⚠️ Unverified marker: `[UNVERIFIED: needs benchmark]`
- 📝 Theoretical marker: `[THEORETICAL: based on ...]`
- ❌ Disproven marker: `[DISPROVEN: see benchmark_name.json]`

Every capability must show:
- Working example with link to code
- OR explicit [PLANNED: target date]
- OR [EXPERIMENTAL: limitations]

## SECTION 4: REGULAR AUDITS

### Automated Checks (scripts/check_documentation_reality.py)
- Run on every PR
- Flag forbidden phrases
- Detect unverified claims
- Check for required tags
- Generate report

### Manual Reviews
- Weekly: New documentation review
- Monthly: Performance claims verification
- Quarterly: Full documentation audit
- On update: Regression check

## SECTION 5: DOCUMENTATION STANDARDS

### File Headers (Required)
```markdown
# Document Title
[LAST VERIFIED: YYYY-MM-DD]
[STATUS: Draft|Review|Stable]
[MIGRATED FROM: source, DATE: YYYY-MM-DD] (if applicable)
```

### Performance Claims Format
```markdown
Operation X shows 3.2x median improvement for data >1MB
[VERIFIED: benchmark_operation_x_20250530.json]
- Conditions: Ubuntu 22.04, 8-core CPU, 16GB RAM
- Baseline: Python 3.10, library v2.1
- Optimized: Rust 1.70, custom implementation
- Variance: ±5% across 100 runs
```

### Feature Status Markers
```markdown
## Current Features [IMPLEMENTED]
- ✅ Basic configuration parsing
- ✅ Service health checks (10 services/second)

## Upcoming Features [PLANNED]
- 🚧 Natural language interface (Target: Q3 2025)
- 🚧 Multi-cloud support (Target: Q4 2025)

## Experimental Features [EXPERIMENTAL]
- 🧪 Rust acceleration (Performance varies by workload)
```

## SECTION 6: CORRECTION PROTOCOL

When false/inflated claims are found:
1. **IMMEDIATELY**: Add [CORRECTION NEEDED] tag
2. **INVESTIGATE**: Trace claim to source
3. **MEASURE**: Run benchmark if possible
4. **UPDATE**: Fix all instances with reality
5. **DOCUMENT**: Add to traceability matrix
6. **LEARN**: Update checks to catch similar issues

### Correction Format
```markdown
~~Original claim~~ [CORRECTED: YYYY-MM-DD]
Actual measurement: [new claim with evidence]
```

## SECTION 7: BENCHMARK REQUIREMENTS

### Before Any Performance Claim
1. Use scripts/benchmark_template.py
2. Run in controlled environment
3. Document all conditions
4. Include variance/stability metrics
5. Save benchmark file with timestamp
6. Update traceability matrix

### Benchmark Naming Convention
`benchmark_[operation]_[YYYYMMDD]_[HHMMSS].json`

## SECTION 8: ENFORCEMENT

### Technical Enforcement
- Pre-commit hooks check for forbidden phrases
- CI pipeline runs documentation checker
- Benchmark results required for performance PRs
- Traceability matrix must be updated

### Cultural Enforcement
- Celebrate accurate documentation
- Reward finding inflated claims
- Make "Show me the benchmark" standard
- Treat documentation bugs as P1 issues

## SECTION 9: QUICK REFERENCE

### Every Claim Needs
```
Claim [STATUS] (Evidence)
```

### Status Options
- [VERIFIED: benchmark_file.json]
- [UNVERIFIED: needs testing]
- [THEORETICAL: based on ...]
- [DISPROVEN: see evidence]
- [MIGRATED FROM: source, DATE]

### Red Flags 🚩
- Percentages without baseline
- Multipliers without conditions  
- Present tense for future features
- Superlatives without evidence
- Claims without status markers

## REMEMBER

> "Trust is lost in buckets and earned in drops."

One false claim contaminates all documentation. When in doubt:
1. Understate and caveat
2. Mark as unverified
3. Defer to benchmarks
4. Ask for evidence

---

**Enforcement Date**: Immediate
**Review Cycle**: Monthly
**Owner**: All contributors
**Violations**: Require immediate correction before merge
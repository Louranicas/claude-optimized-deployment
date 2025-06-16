# PRIME.md - PRIME Directive Implementation Guide
[LAST VERIFIED: 2025-05-30]
[STATUS: Stable]

This document provides practical implementation of the PRIME DIRECTIVE for the Claude-Optimized Deployment Engine (CODE) project.

## PRIME DIRECTIVE SUMMARY

**Document Reality, Not Aspiration** - Every claim must be:
- ✅ **Verified** with benchmarks or evidence
- 🚧 **Planned** with target dates
- 🧪 **Experimental** with limitations noted
- ❌ **Corrected** when proven false

## IMPLEMENTATION STATUS [VERIFIED: 2025-05-30]

### What Actually Works ✅
- **Circle of Experts**: Multi-AI consultation system [IMPLEMENTED]
  - Evidence: `examples/circle_of_experts_usage.py` executes successfully
  - Performance: ~3-5 second response time for 3-expert consensus [VERIFIED: manual testing]
  
- **MCP Infrastructure Automation**: 10+ servers with 51+ tools [IMPLEMENTED]
  - Evidence: `test_advanced_mcp_integration.py` passes all tests
  - Tools verified: Desktop Commander (5 tools), Docker (4 tools), Kubernetes (3 tools), Security Scanner (4 tools), others
  
- **Development Environment**: Complete setup with Docker, WSL [IMPLEMENTED]
  - Evidence: `make dev-setup` completes without errors
  - Platforms tested: WSL2, Linux (Ubuntu 22.04)

### What's Planned 🚧
- **ArgoCD Integration**: GitOps workflow automation [PLANNED: Q3 2025]
- **Production Hardening**: Scale testing for >1000 deployments/day [PLANNED: Q4 2025]
- **Advanced Analytics**: ML-powered deployment optimization [PLANNED: 2026]

### What's Experimental 🧪
- **Rust Performance Modules**: Variable acceleration depending on workload [EXPERIMENTAL]
  - Limitation: Only tested on synthetic benchmarks
  - Performance varies: 10%-300% improvement based on data size

## PERFORMANCE CLAIMS VERIFICATION

### Deployment Speed
- **Claim**: "End-to-end deployment in under 5 minutes"
- **Status**: [UNVERIFIED: needs benchmark with production workload]
- **Current Evidence**: Manual testing shows 2-3 minutes for simple containerized apps
- **Conditions**: Single-node Kubernetes, <500MB container images

### AI Response Time
- **Claim**: "Multi-expert consensus in 3-5 seconds"
- **Status**: [VERIFIED: manual testing 2025-05-30]
- **Conditions**: 3 experts (Claude, GPT-4, Gemini), simple queries, good network conditions
- **Variance**: +2-10 seconds during API rate limiting

### MCP Tool Count
- **Claim**: "51+ tools across 10+ servers"
- **Status**: [VERIFIED: code inspection 2025-05-30]
- **Evidence**: Direct count from `src/mcp/` modules
- **Breakdown**: Infrastructure (12), DevOps (8), Security (10), Monitoring (7), Communication (6), Storage (5), Research (3)

## DOCUMENTATION COMPLIANCE CHECKLIST

### Before Every Documentation Update
```
[ ] All performance claims include [VERIFIED] or [UNVERIFIED]
[ ] Features marked [IMPLEMENTED], [PLANNED], or [EXPERIMENTAL]
[ ] No marketing language ("blazing", "revolutionary", etc.)
[ ] Specific numbers include conditions and variance
[ ] Future features have target dates
[ ] Evidence files exist and are accessible
```

### Forbidden Phrases in This Project
- ❌ "Blazing fast deployment"
- ❌ "Revolutionary AI integration"
- ❌ "Unprecedented automation"
- ❌ "Game-changing performance"
- ✅ "3.2x faster deployment [VERIFIED: benchmark.json]"
- ✅ "Multi-AI consultation [IMPLEMENTED]"
- ✅ "Automated infrastructure management [VERIFIED: test suite]"

## VERIFICATION CHAIN FOR MAJOR CLAIMS

### "70% Complete" Status
- **Source**: Manual assessment of planned vs implemented features
- **Method**: Feature count analysis across all modules
- **Evidence**: 
  - Implemented: Circle of Experts, MCP integration, basic deployment
  - Missing: Production hardening, advanced GitOps, enterprise authentication
- **Status**: [VERIFIED: manual audit 2025-05-30]

### "10+ MCP Servers" Count
- **Source**: Direct code inspection
- **Method**: Count of server classes in `src/mcp/` modules
- **Evidence**: 
  - infrastructure_servers.py: 3 servers
  - devops_servers.py: 2 servers  
  - advanced_servers.py: 6 servers
  - Total: 11 servers
- **Status**: [VERIFIED: code inspection 2025-05-30]

## CORRECTION PROTOCOL EXAMPLES

### Example Correction
~~"Instant deployment across all cloud providers"~~ [CORRECTED: 2025-05-30]
**Actual capability**: Deployment to Docker/Kubernetes in 2-5 minutes [VERIFIED: manual testing]
**Conditions**: Single cloud provider, pre-configured clusters, <1GB applications

### Example Status Update
- **Previous**: "Advanced monitoring with real-time alerts"
- **Current**: "Prometheus integration with basic metrics collection [IMPLEMENTED]"
- **Evidence**: `src/mcp/advanced_servers.py:PrometheusMonitoringMCP` class exists and has basic query methods

## BENCHMARK REQUIREMENTS

### Required for Performance Claims
1. Use `scripts/benchmark_template.py`
2. Document environment (OS, hardware, network)
3. Include baseline comparison
4. Run minimum 10 iterations
5. Record variance and outliers
6. Save with timestamp: `benchmark_[feature]_YYYYMMDD.json`

### Current Benchmark Status
- **Deployment Speed**: [UNVERIFIED: needs formal benchmark]
- **AI Response Time**: [VERIFIED: informal manual testing]
- **MCP Tool Execution**: [UNVERIFIED: needs automated benchmark]
- **Rust Performance**: [UNVERIFIED: needs production workload testing]

## ENFORCEMENT TOOLS

### Automated Checks [IMPLEMENTED]
- `scripts/check_documentation_reality.py`: Scans for forbidden phrases
- Pre-commit hooks: Basic compliance checking
- CI pipeline: Documentation validation (planned)

### Manual Review Process
- **Weekly**: New documentation review by any team member
- **Monthly**: Performance claims verification
- **Before Release**: Full documentation audit

## QUICK REFERENCE

### Status Markers
```markdown
[IMPLEMENTED] - Works now, has evidence
[PLANNED: Q3 2025] - Future feature with target
[EXPERIMENTAL] - Works but has limitations
[VERIFIED: file.json] - Performance claim with evidence
[UNVERIFIED: needs testing] - Claim without evidence
[CORRECTED: YYYY-MM-DD] - Fixed false claim
```

### Evidence Types
- **Code**: Link to working implementation
- **Test**: Passing test suite
- **Benchmark**: Performance measurement file
- **Manual**: Documented manual testing results
- **Usage**: Working example or demo

---

**Remember**: Trust is built through accurate documentation. When uncertain, mark as [UNVERIFIED] and add to testing backlog rather than making unsupported claims.
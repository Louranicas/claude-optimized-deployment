# Security Validation Report

**Generated**: 2025-06-13T13:48:13.119054  
**Pass Rate**: 60.0%  
**Total Issues**: 1371  

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | 10 |
| Passed | 6 |
| Failed | 4 |
| Critical Issues | 1360 |
| High Issues | 11 |
| Medium Issues | 0 |
| Low Issues | 0 |

## Test Results

### Hardcoded Secrets

| Severity | Type | Finding | File |
|----------|------|---------|------|
| CRITICAL | Token | Potential Token exposed | security_audit_test.py (L494) |
| CRITICAL | Password | Potential Password exposed | test_rbac_direct.py (L132) |
| CRITICAL | Password | Potential Password exposed | test_rbac_core.py (L94) |
| CRITICAL | Password | Potential Password exposed | dependency_integration_test.py (L73) |
| CRITICAL | Password | Potential Password exposed | bandit_comprehensive_report.json (L1597) |
| CRITICAL | Password | Potential Password exposed | bandit_comprehensive_report.json (L1617) |
| CRITICAL | Password | Potential Password exposed | bandit_comprehensive_report.json (L1637) |
| CRITICAL | Password | Potential Password exposed | bandit_comprehensive_report.json (L1657) |
| CRITICAL | Password | Potential Password exposed | bandit_comprehensive_report.json (L1677) |
| CRITICAL | Password | Potential Password exposed | bandit_comprehensive_report.json (L1773) |
| CRITICAL | Password | Potential Password exposed | bandit_comprehensive_report.json (L1793) |
| CRITICAL | Password | Potential Password exposed | bandit_comprehensive_report.json (L1813) |
| CRITICAL | Password | Potential Password exposed | bandit_comprehensive_report.json (L1883) |
| CRITICAL | Password | Potential Password exposed | bandit_comprehensive_report.json (L1903) |
| CRITICAL | Password | Potential Password exposed | bandit_comprehensive_report.json (L1923) |
| CRITICAL | Password | Potential Password exposed | bandit_comprehensive_report.json (L2003) |
| CRITICAL | API Key | Potential API Key exposed | test_mcp_security_integration.py (L73) |
| CRITICAL | Password | Potential Password exposed | test_mcp_security_integration.py (L113) |
| CRITICAL | Password | Potential Password exposed | test_rbac_standalone.py (L280) |
| CRITICAL | Password | Potential Password exposed | test_rbac_standalone.py (L288) |
| CRITICAL | API Key | Potential API Key exposed | agent_6_comprehensive_integration_testing_framework.py (L536) |
| CRITICAL | API Key | Potential API Key exposed | agent_6_comprehensive_integration_testing_framework.py (L579) |
| CRITICAL | Password | Potential Password exposed | test_mcp_security_comprehensive.py (L290) |
| CRITICAL | Password | Potential Password exposed | test_mcp_security_comprehensive.py (L556) |
| CRITICAL | Password | Potential Password exposed | test_mcp_security_comprehensive.py (L639) |
| CRITICAL | API Key | Potential API Key exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L108463) |
| CRITICAL | API Key | Potential API Key exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L108583) |
| CRITICAL | API Key | Potential API Key exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L206915) |
| CRITICAL | API Key | Potential API Key exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L207035) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L3577) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L3585) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L3697) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L5456) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L5464) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L5616) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L5656) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L5672) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L108511) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L108519) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L206963) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L206971) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L207977) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L207985) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L211713) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L211721) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L211833) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L213592) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L213600) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L213752) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L213792) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json (L213808) |
| CRITICAL | Password | Potential Password exposed | test_rbac_system.py (L227) |
| CRITICAL | Password | Potential Password exposed | test_rbac_system.py (L239) |
| CRITICAL | Password | Potential Password exposed | test_rbac_system.py (L249) |
| CRITICAL | Password | Potential Password exposed | test_rbac_system.py (L250) |
| CRITICAL | Password | Potential Password exposed | test_rbac_system.py (L380) |
| CRITICAL | Password | Potential Password exposed | test_rbac_system.py (L396) |
| CRITICAL | Password | Potential Password exposed | test_rbac_system.py (L443) |
| CRITICAL | Password | Potential Password exposed | test_rbac_system.py (L452) |
| CRITICAL | API Key | Potential API Key exposed | test_production_modules_comprehensive.py (L376) |
| CRITICAL | Password | Potential Password exposed | test_production_modules_comprehensive.py (L431) |
| CRITICAL | Password | Potential Password exposed | security_audit_phase3_infrastructure.py (L50) |
| CRITICAL | Password | Potential Password exposed | security_audit_phase3_infrastructure.py (L109) |
| CRITICAL | API Key | Potential API Key exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L10274) |
| CRITICAL | API Key | Potential API Key exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L10310) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L153) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L307) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L314) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L1231) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L1238) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L1259) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5137) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5144) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5151) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5158) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5165) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5172) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5179) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5186) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5193) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5200) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5207) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5389) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5396) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5403) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5410) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5417) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5424) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5431) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5438) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5445) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5452) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5459) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5466) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5473) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5480) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5487) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5494) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5501) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5508) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5515) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5522) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5529) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5536) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5543) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5550) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5585) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5592) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5599) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5606) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5613) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5620) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5634) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5641) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5648) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5655) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5662) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5669) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5676) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5683) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5690) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5697) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5704) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5711) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5718) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5725) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5732) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5739) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5746) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5753) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5760) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5767) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5774) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5781) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5788) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5795) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5802) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5809) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5844) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5851) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5858) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5865) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5872) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5879) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5893) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5900) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5907) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5914) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5921) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5928) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5935) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5942) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5949) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5956) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5963) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5970) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5977) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5984) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5991) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L5998) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6005) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6012) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6019) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6026) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6033) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6040) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6047) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6054) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6061) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6068) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6075) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6082) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6089) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6096) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6103) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6110) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6117) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6124) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6131) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6138) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6145) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6152) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6159) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6166) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6173) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6180) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6187) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6194) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6201) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6208) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6215) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6222) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6229) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6236) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6243) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6250) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6257) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6264) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6271) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6278) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6285) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6292) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6299) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6306) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6313) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6320) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6327) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6334) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6341) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6348) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6355) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6362) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6369) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6376) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6383) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6390) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6397) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6404) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6411) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6418) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6425) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6432) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6439) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6446) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6453) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6460) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6467) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6474) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6481) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6488) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6495) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6502) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6509) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6516) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6523) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6530) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6565) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6572) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6579) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6586) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6593) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6600) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6614) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6621) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6628) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6635) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6642) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6649) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6656) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6663) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6670) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6677) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6684) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6691) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6698) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6705) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6712) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6719) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6726) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6733) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6740) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6747) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6754) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6761) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6768) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6775) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6782) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6789) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6824) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6831) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6838) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6845) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6852) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6859) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6873) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6880) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6887) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6894) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6901) |
| CRITICAL | Password | Potential Password exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L6978) |
| CRITICAL | Private Key | Potential Private Key exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L328) |
| CRITICAL | Private Key | Potential Private Key exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L3590) |
| CRITICAL | Private Key | Potential Private Key exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L3597) |
| CRITICAL | Private Key | Potential Private Key exposed | AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json (L3604) |
| CRITICAL | Password | Potential Password exposed | docker-compose.vault.yml (L89) |
| CRITICAL | Password | Potential Password exposed | venv_security/lib/python3.12/site-packages/cryptography/hazmat/_oid.py (L347) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_security/lib/python3.12/site-packages/cryptography/hazmat/primitives/serialization/ssh.py (L78) |
| CRITICAL | Password | Potential Password exposed | venv_security/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L520) |
| CRITICAL | Password | Potential Password exposed | venv_security/lib/python3.12/site-packages/pip/_internal/network/auth.py (L462) |
| CRITICAL | Bearer Token | Potential Bearer Token exposed | code-base-crawler/code-base-crawler/enhanced_security_audit_results_20250608_101718.json (L206) |
| CRITICAL | Password | Potential Password exposed | code-base-crawler/code-base-crawler/security_scan.py (L99) |
| CRITICAL | Bearer Token | Potential Bearer Token exposed | code-base-crawler/code-base-crawler/run_security_audit.py (L302) |
| CRITICAL | Password | Potential Password exposed | code-base-crawler/code-base-crawler/run_enhanced_security_audit.py (L303) |
| CRITICAL | Token | Potential Token exposed | code-base-crawler/code-base-crawler/run_enhanced_security_audit.py (L303) |
| CRITICAL | Bearer Token | Potential Bearer Token exposed | code-base-crawler/code-base-crawler/run_enhanced_security_audit.py (L271) |
| CRITICAL | Password | Potential Password exposed | code-base-crawler/code-base-crawler/security_env/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L520) |
| CRITICAL | Password | Potential Password exposed | code-base-crawler/code-base-crawler/security_env/lib/python3.12/site-packages/pip/_internal/network/auth.py (L462) |
| CRITICAL | Bearer Token | Potential Bearer Token exposed | code-base-crawler/code-base-crawler/cbc_security/error_sanitizer.py (L289) |
| CRITICAL | Password | Potential Password exposed | code-base-crawler/code-base-crawler/monitoring/alertmanager.yml (L6) |
| CRITICAL | Password | Potential Password exposed | code-base-crawler/code-base-crawler/anam_py/test_env/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L520) |
| CRITICAL | Password | Potential Password exposed | code-base-crawler/code-base-crawler/anam_py/test_env/lib/python3.12/site-packages/pip/_internal/network/auth.py (L462) |
| CRITICAL | Password | Potential Password exposed | security_env/lib/python3.12/site-packages/pydantic/types.py (L1695) |
| CRITICAL | Password | Potential Password exposed | security_env/lib/python3.12/site-packages/opentelemetry/sdk/environment_variables.py (L238) |
| CRITICAL | Password | Potential Password exposed | security_env/lib/python3.12/site-packages/face/testing.py (L62) |
| CRITICAL | Password | Potential Password exposed | security_env/lib/python3.12/site-packages/cyclonedx/model/crypto.py (L712) |
| CRITICAL | Password | Potential Password exposed | security_env/lib/python3.12/site-packages/cryptography/hazmat/_oid.py (L347) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | security_env/lib/python3.12/site-packages/cryptography/hazmat/primitives/serialization/ssh.py (L78) |
| CRITICAL | Password | Potential Password exposed | security_env/lib/python3.12/site-packages/httpx/_urls.py (L336) |
| CRITICAL | Token | Potential Token exposed | security_env/lib/python3.12/site-packages/boolean/boolean.py (L240) |
| CRITICAL | Password | Potential Password exposed | security_env/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L23) |
| CRITICAL | Password | Potential Password exposed | security_env/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L159) |
| CRITICAL | Password | Potential Password exposed | security_env/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L164) |
| CRITICAL | Password | Potential Password exposed | security_env/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L217) |
| CRITICAL | Password | Potential Password exposed | security_env/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L222) |
| CRITICAL | Password | Potential Password exposed | security_env/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L520) |
| CRITICAL | Password | Potential Password exposed | security_env/lib/python3.12/site-packages/pip/_internal/network/auth.py (L462) |
| CRITICAL | Token | Potential Token exposed | security_env/lib/python3.12/site-packages/nltk/tokenize/treebank.py (L249) |
| CRITICAL | Token | Potential Token exposed | security_env/lib/python3.12/site-packages/nltk/sem/logic.py (L585) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/pydantic/types.py (L1819) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/pydantic/types.py (L1846) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/starlette/datastructures.py (L166) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/cryptography/hazmat/_oid.py (L347) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/cryptography/hazmat/primitives/serialization/ssh.py (L78) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/httpx/_urls.py (L336) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L80) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L215) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L245) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/sqlalchemy/dialects/sqlite/provision.py (L76) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/cx_oracle.py (L198) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/cx_oracle.py (L242) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/oracledb.py (L271) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/oracledb.py (L313) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/oracledb.py (L345) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/provision.py (L193) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/sqlalchemy/dialects/mysql/mysqldb.py (L206) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L520) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/pip/_internal/network/auth.py (L462) |
| CRITICAL | Token | Potential Token exposed | test_env/lib/python3.12/site-packages/alembic/script/write_hooks.py (L25) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/protocols/ftp.py (L2891) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/test/test_ftp.py (L148) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/cred/test/test_strcred.py (L287) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/cred/test/test_strcred.py (L311) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/cred/test/test_strcred.py (L339) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/python/util.py (L320) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/python/util.py (L323) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/python/test/test_fakepwd.py (L200) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/python/test/test_fakepwd.py (L218) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/python/test/test_fakepwd.py (L386) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/python/test/test_fakepwd.py (L408) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/conch/telnet.py (L1096) |
| CRITICAL | Private Key | Potential Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L305) |
| CRITICAL | Private Key | Potential Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L364) |
| CRITICAL | Private Key | Potential Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L429) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L188) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L217) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L272) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L288) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L334) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L397) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L591) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_default.py (L213) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_ckeygen.py (L438) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_ckeygen.py (L674) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1262) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1265) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1294) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1297) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1325) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1328) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1344) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1347) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_checkers.py (L72) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_checkers.py (L87) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_checkers.py (L102) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/conch/test/test_userauth.py (L786) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/ssh/keys.py (L395) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | test_env/lib/python3.12/site-packages/twisted/conch/ssh/keys.py (L1511) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/conch/ssh/userauth.py (L526) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/conch/ssh/userauth.py (L725) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/conch/client/default.py (L208) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/conch/scripts/tkconch.py (L513) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/mail/_cred.py (L48) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/mail/smtp.py (L1974) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/mail/test/test_smtp.py (L1805) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/words/test/test_irc.py (L2235) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/words/test/test_irc.py (L2256) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/words/test/test_ircsupport.py (L74) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/words/test/test_jabberclient.py (L104) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/words/test/test_jabbersasl.py (L243) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/words/test/test_jabbersasl.py (L253) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/words/test/test_jabbersasl.py (L264) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/words/test/test_jabbersasl.py (L275) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/words/test/test_jabbersaslmechanisms.py (L145) |
| CRITICAL | Password | Potential Password exposed | test_env/lib/python3.12/site-packages/twisted/words/test/test_jabbercomponent.py (L32) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/pydantic/types.py (L1819) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/pydantic/types.py (L1846) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/opentelemetry/sdk/environment_variables.py (L238) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/oauthlib/oauth2/rfc6749/clients/legacy_application.py (L73) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/google/oauth2/challenges.py (L101) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/google/auth/metrics.py (L30) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/google/auth/metrics.py (L31) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_bulletproof/lib/python3.12/site-packages/google/auth/crypt/_python_rsa.py (L38) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_bulletproof/lib/python3.12/site-packages/google/auth/crypt/_python_rsa.py (L39) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_bulletproof/lib/python3.12/site-packages/google/auth/transport/_mtls_helper.py (L34) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_bulletproof/lib/python3.12/site-packages/google/auth/transport/_mtls_helper.py (L36) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/starlette/datastructures.py (L166) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/face/testing.py (L62) |
| CRITICAL | API Key | Potential API Key exposed | venv_bulletproof/lib/python3.12/site-packages/tornado/test/auth_test.py (L337) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/tornado/test/curl_httpclient_test.py (L106) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/tornado/test/curl_httpclient_test.py (L123) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/tornado/test/httpclient_test.py (L268) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/tornado/test/httpclient_test.py (L278) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/tornado/test/httpclient_test.py (L287) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/tornado/test/httpclient_test.py (L295) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/tornado/test/httpclient_test.py (L308) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/cyclonedx/model/crypto.py (L712) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/cryptography/hazmat/_oid.py (L314) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_bulletproof/lib/python3.12/site-packages/cryptography/hazmat/primitives/serialization/ssh.py (L78) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/huggingface_hub/_login.py (L353) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/botocore/credentials.py (L1911) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/botocore/data/iam/2010-05-08/examples-1.json (L1430) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/httpx/_urls.py (L336) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/amqp/connection.py (L191) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_bulletproof/lib/python3.12/site-packages/PIL/ImageFont.py (L1274) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/boolean/boolean.py (L240) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/pymysql/connections.py (L1026) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/transformers/testing_utils.py (L200) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/transformers/models/idefics/processing_idefics.py (L387) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/transformers/models/cohere/tokenization_cohere_fast.py (L121) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/transformers/models/llama4/processing_llama4.py (L113) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/transformers/models/llama4/processing_llama4.py (L114) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/transformers/models/kosmos2/processing_kosmos2.py (L108) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/mcp/shared/_httpx_utils.py (L60) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_bulletproof/lib/python3.12/site-packages/rsa/pem.py (L88) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_bulletproof/lib/python3.12/site-packages/rsa/pem.py (L115) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_bulletproof/lib/python3.12/site-packages/rsa/key.py (L603) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L23) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L159) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L164) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L217) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L222) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L75) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L200) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L230) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/sqlalchemy/dialects/sqlite/provision.py (L78) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/cx_oracle.py (L162) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/cx_oracle.py (L197) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/provision.py (L193) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/sqlalchemy/dialects/mysql/mysqldb.py (L204) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/grpc/_server.py (L63) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/grpc/_server.py (L64) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/grpc/_server.py (L70) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_bulletproof/lib/python3.12/site-packages/googleapiclient/discovery_cache/documents/appengine.v1.json (L2148) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_bulletproof/lib/python3.12/site-packages/googleapiclient/discovery_cache/documents/appengine.v1beta.json (L2366) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_bulletproof/lib/python3.12/site-packages/googleapiclient/discovery_cache/documents/appengine.v1alpha.json (L1023) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/psycopg2/__init__.py (L90) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/psycopg2/errorcodes.py (L269) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L478) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/pip/_internal/network/auth.py (L467) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/alembic/script/write_hooks.py (L25) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/nltk/tokenize/treebank.py (L249) |
| CRITICAL | Token | Potential Token exposed | venv_bulletproof/lib/python3.12/site-packages/nltk/sem/logic.py (L585) |
| CRITICAL | Password | Potential Password exposed | venv_bulletproof/lib/python3.12/site-packages/kubernetes/config/kube_config_test.py (L89) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/fsspec/spec.py (L1612) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/pexpect/pxssh.py (L73) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/pexpect/pxssh.py (L110) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/pexpect/pty_spawn.py (L138) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/pexpect/pty_spawn.py (L350) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/pexpect/__init__.py (L29) |
| CRITICAL | API Key | Potential API Key exposed | venv_ai/lib/python3.12/site-packages/tornado/test/auth_test.py (L337) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/tornado/test/curl_httpclient_test.py (L106) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/tornado/test/curl_httpclient_test.py (L123) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/tornado/test/httpclient_test.py (L268) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/tornado/test/httpclient_test.py (L278) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/tornado/test/httpclient_test.py (L287) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/tornado/test/httpclient_test.py (L295) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/tornado/test/httpclient_test.py (L308) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/6873.d5b12730d4556b6f37bf.js (L294) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/notebook/static/7995.45be6443b704da1daafc.js (L2950) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/8218.983a3a002f016180aaab.js (L238) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/7159.41e52038b70d27a3b442.js (L223) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/2409.6091282e2ebffe2ab089.js (L1580) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/6491.4ec5e8e76fbff7d9698a.js (L212) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/310.857f702af7a4a486c75e.js (L6422) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/4886.6084c97eb0f7628908ee.js (L366) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/7488.4d8124f72a0f10256f44.js (L413) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/9442.e301e4179b7c69c125d7.js (L860) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/2019.a0afb11aac931fb43c5c.js (L340) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/notebook/static/417.29f636ec8be265b7e480.js (L21599) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/6428.e4e53b40817c3dd248ca.js (L198) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/1939.e620a31e5ee7d4ccc1bc.js (L282) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/3211.2e93fd406e5c4e53774f.js (L70) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/3211.2e93fd406e5c4e53774f.js (L73) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/4667.288ec271d366f6d03bf4.js (L165) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/1950.a590659714a301a94f31.js (L911) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/1091.f006368c55525d627dc3.js (L74) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/2453.ebdb135eb902bf82e103.js (L509) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/notebook/static/145.2fd139f1721cfaedfccf.js (L338) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/huggingface_hub/_login.py (L353) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/jupyter_client/ssh/tunnel.py (L299) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/jupyter_client/ssh/tunnel.py (L374) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/jupyter_client/ssh/tunnel.py (L413) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/httpx/_urls.py (L336) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/PIL/ImageFont.py (L1274) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/transformers/testing_utils.py (L200) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/transformers/models/idefics/processing_idefics.py (L387) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/transformers/models/cohere/tokenization_cohere_fast.py (L121) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/transformers/models/llama4/processing_llama4.py (L113) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/transformers/models/llama4/processing_llama4.py (L114) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/transformers/models/kosmos2/processing_kosmos2.py (L108) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/jupyter_server/auth/__main__.py (L20) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/jupyter_server/auth/__main__.py (L21) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/jupyter_server/auth/security.py (L51) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/jupyter_server/auth/security.py (L52) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L478) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/pip/_internal/network/auth.py (L467) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/zmq/ssh/tunnel.py (L295) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/zmq/ssh/tunnel.py (L365) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/zmq/ssh/tunnel.py (L397) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/6214.617de47747c5a9b19ef7.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/4982.c609185756485c6e3344.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/2023.59b30086fbeff6d17e3b.js (L1) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/6733.2d8d3e01d56d79a52e7e.js (L2) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/4311.b44e8bc4829e0b1226d2.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/6364.c592f3101de349ba3904.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/8038.aea19fb961abd87d6255.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/1912.f16dddc294d66c3c81e9.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/9572.f91bbaa33e932d524f8f.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/805.2a0b8ac50aa8e6ab096f.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/339.380593b40d8d41150a4e.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/580.4ea1e6182e0b35ff091a.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/8915.ab253990b1581460b255.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/9881.37d189ff085cb3468683.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/8855.b17b9969fce42d0398e4.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/5135.7f204de2153e4d85406d.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/7881.c5a234ce171f347c94e2.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/7881.c5a234ce171f347c94e2.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/1359.d5f23f0e2a6f67b69751.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/3358.7ba73a6804155b619b44.js (L1) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/static/232.5419cbec68e3fd0cf431.js (L848) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L196) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L710) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/jupyterlab/staging/yarn.js (L727) |
| CRITICAL | Password | Potential Password exposed | venv_ai/lib/python3.12/site-packages/ptyprocess/ptyprocess.py (L434) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/skimage/measure/_marching_cubes_lewiner_luts.py (L194) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | venv_ai/lib/python3.12/site-packages/skimage/measure/_marching_cubes_lewiner_luts.py (L437) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/6214.617de47747c5a9b19ef7.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/4982.c609185756485c6e3344.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/2023.59b30086fbeff6d17e3b.js (L1) |
| CRITICAL | Password | Potential Password exposed | venv_ai/share/jupyter/lab/static/6733.2d8d3e01d56d79a52e7e.js (L2) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/4311.b44e8bc4829e0b1226d2.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/6364.c592f3101de349ba3904.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/8038.aea19fb961abd87d6255.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/1912.f16dddc294d66c3c81e9.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/9572.f91bbaa33e932d524f8f.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/805.2a0b8ac50aa8e6ab096f.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/339.380593b40d8d41150a4e.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/580.4ea1e6182e0b35ff091a.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/8915.ab253990b1581460b255.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/9881.37d189ff085cb3468683.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/8855.b17b9969fce42d0398e4.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/5135.7f204de2153e4d85406d.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/7881.c5a234ce171f347c94e2.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/7881.c5a234ce171f347c94e2.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/1359.d5f23f0e2a6f67b69751.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_ai/share/jupyter/lab/static/3358.7ba73a6804155b619b44.js (L1) |
| CRITICAL | Password | Potential Password exposed | venv_ai/share/jupyter/lab/static/232.5419cbec68e3fd0cf431.js (L848) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | tests/integration/test_mcp_security_scenarios.py (L141) |
| CRITICAL | Password | Potential Password exposed | tests/integration/test_mcp_security_scenarios.py (L139) |
| CRITICAL | Private Key | Potential Private Key exposed | tests/integration/test_mcp_security_scenarios.py (L142) |
| CRITICAL | Token | Potential Token exposed | tests/integration/test_mcp_authentication_authorization.py (L626) |
| CRITICAL | Password | Potential Password exposed | tests/security/conftest.py (L111) |
| CRITICAL | Password | Potential Password exposed | tests/security/conftest.py (L127) |
| CRITICAL | Password | Potential Password exposed | tests/security/conftest.py (L176) |
| CRITICAL | Password | Potential Password exposed | tests/security/conftest.py (L183) |
| CRITICAL | Password | Potential Password exposed | tests/security/conftest.py (L190) |
| CRITICAL | Password | Potential Password exposed | tests/security/test_security_regression.py (L312) |
| CRITICAL | Password | Potential Password exposed | tests/security/test_authentication_bypass.py (L31) |
| CRITICAL | Password | Potential Password exposed | tests/security/comprehensive_security_tests.py (L128) |
| CRITICAL | Password | Potential Password exposed | tests/api/test_pydantic_schemas.py (L52) |
| CRITICAL | Password | Potential Password exposed | tests/api/test_pydantic_schemas.py (L56) |
| CRITICAL | Password | Potential Password exposed | tests/api/test_pydantic_schemas.py (L124) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L106) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L140) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L157) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L175) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L200) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L222) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L239) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L272) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L297) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L312) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L343) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L344) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L366) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L367) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L379) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L380) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L836) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L846) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L869) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L877) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L900) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L918) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L954) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L996) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L1002) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L1038) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L1069) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L1090) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L1110) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L1146) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_user_manager.py (L1172) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_models.py (L115) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_models.py (L898) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_models.py (L912) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_models.py (L920) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_models.py (L928) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_models.py (L983) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_api.py (L510) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_api.py (L511) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_auth_production.py (L814) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_auth_production.py (L855) |
| CRITICAL | Password | Potential Password exposed | tests/auth/test_auth_production.py (L912) |
| CRITICAL | API Key | Potential API Key exposed | k8s/example-deployment-with-vault.yaml (L45) |
| CRITICAL | API Key | Potential API Key exposed | k8s/example-deployment-with-vault.yaml (L46) |
| CRITICAL | API Key | Potential API Key exposed | k8s/example-deployment-with-vault.yaml (L47) |
| CRITICAL | Password | Potential Password exposed | k8s/example-deployment-with-vault.yaml (L32) |
| CRITICAL | Password | Potential Password exposed | k8s/mcp-deployment.yaml (L43) |
| CRITICAL | Password | Potential Password exposed | deploy/config/environments/development.yaml (L45) |
| CRITICAL | Password | Potential Password exposed | deploy/config/environments/production.yaml (L43) |
| CRITICAL | Password | Potential Password exposed | deploy/config/environments/production.yaml (L46) |
| CRITICAL | API Key | Potential API Key exposed | deploy/config/servers/brave-search.yaml (L77) |
| CRITICAL | Password | Potential Password exposed | scripts/production_readiness_validator.py (L521) |
| CRITICAL | Token | Potential Token exposed | scripts/migrate_secrets_to_vault.py (L275) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/pydantic/types.py (L1819) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/pydantic/types.py (L1846) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/oauthlib/oauth2/rfc6749/clients/legacy_application.py (L73) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/passlib/tests/utils.py (L3459) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/google/oauth2/challenges.py (L101) |
| CRITICAL | Token | Potential Token exposed | venv_deployment/lib/python3.12/site-packages/google/auth/metrics.py (L30) |
| CRITICAL | Token | Potential Token exposed | venv_deployment/lib/python3.12/site-packages/google/auth/metrics.py (L31) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_deployment/lib/python3.12/site-packages/google/auth/crypt/_python_rsa.py (L38) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_deployment/lib/python3.12/site-packages/google/auth/crypt/_python_rsa.py (L39) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_deployment/lib/python3.12/site-packages/google/auth/transport/_mtls_helper.py (L34) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_deployment/lib/python3.12/site-packages/google/auth/transport/_mtls_helper.py (L36) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/starlette/datastructures.py (L166) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/fsspec/spec.py (L1640) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/cryptography/hazmat/_oid.py (L347) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/cryptography/hazmat/primitives/serialization/ssh.py (L78) |
| CRITICAL | Token | Potential Token exposed | venv_deployment/lib/python3.12/site-packages/huggingface_hub/_login.py (L353) |
| CRITICAL | Token | Potential Token exposed | venv_deployment/lib/python3.12/site-packages/botocore/credentials.py (L2002) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/botocore/data/iam/2010-05-08/examples-1.json (L1430) |
| CRITICAL | API Key | Potential API Key exposed | venv_deployment/lib/python3.12/site-packages/litellm/proxy/_experimental/out/_next/static/chunks/250-891ef1700d4a6403.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_deployment/lib/python3.12/site-packages/litellm/proxy/_experimental/out/_next/static/chunks/app/page-b7119130cbafab63.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_deployment/lib/python3.12/site-packages/litellm/proxy/_experimental/out/_next/static/chunks/app/page-b7119130cbafab63.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_deployment/lib/python3.12/site-packages/litellm/proxy/_experimental/out/_next/static/chunks/app/page-b7119130cbafab63.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_deployment/lib/python3.12/site-packages/litellm/proxy/_experimental/out/_next/static/chunks/app/page-b7119130cbafab63.js (L1) |
| CRITICAL | Token | Potential Token exposed | venv_deployment/lib/python3.12/site-packages/litellm/proxy/_experimental/out/_next/static/chunks/app/page-b7119130cbafab63.js (L1) |
| CRITICAL | API Key | Potential API Key exposed | venv_deployment/lib/python3.12/site-packages/litellm/proxy/spend_tracking/spend_tracking_utils.py (L195) |
| CRITICAL | API Key | Potential API Key exposed | venv_deployment/lib/python3.12/site-packages/litellm/proxy/spend_tracking/spend_tracking_utils.py (L219) |
| CRITICAL | Bearer Token | Potential Bearer Token exposed | venv_deployment/lib/python3.12/site-packages/litellm/proxy/management_endpoints/key_management_endpoints.py (L1214) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/litellm/proxy/swagger/swagger-ui-bundle.js (L2) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/litellm/proxy/swagger/swagger-ui-bundle.js (L2) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/litellm/proxy/swagger/swagger-ui-bundle.js (L2) |
| CRITICAL | Token | Potential Token exposed | venv_deployment/lib/python3.12/site-packages/litellm/proxy/auth/auth_exception_handler.py (L69) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/httpx/_urls.py (L336) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/mcp/shared/_httpx_utils.py (L60) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_deployment/lib/python3.12/site-packages/rsa/pem.py (L88) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_deployment/lib/python3.12/site-packages/rsa/pem.py (L115) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_deployment/lib/python3.12/site-packages/rsa/key.py (L603) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L80) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L215) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L245) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/sqlalchemy/dialects/sqlite/provision.py (L76) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/cx_oracle.py (L198) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/cx_oracle.py (L242) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/oracledb.py (L271) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/oracledb.py (L313) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/oracledb.py (L345) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/provision.py (L193) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/sqlalchemy/dialects/mysql/mysqldb.py (L206) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_deployment/lib/python3.12/site-packages/googleapiclient/discovery_cache/documents/appengine.v1.json (L2435) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_deployment/lib/python3.12/site-packages/googleapiclient/discovery_cache/documents/appengine.v1beta.json (L2659) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_deployment/lib/python3.12/site-packages/googleapiclient/discovery_cache/documents/appengine.v1alpha.json (L1086) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L520) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/pip/_internal/network/auth.py (L462) |
| CRITICAL | Token | Potential Token exposed | venv_deployment/lib/python3.12/site-packages/alembic/script/write_hooks.py (L25) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/kubernetes/config/kube_config_test.py (L89) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/protocols/ftp.py (L2891) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/test/test_ftp.py (L148) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/cred/test/test_strcred.py (L287) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/cred/test/test_strcred.py (L311) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/cred/test/test_strcred.py (L339) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/python/util.py (L320) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/python/util.py (L323) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/python/test/test_fakepwd.py (L200) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/python/test/test_fakepwd.py (L218) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/python/test/test_fakepwd.py (L386) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/python/test/test_fakepwd.py (L408) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/telnet.py (L1096) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L305) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L364) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L429) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L188) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L217) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L272) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L288) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L334) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L397) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/keydata.py (L591) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_default.py (L213) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_ckeygen.py (L438) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_ckeygen.py (L674) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1262) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1265) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1294) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1297) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1325) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1328) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1344) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_keys.py (L1347) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_checkers.py (L72) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_checkers.py (L87) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_checkers.py (L102) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/test/test_userauth.py (L786) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/ssh/keys.py (L395) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/ssh/keys.py (L1511) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/ssh/userauth.py (L526) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/ssh/userauth.py (L725) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/client/default.py (L208) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/conch/scripts/tkconch.py (L513) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/mail/_cred.py (L48) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/mail/smtp.py (L1974) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/mail/test/test_smtp.py (L1805) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/words/test/test_irc.py (L2235) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/words/test/test_irc.py (L2256) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/words/test/test_ircsupport.py (L74) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/words/test/test_jabberclient.py (L104) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/words/test/test_jabbersasl.py (L243) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/words/test/test_jabbersasl.py (L253) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/words/test/test_jabbersasl.py (L264) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/words/test/test_jabbersasl.py (L275) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/words/test/test_jabbersaslmechanisms.py (L145) |
| CRITICAL | Password | Potential Password exposed | venv_deployment/lib/python3.12/site-packages/twisted/words/test/test_jabbercomponent.py (L32) |
| CRITICAL | Password | Potential Password exposed | venv_mcp_main/lib/python3.12/site-packages/pydantic/types.py (L1819) |
| CRITICAL | Password | Potential Password exposed | venv_mcp_main/lib/python3.12/site-packages/pydantic/types.py (L1846) |
| CRITICAL | Password | Potential Password exposed | venv_mcp_main/lib/python3.12/site-packages/starlette/datastructures.py (L166) |
| CRITICAL | Password | Potential Password exposed | venv_mcp_main/lib/python3.12/site-packages/httpx/_urls.py (L336) |
| CRITICAL | Password | Potential Password exposed | venv_mcp_main/lib/python3.12/site-packages/mcp/shared/_httpx_utils.py (L60) |
| CRITICAL | Password | Potential Password exposed | venv_mcp_main/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L478) |
| CRITICAL | Password | Potential Password exposed | venv_mcp_main/lib/python3.12/site-packages/pip/_internal/network/auth.py (L467) |
| CRITICAL | Password | Potential Password exposed | monitoring/alertmanager.yml (L98) |
| CRITICAL | Password | Potential Password exposed | monitoring/alertmanager.yml (L131) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109198) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109218) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109238) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109258) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109278) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109298) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109318) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109338) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109358) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109378) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109398) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109418) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109438) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109458) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109478) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109498) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109518) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109538) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109558) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109578) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109598) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109618) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109638) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109658) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109678) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109698) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109718) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109738) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109758) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109778) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109798) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109818) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109838) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109858) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109878) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109898) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109918) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109938) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109958) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109978) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L109998) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110018) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110038) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110058) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110078) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110098) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110159) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110179) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110199) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110246) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110298) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110354) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110409) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110459) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110514) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110534) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110694) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110714) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110738) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110820) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110840) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110860) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110880) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110900) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110955) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110975) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L110995) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L122963) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L139011) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L139031) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L139071) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L139091) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L139151) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L140291) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L140891) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L141422) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L141462) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L141642) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L141662) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L141682) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L141702) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L141722) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L141742) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L141762) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L141782) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L163434) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L171762) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L171782) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L173091) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L173313) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L173333) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L175456) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L178243) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L180178) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L180198) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L222578) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L222738) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L225413) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L225433) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L225473) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L225501) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L225521) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L232659) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L233099) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L233140) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L247319) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L247339) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268181) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268201) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268221) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268268) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268320) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268376) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268431) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268481) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268536) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268556) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268716) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268736) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268760) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268842) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268862) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268882) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268902) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268922) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268977) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L268997) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L269017) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L294099) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L294119) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L294159) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L294179) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L294239) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L295379) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L295959) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L296490) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L296530) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L296710) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L296730) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L296750) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L296770) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L296790) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L296810) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L296830) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L296850) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L317871) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L326199) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L326219) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L327528) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L327750) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L327770) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L329894) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L332499) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L376995) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L377155) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L379830) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L379850) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L379890) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L379918) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L379938) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L386469) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L386909) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L386950) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L401129) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L401149) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450617) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450624) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450631) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450638) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450645) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450652) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450659) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450666) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450673) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450680) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450687) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450694) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450701) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450708) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450715) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450722) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450729) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450736) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450743) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450750) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450757) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450764) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450771) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450778) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450785) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450792) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450799) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450806) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450813) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450820) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450827) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450834) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450841) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450848) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450855) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450862) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450869) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450876) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450883) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450890) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450897) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450904) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450911) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450918) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450925) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450932) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450939) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450946) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450960) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450967) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450974) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450981) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450988) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L450995) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451002) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451009) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451044) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451051) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451058) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451065) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451072) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451079) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451086) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451093) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451100) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451107) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451121) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451128) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451135) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451142) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451149) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451156) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451163) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451170) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451177) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451184) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451191) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451198) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451205) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451212) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451219) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451226) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451233) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451240) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451247) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451254) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451261) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451268) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451275) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451282) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451289) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451296) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451303) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451310) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451317) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451324) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451331) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451338) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451345) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451359) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451366) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451373) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451380) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451387) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451394) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451401) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451436) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451443) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451450) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451457) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451464) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451471) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451478) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451485) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451492) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/comprehensive_security_analysis_report.json (L451499) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109195) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109215) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109235) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109255) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109275) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109295) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109315) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109335) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109355) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109375) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109395) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109415) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109435) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109455) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109475) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109495) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109515) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109535) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109555) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109575) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109595) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109615) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109635) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109655) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109675) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109695) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109715) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109735) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109755) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109775) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109795) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109815) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109835) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109855) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109875) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109895) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109915) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109935) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109955) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109975) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L109995) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110015) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110035) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110055) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110075) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110095) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110156) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110176) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110196) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110243) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110295) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110351) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110406) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110456) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110511) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110531) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110691) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110711) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110735) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110817) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110837) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110857) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110877) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110897) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110952) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110972) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L110992) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L122960) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L139008) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L139028) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L139068) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L139088) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L139148) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L140288) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L140888) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L141419) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L141459) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L141639) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L141659) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L141679) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L141699) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L141719) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L141739) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L141759) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L141779) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L163431) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L171759) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L171779) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L173088) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L173310) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L173330) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L175453) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L178240) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L180175) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L180195) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L222575) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L222735) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L225410) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L225430) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L225470) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L225498) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L225518) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L232656) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L233096) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L233137) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L247316) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L247336) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268178) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268198) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268218) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268265) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268317) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268373) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268428) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268478) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268533) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268553) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268713) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268733) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268757) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268839) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268859) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268879) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268899) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268919) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268974) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L268994) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L269014) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L294096) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L294116) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L294156) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L294176) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L294236) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L295376) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L295956) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L296487) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L296527) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L296707) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L296727) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L296747) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L296767) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L296787) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L296807) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L296827) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L296847) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L317868) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L326196) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L326216) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L327525) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L327747) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L327767) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L329891) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L332496) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L376992) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L377152) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L379827) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L379847) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L379887) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L379915) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L379935) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L386466) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L386906) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L386947) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L401126) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/bandit_security_report.json (L401146) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/pydantic/types.py (L1695) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/opentelemetry/sdk/environment_variables.py (L238) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/face/testing.py (L62) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/cyclonedx/model/crypto.py (L712) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/cryptography/hazmat/_oid.py (L347) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/cryptography/hazmat/primitives/serialization/ssh.py (L78) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/httpx/_urls.py (L336) |
| CRITICAL | Token | Potential Token exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/boolean/boolean.py (L240) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L23) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L159) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L164) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L217) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L222) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L520) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/pip/_internal/network/auth.py (L462) |
| CRITICAL | Token | Potential Token exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/nltk/tokenize/treebank.py (L249) |
| CRITICAL | Token | Potential Token exposed | mcp_learning_system/security_venv/lib/python3.12/site-packages/nltk/sem/logic.py (L585) |
| CRITICAL | AWS Access Key | Potential AWS Access Key exposed | mcp_learning_system/ml_test_env/lib/python3.12/site-packages/PIL/ImageFont.py (L1274) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/ml_test_env/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L520) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/ml_test_env/lib/python3.12/site-packages/pip/_internal/network/auth.py (L462) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/python_learning/test_env/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L520) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/python_learning/test_env/lib/python3.12/site-packages/pip/_internal/network/auth.py (L462) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/pydantic/types.py (L1695) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/opentelemetry/sdk/environment_variables.py (L238) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/face/testing.py (L62) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/cyclonedx/model/crypto.py (L712) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/cryptography/hazmat/_oid.py (L347) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/cryptography/hazmat/primitives/serialization/ssh.py (L78) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/httpx/_urls.py (L336) |
| CRITICAL | Token | Potential Token exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/boolean/boolean.py (L240) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L23) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L159) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L164) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L217) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/bandit/plugins/general_hardcoded_password.py (L222) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L478) |
| CRITICAL | Password | Potential Password exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/pip/_internal/network/auth.py (L467) |
| CRITICAL | Token | Potential Token exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/nltk/tokenize/treebank.py (L249) |
| CRITICAL | Token | Potential Token exposed | mcp_learning_system/rust_core/security_venv/lib/python3.12/site-packages/nltk/sem/logic.py (L585) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/pydantic/types.py (L1819) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/pydantic/types.py (L1846) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/starlette/datastructures.py (L166) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/cryptography/hazmat/_oid.py (L347) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_mcp/lib/python3.12/site-packages/cryptography/hazmat/primitives/serialization/ssh.py (L78) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/httpx/_urls.py (L336) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/mcp/shared/_httpx_utils.py (L60) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L80) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L215) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L245) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/sqlalchemy/dialects/sqlite/provision.py (L76) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/cx_oracle.py (L198) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/cx_oracle.py (L242) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/oracledb.py (L271) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/oracledb.py (L313) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/oracledb.py (L345) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/provision.py (L193) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/sqlalchemy/dialects/mysql/mysqldb.py (L206) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/paramiko/transport.py (L1731) |
| CRITICAL | Token | Potential Token exposed | venv_mcp/lib/python3.12/site-packages/paramiko/common.py (L166) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L478) |
| CRITICAL | Password | Potential Password exposed | venv_mcp/lib/python3.12/site-packages/pip/_internal/network/auth.py (L467) |
| CRITICAL | Token | Potential Token exposed | venv_mcp/lib/python3.12/site-packages/alembic/script/write_hooks.py (L25) |
| CRITICAL | Password | Potential Password exposed | mcp_servers/dist/servers/optimized-example-server.js (L548) |
| CRITICAL | Password | Potential Password exposed | mcp_servers/test_venv/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L520) |
| CRITICAL | Password | Potential Password exposed | mcp_servers/test_venv/lib/python3.12/site-packages/pip/_internal/network/auth.py (L462) |
| CRITICAL | Password | Potential Password exposed | mcp_servers/src/servers/optimized-example-server.ts (L652) |
| CRITICAL | Password | Potential Password exposed | venv_production_mcp/lib/python3.12/site-packages/pydantic/types.py (L1819) |
| CRITICAL | Password | Potential Password exposed | venv_production_mcp/lib/python3.12/site-packages/pydantic/types.py (L1846) |
| CRITICAL | Password | Potential Password exposed | venv_production_mcp/lib/python3.12/site-packages/oauthlib/oauth2/rfc6749/clients/legacy_application.py (L73) |
| CRITICAL | Password | Potential Password exposed | venv_production_mcp/lib/python3.12/site-packages/google/oauth2/challenges.py (L101) |
| CRITICAL | Token | Potential Token exposed | venv_production_mcp/lib/python3.12/site-packages/google/auth/metrics.py (L30) |
| CRITICAL | Token | Potential Token exposed | venv_production_mcp/lib/python3.12/site-packages/google/auth/metrics.py (L31) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_production_mcp/lib/python3.12/site-packages/google/auth/crypt/_python_rsa.py (L38) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_production_mcp/lib/python3.12/site-packages/google/auth/crypt/_python_rsa.py (L39) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_production_mcp/lib/python3.12/site-packages/google/auth/transport/_mtls_helper.py (L34) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_production_mcp/lib/python3.12/site-packages/google/auth/transport/_mtls_helper.py (L36) |
| CRITICAL | Password | Potential Password exposed | venv_production_mcp/lib/python3.12/site-packages/starlette/datastructures.py (L166) |
| CRITICAL | Password | Potential Password exposed | venv_production_mcp/lib/python3.12/site-packages/fsspec/spec.py (L1640) |
| CRITICAL | Token | Potential Token exposed | venv_production_mcp/lib/python3.12/site-packages/huggingface_hub/_login.py (L353) |
| CRITICAL | Password | Potential Password exposed | venv_production_mcp/lib/python3.12/site-packages/httpx/_urls.py (L336) |
| CRITICAL | Token | Potential Token exposed | venv_production_mcp/lib/python3.12/site-packages/transformers/testing_utils.py (L200) |
| CRITICAL | Token | Potential Token exposed | venv_production_mcp/lib/python3.12/site-packages/transformers/models/idefics/processing_idefics.py (L387) |
| CRITICAL | Token | Potential Token exposed | venv_production_mcp/lib/python3.12/site-packages/transformers/models/cohere/tokenization_cohere_fast.py (L121) |
| CRITICAL | Token | Potential Token exposed | venv_production_mcp/lib/python3.12/site-packages/transformers/models/llama4/processing_llama4.py (L113) |
| CRITICAL | Token | Potential Token exposed | venv_production_mcp/lib/python3.12/site-packages/transformers/models/llama4/processing_llama4.py (L114) |
| CRITICAL | Token | Potential Token exposed | venv_production_mcp/lib/python3.12/site-packages/transformers/models/kosmos2/processing_kosmos2.py (L108) |
| CRITICAL | Password | Potential Password exposed | venv_production_mcp/lib/python3.12/site-packages/mcp/shared/_httpx_utils.py (L60) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_production_mcp/lib/python3.12/site-packages/rsa/pem.py (L88) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_production_mcp/lib/python3.12/site-packages/rsa/pem.py (L115) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_production_mcp/lib/python3.12/site-packages/rsa/key.py (L603) |
| CRITICAL | Token | Potential Token exposed | venv_production_mcp/lib/python3.12/site-packages/grpc/_server.py (L63) |
| CRITICAL | Token | Potential Token exposed | venv_production_mcp/lib/python3.12/site-packages/grpc/_server.py (L64) |
| CRITICAL | Token | Potential Token exposed | venv_production_mcp/lib/python3.12/site-packages/grpc/_server.py (L70) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_production_mcp/lib/python3.12/site-packages/googleapiclient/discovery_cache/documents/appengine.v1.json (L2435) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_production_mcp/lib/python3.12/site-packages/googleapiclient/discovery_cache/documents/appengine.v1beta.json (L2659) |
| CRITICAL | Private Key | Potential Private Key exposed | venv_production_mcp/lib/python3.12/site-packages/googleapiclient/discovery_cache/documents/appengine.v1alpha.json (L1086) |
| CRITICAL | Password | Potential Password exposed | venv_production_mcp/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L478) |
| CRITICAL | Password | Potential Password exposed | venv_production_mcp/lib/python3.12/site-packages/pip/_internal/network/auth.py (L467) |
| CRITICAL | Password | Potential Password exposed | src/core/secrets_rotation_config.py (L28) |
| CRITICAL | Password | Potential Password exposed | src/monitoring/prometheus.yml (L107) |
| CRITICAL | Token | Potential Token exposed | src/auth/token_revocation.py (L110) |
| CRITICAL | Password | Potential Password exposed | test_environments/monitoring/alert_manager.py (L1107) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/pydantic/types.py (L1819) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/pydantic/types.py (L1846) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/passlib/tests/utils.py (L3459) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/starlette/datastructures.py (L166) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/cryptography/hazmat/_oid.py (L347) |
| CRITICAL | SSH Private Key | Potential SSH Private Key exposed | venv_test/lib/python3.12/site-packages/cryptography/hazmat/primitives/serialization/ssh.py (L78) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/httpx/_urls.py (L336) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L80) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L215) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/sqlalchemy/dialects/mssql/pyodbc.py (L245) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/sqlalchemy/dialects/sqlite/provision.py (L76) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/cx_oracle.py (L198) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/cx_oracle.py (L242) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/oracledb.py (L271) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/oracledb.py (L313) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/oracledb.py (L345) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/sqlalchemy/dialects/oracle/provision.py (L193) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/sqlalchemy/dialects/mysql/mysqldb.py (L206) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L520) |
| CRITICAL | Password | Potential Password exposed | venv_test/lib/python3.12/site-packages/pip/_internal/network/auth.py (L462) |
| CRITICAL | Token | Potential Token exposed | venv_test/lib/python3.12/site-packages/alembic/script/write_hooks.py (L25) |
| CRITICAL | Password | Potential Password exposed | rust_core/security_audit_env/mcp_learning_system/security_venv/lib/python3.12/site-packages/pip/_internal/utils/misc.py (L520) |
| CRITICAL | Password | Potential Password exposed | rust_core/security_audit_env/mcp_learning_system/security_venv/lib/python3.12/site-packages/pip/_internal/network/auth.py (L462) |

### Kubernetes Security

| Severity | Type | Finding | File |
|----------|------|---------|------|
| HIGH | Missing Security Context | No security context defined | k8s/mcp-hpa.yaml |
| HIGH | Host Network | Pod using host network | k8s/monitoring.yaml |
| CRITICAL | Docker Socket | Docker socket mounted in container | docker-compose.mcp-production.yml |
| CRITICAL | Privileged Container | Container running with privileged flag | code-base-crawler/code-base-crawler/monitoring/docker-compose.monitoring-full.yml |
| CRITICAL | Privileged Container | Container running with privileged flag | code-base-crawler/code-base-crawler/monitoring/docker-compose.monitoring.yml |
| HIGH | Missing Security Context | No security context defined | .github/workflows/deployment.yml |
| CRITICAL | Docker Socket | Docker socket mounted in container | infrastructure/logging/filebeat.yml |
| CRITICAL | Docker Socket | Docker socket mounted in container | infrastructure/logging/docker-compose.logging.yml |
| CRITICAL | Docker Socket | Docker socket mounted in container | containers/development/docker-compose.dev.yml |
| CRITICAL | Docker Socket | Docker socket mounted in container | containers/networking/traefik.yml |

### Container Security

| Severity | Type | Finding | File |
|----------|------|---------|------|
| HIGH | Root User | Container may run as root (no USER directive) | Dockerfile.tracing |
| HIGH | Root User | Container may run as root (no USER directive) | Dockerfile.rust-build |
| HIGH | Root User | Container may run as root (no USER directive) | code-base-crawler/code-base-crawler/Dockerfile.simple |
| HIGH | Root User | Container may run as root (no USER directive) | code-base-crawler/code-base-crawler/tests/Dockerfile.test |
| HIGH | Root User | Container may run as root (no USER directive) | code-base-crawler/code-base-crawler/test_results/integration_20250608_100235/Dockerfile |

### Rbac Policies

| Severity | Type | Finding | File |
|----------|------|---------|------|
| HIGH | Overly Permissive RBAC | RBAC rule with wildcard permissions | k8s/rbac.yaml |
| HIGH | Overly Permissive RBAC | RBAC rule with wildcard permissions | k8s/production/services.yaml |

### Dependencies

| Severity | Type | Finding | File |
|----------|------|---------|------|
| HIGH | Vulnerable Dependency | Potentially vulnerable package: requests | requirements.txt |

## Recommendations

1. **Immediate Actions**:
   - Fix all CRITICAL issues immediately
   - Rotate any exposed credentials
   - Implement proper secret management

2. **Short-term Actions**:
   - Address HIGH severity issues
   - Implement missing security controls
   - Update vulnerable dependencies

3. **Long-term Actions**:
   - Regular security audits
   - Automated security scanning in CI/CD
   - Security training for development team

## Compliance Status

Based on the security validation results, the system demonstrates:
- **SOC2 Readiness**: Partial (needs completion)
- **GDPR Compliance**: Partial (privacy controls needed)
- **PCI-DSS Readiness**: Not Ready (encryption required)

---

**Security Validation Framework Version**: 1.0.0

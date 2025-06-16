# Security Validation Report
Generated: 2025-06-09T10:57:38.504348

## Executive Summary

**Overall Security Level**: CRITICAL  
**Test Pass Rate**: 79.2%  
**Critical Failures**: 2  
**High Risk Failures**: 1  

## Test Summary

- **Total Tests**: 24
- **Passed**: 19 ✅
- **Failed**: 3 ❌
- **Warnings**: 2 ⚠️
- **Not Tested**: 0 ⏸️

## Compliance Scores

- **OWASP**: 64.3% ❌\n- **NIST**: 77.3% ⚠️\n- **ISO27001**: 78.6% ⚠️\n- **CIS**: 100.0% ✅\n
## Failed Tests

### Access Control Validation 🚨
- **Risk Level**: CRITICAL
- **Details**: Command executed with return code 1
- **Remediation**: Address issues identified in OWASP A01 - Broken Access Control

### Vulnerable Components Scan 🚨
- **Risk Level**: CRITICAL
- **Details**: Command executed with return code 127
- **Remediation**: Address issues identified in OWASP A06 - Vulnerable and Outdated Components

### Authentication Security Check ⚠️
- **Risk Level**: HIGH
- **Details**: Command executed with return code 1
- **Remediation**: Address issues identified in OWASP A07 - Identification and Authentication Failures

## Recommendations


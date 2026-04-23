## Vulnerability Report: Charging Network Spoofing / Session Abuse (CTEK Chargeportal)

### Severity
**Critical overall (max CVSS v3.1: 9.4)**

### Reported by
**Khaled Sarieddine ([LinkedIn](https://www.linkedin.com/in/khaled-salah-sarieddine/))**
**Mohammad Ali Sayed ([LinkedIn](https://www.linkedin.com/in/mohammadali-sayed/))**

### Date Reported
**05/10/2025**

### Status
**Closed and Remediated**

### Published by CISA
**03/19/2026**

### Summary
A critical set of vulnerabilities has been identified in CTEK Chargeportal, as documented in CISA advisory ICSA-26-078-06. These issues enable unauthenticated station impersonation, session hijacking, brute-force authentication attacks, and credential exposure via public mapping platforms.

### Description
The advisory maps to four vulnerabilities:
- **CVE-2026-25192 (CVSS 9.4, CWE-306)**: WebSocket endpoints lack proper authentication mechanisms, allowing attackers to impersonate legitimate charging stations and gain unauthorized administrative control over the backend.
- **CVE-2026-31904 (CVSS 7.5, CWE-307)**: Absence of rate limiting on the WebSocket API enables denial-of-service attacks and brute-force authentication attempts.
- **CVE-2026-27649 (CVSS 7.3, CWE-613)**: Predictable session identifiers allow session hijacking, enabling unauthorized connections to displace legitimate stations and gain unauthorized access.
- **CVE-2026-28204 (CVSS 6.5, CWE-522)**: Station authentication identifiers are publicly accessible via web-based mapping platforms.

Together, these weaknesses can be chained to impersonate charging endpoints, maintain unauthorized backend presence, and disrupt or manipulate charging-session state.

### Impact
The exploitation of this vulnerability can lead to the following risks:
- **Unauthorized backend access**: Attackers can connect and issue commands without valid credentials (CVE-2026-25192).
- **Service disruption and brute-force exposure**: Repeated authentication traffic can degrade availability and increase credential attack risk (CVE-2026-31904).
- **Session integrity loss**: Predictable session identifiers can displace legitimate stations and corrupt session state (CVE-2026-27649).
- **Credential exposure**: Publicly available station identifiers increase targeted attack feasibility (CVE-2026-28204).

### Steps to Reproduce
1. Identify a target CTEK Chargeportal WebSocket endpoint using publicly accessible mapping platforms that expose station authentication identifiers.
2. Connect to the OCPP WebSocket endpoint using the discovered station identifier, bypassing authentication controls (CVE-2026-25192, CVE-2026-28204).
3. Issue OCPP protocol commands to the backend to simulate a legitimate charger, manipulate backend data, or disrupt charging sessions.
4. Observe that no rate limiting prevents repeated connection attempts, enabling brute-force or DoS scenarios (CVE-2026-31904).
5. Connect using a known or predicted session identifier to displace a legitimate station's active session (CVE-2026-27649).

All steps are performed in a controlled test environment with authorization.

### Root Cause
- Missing mandatory authentication enforcement for WebSocket connection paths.
- Missing or weak throttling/lockout controls for authentication attempts.
- Predictable session identifiers with insufficient lifecycle and uniqueness controls.
- Public exposure of station authentication identifiers via mapping APIs.

### Recommendations
To mitigate the risks associated with this vulnerability, the following actions should be taken:
1. **Proper Authentication Enforcement**:
   - Require strong mutual authentication for charging station to backend communications.
   - Block unauthenticated WebSocket upgrades by default.
2. **Rate Limiting and Brute Force Protection**:
   - Apply per-source rate limits on authentication endpoints.
   - Enforce lockout/backoff after failed authentication thresholds.
3. **Session Management Hardening**:
   - Enforce unique, unpredictable session identifiers per station connection.
   - Implement short session lifetimes with immediate revocation on re-authentication.
4. **Credential Protection**:
   - Remove or obfuscate station authentication identifiers from public-facing mapping platforms.
5. **Network Segmentation and Access Controls**:
   - Restrict charger-management interfaces to trusted networks/VPN.
   - Segment OT charging networks from corporate IT and external zones.

### Risk Assessment
Given that this vulnerability set includes an unauthenticated access path (CVSS 9.4) and additional high-severity weaknesses, the overall risk is considered high to critical. Exploitation can lead to unauthorized control of charging workflows, service disruption, and significant operational and reputational impact. Note that CTEK is sunsetting the Chargeportal product in April 2026; operators should urgently migrate to a supported platform.

### Reference
- [CISA ICS Advisory ICSA-26-078-06](https://www.cisa.gov/news-events/ics-advisories/icsa-26-078-06)
- [CVE-2026-25192](https://www.cve.org/CVERecord?id=CVE-2026-25192)
- [CVE-2026-31904](https://www.cve.org/CVERecord?id=CVE-2026-31904)
- [CVE-2026-27649](https://www.cve.org/CVERecord?id=CVE-2026-27649)
- [CVE-2026-28204](https://www.cve.org/CVERecord?id=CVE-2026-28204)

### Vendor of Product
- CTEK (Sweden) - Chargeportal OCPP backend platform for EV charging infrastructure

### Affected Product Code Base
- CTEK Chargeportal: vers:all/*

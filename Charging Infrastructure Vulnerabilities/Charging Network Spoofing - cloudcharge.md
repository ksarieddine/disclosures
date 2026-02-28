## Vulnerability Report: Charging Network Spoofing / Session Abuse (CloudCharge)

### Severity
**Critical overall (max CVSS v3.1: 9.4)**

### Reported by
**Khaled Sarieddine ([LinkedIn](https://www.linkedin.com/in/khaled-salah-sarieddine/))**
**Mohammad Ali Sayed ([LinkedIn](https://www.linkedin.com/in/mohammadali-sayed/))**

### Date Reported
**10/05/2025**

### Status
**Closed and Remediated**

### Published by CISA
**02/26/2026**

### Summary
A critical set of vulnerabilities has been identified in the CloudCharge (cloudcharge.se) EV charging management platform, as documented in CISA advisory ICSA-26-057-03. These issues enable unauthenticated station impersonation, session hijacking, brute-force authentication attacks, and credential exposure via public mapping platforms.

### Description
The advisory maps to four vulnerabilities:
- **CVE-2026-20781 (CVSS 9.4, CWE-306)**: WebSocket endpoints lack authentication, allowing attackers to impersonate charging stations and issue unauthorized OCPP commands to the backend.
- **CVE-2026-25114 (CVSS 7.5, CWE-307)**: Missing rate limiting on the WebSocket API enables denial-of-service attacks and brute-force authentication attempts.
- **CVE-2026-27652 (CVSS 7.3, CWE-613)**: Predictable session identifiers allow multiple connections to use the same session ID, enabling hijacking and displacement of legitimate stations.
- **CVE-2026-20733 (CVSS 6.5, CWE-522)**: Charging station authentication identifiers are publicly accessible via web-based mapping platforms.

Together, these weaknesses can be chained to impersonate charging endpoints, maintain unauthorized backend presence, and disrupt or manipulate charging-session state.

### Impact
The exploitation of this vulnerability can lead to the following risks:
- **Unauthorized backend access**: Attackers connect and issue commands without valid credentials (CVE-2026-20781).
- **Service disruption and brute-force exposure**: Repeated authentication traffic degrades availability and increases credential attack risk (CVE-2026-25114).
- **Session integrity loss**: Concurrent reuse of session IDs causes data inconsistency and possible station displacement (CVE-2026-27652).
- **Credential exposure**: Station IDs discoverable via public mapping enable targeted attacks (CVE-2026-20733).

### Root Cause
- Missing mandatory authentication enforcement for WebSocket connection paths.
- Missing or weak throttling/lockout controls for authentication attempts.
- Predictable/reusable session identifiers with weak lifecycle controls.
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
Given that this vulnerability set includes an unauthenticated access path (CVSS 9.4) and additional high-severity weaknesses, the overall risk is considered high to critical. Exploitation can lead to unauthorized control of charging workflows, service disruption, and significant operational and reputational impact.

### Reference
- [CISA ICS Advisory ICSA-26-057-03](https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-03)
- [CVE-2026-20781](https://www.cve.org/CVERecord?id=CVE-2026-20781)
- [CVE-2026-25114](https://www.cve.org/CVERecord?id=CVE-2026-25114)
- [CVE-2026-27652](https://www.cve.org/CVERecord?id=CVE-2026-27652)
- [CVE-2026-20733](https://www.cve.org/CVERecord?id=CVE-2026-20733)

### Vendor of Product
- CloudCharge (Sweden) – EV charging management platform (cloudcharge.se)

### Affected Product Code Base
- CloudCharge cloudcharge.se – All versions

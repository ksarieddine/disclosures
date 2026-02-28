## Vulnerability Report: Charging Network Spoofing / Session Abuse (Mobility46)

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
A critical set of vulnerabilities has been identified in the Mobility46 (mobility46.se) EV charging management platform, as documented in CISA advisory ICSA-26-057-08. These issues enable unauthenticated station impersonation, session hijacking, brute-force authentication attacks, and credential exposure via public mapping platforms.

### Description
The advisory maps to four vulnerabilities:
- **CVE-2026-27028 (CVSS 9.4, CWE-306)**: WebSocket endpoints lack authentication, enabling unauthorized station impersonation and data manipulation.
- **CVE-2026-26305 (CVSS 7.5, CWE-307)**: Missing rate limiting on authentication requests allows DoS and brute-force attacks.
- **CVE-2026-27647 (CVSS 7.3, CWE-613)**: Predictable session identifiers enable session hijacking and unauthorized backend access.
- **CVE-2026-22878 (CVSS 6.5, CWE-522)**: Charging station authentication credentials are publicly accessible via web-based mapping platforms.

Together, these weaknesses can enable attackers to gain unauthorized administrative control over vulnerable charging stations or disrupt charging services through denial-of-service attacks.

### Impact
The exploitation of this vulnerability can lead to the following risks:
- **Unauthorized backend access**: Attackers impersonate stations and manipulate data without valid credentials (CVE-2026-27028).
- **Service disruption and brute-force exposure**: Missing rate limits enable DoS attacks and credential brute-forcing (CVE-2026-26305).
- **Session integrity loss**: Predictable session IDs allow hijacking and unauthorized backend presence (CVE-2026-27647).
- **Credential exposure**: Station credentials discoverable via public mapping enable targeted exploitation (CVE-2026-22878).

### Root Cause
- Missing mandatory authentication enforcement for WebSocket connection paths.
- Missing or weak throttling/lockout controls for authentication attempts.
- Predictable session identifiers with insufficient lifecycle controls.
- Public exposure of station authentication credentials via mapping APIs.

### Recommendations
To mitigate the risks associated with this vulnerability, the following actions should be taken:
1. **Proper Authentication Enforcement**:
   - Require strong mutual authentication for charging station to backend communications.
   - Block unauthenticated WebSocket upgrades by default.
2. **Rate Limiting and Brute Force Protection**:
   - Apply per-source rate limits on authentication endpoints.
   - Enforce lockout/backoff after failed authentication thresholds.
3. **Session Management Hardening**:
   - Enforce unique, cryptographically random session identifiers per station connection.
   - Implement short session lifetimes with immediate revocation on re-authentication.
4. **Credential Protection**:
   - Remove or obfuscate station authentication credentials from public-facing mapping platforms.
5. **Network Segmentation and Access Controls**:
   - Restrict charger-management interfaces to trusted networks/VPN.
   - Implement defense-in-depth cybersecurity strategies and monitor for suspicious activity.

### Risk Assessment
Given that this vulnerability set includes an unauthenticated access path (CVSS 9.4) and additional high-severity weaknesses, the overall risk is considered high to critical. Exploitation can lead to unauthorized administrative control of charging stations, large-scale denial-of-service conditions, and significant operational and reputational impact.

### Reference
- [CISA ICS Advisory ICSA-26-057-08](https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-08)
- [CVE-2026-27028](https://www.cve.org/CVERecord?id=CVE-2026-27028)
- [CVE-2026-26305](https://www.cve.org/CVERecord?id=CVE-2026-26305)
- [CVE-2026-27647](https://www.cve.org/CVERecord?id=CVE-2026-27647)
- [CVE-2026-22878](https://www.cve.org/CVERecord?id=CVE-2026-22878)

### Vendor of Product
- Mobility46 (Sweden) – EV charging management platform (mobility46.se)

### Affected Product Code Base
- Mobility46 mobility46.se – All versions

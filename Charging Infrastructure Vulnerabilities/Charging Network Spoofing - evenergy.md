## Vulnerability Report: Charging Network Spoofing / Session Abuse (EV Energy)

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
A critical set of vulnerabilities has been identified in the EV Energy (ev.energy) EV charging management platform, as documented in CISA advisory ICSA-26-057-07. These issues enable unauthenticated station impersonation, session hijacking, brute-force authentication attacks, and credential exposure via public mapping platforms.

### Description
The advisory maps to four vulnerabilities:
- **CVE-2026-27772 (CVSS 9.4, CWE-306)**: WebSocket endpoints permit unauthenticated access, enabling attackers to impersonate charging stations and manipulate backend data.
- **CVE-2026-24445 (CVSS 7.5, CWE-307)**: The API lacks restrictions on the number of authentication requests, enabling denial-of-service and brute-force attack vectors.
- **CVE-2026-26290 (CVSS 7.3, CWE-613)**: Multiple connections can use identical session identifiers, permitting session hijacking or shadowing scenarios.
- **CVE-2026-25774 (CVSS 6.5, CWE-522)**: Station authentication credentials are publicly accessible via web-based mapping platforms.

Together, these weaknesses can enable attackers to obtain unauthorized administrative control over vulnerable charging stations or disrupt charging services.

### Impact
The exploitation of this vulnerability can lead to the following risks:
- **Unauthorized backend access**: Attackers impersonate stations and manipulate backend data without valid credentials (CVE-2026-27772).
- **Service disruption and brute-force exposure**: Unrestricted authentication requests enable DoS and credential attacks (CVE-2026-24445).
- **Session integrity loss**: Shared session identifiers allow session hijacking and shadowing (CVE-2026-26290).
- **Credential exposure**: Station credentials discoverable via public mapping enable targeted exploitation (CVE-2026-25774).

### Root Cause
- Missing mandatory authentication enforcement for WebSocket connection paths.
- Missing or weak throttling/lockout controls for authentication attempts.
- Reusable/shared session identifiers with weak lifecycle controls.
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
   - Reject duplicate session connections immediately upon detection.
4. **Credential Protection**:
   - Remove or obfuscate station authentication credentials from public-facing mapping platforms.
5. **Network Segmentation and Access Controls**:
   - Restrict charger-management interfaces to trusted networks/VPN.
   - Isolate OT charging networks behind firewalls from business IT and external zones.

### Risk Assessment
Given that this vulnerability set includes an unauthenticated access path (CVSS 9.4) and additional high-severity weaknesses, the overall risk is considered high to critical. Exploitation can lead to unauthorized administrative control of charging stations, service disruption through session shadowing, and significant operational and reputational impact.

### Reference
- [CISA ICS Advisory ICSA-26-057-07](https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-07)
- [CVE-2026-27772](https://www.cve.org/CVERecord?id=CVE-2026-27772)
- [CVE-2026-24445](https://www.cve.org/CVERecord?id=CVE-2026-24445)
- [CVE-2026-26290](https://www.cve.org/CVERecord?id=CVE-2026-26290)
- [CVE-2026-25774](https://www.cve.org/CVERecord?id=CVE-2026-25774)

### Vendor of Product
- EV Energy (United Kingdom) – EV charging management platform (ev.energy)

### Affected Product Code Base
- EV Energy ev.energy – All versions

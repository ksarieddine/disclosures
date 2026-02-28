## Vulnerability Report: Charging Network Spoofing / Session Abuse (Chargemap)

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
A critical set of vulnerabilities has been identified in the Chargemap (chargemap.com) EV charging management platform, as documented in CISA advisory ICSA-26-057-05. These issues enable unauthenticated station impersonation, session hijacking, brute-force authentication attacks, and credential exposure via public mapping platforms.

### Description
The advisory maps to four vulnerabilities:
- **CVE-2026-25851 (CVSS 9.4, CWE-306)**: WebSocket endpoints lack proper authentication, enabling attackers to impersonate charging stations and execute unauthorized OCPP commands against the backend.
- **CVE-2026-20792 (CVSS 7.5, CWE-307)**: The WebSocket API lacks restrictions on authentication request volume, facilitating denial-of-service and brute-force attacks.
- **CVE-2026-25711 (CVSS 7.3, CWE-613)**: Multiple endpoints can connect using the same session identifier, enabling session hijacking and service disruption.
- **CVE-2026-20791 (CVSS 6.5, CWE-522)**: Charging station authentication identifiers are publicly accessible via web-based mapping platforms.

Together, these weaknesses can enable attackers to gain unauthorized administrative control over vulnerable charging stations or disrupt charging services.

### Impact
The exploitation of this vulnerability can lead to the following risks:
- **Unauthorized backend access**: Attackers connect and execute unauthorized OCPP commands without valid credentials (CVE-2026-25851).
- **Service disruption and brute-force exposure**: Unrestricted authentication requests enable DoS and credential attacks (CVE-2026-20792).
- **Session integrity loss**: Shared session identifiers allow session hijacking and station displacement (CVE-2026-25711).
- **Credential exposure**: Station identifiers discoverable via public mapping enable targeted exploitation (CVE-2026-20791).

### Root Cause
- Missing mandatory authentication enforcement for WebSocket connection paths.
- Missing or weak throttling/lockout controls for authentication attempts.
- Shared/reusable session identifiers with weak lifecycle controls.
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
   - Reject duplicate session connections and implement immediate revocation on re-authentication.
4. **Credential Protection**:
   - Remove or obfuscate station authentication identifiers from public-facing mapping platforms.
5. **Network Segmentation and Access Controls**:
   - Restrict charger-management interfaces to trusted networks/VPN.
   - Segment OT charging networks from corporate IT and external zones.

### Risk Assessment
Given that this vulnerability set includes an unauthenticated access path (CVSS 9.4) and additional high-severity weaknesses, the overall risk is considered high to critical. Exploitation can lead to unauthorized administrative control of charging stations and widespread service disruption.

### Reference
- [CISA ICS Advisory ICSA-26-057-05](https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-05)
- [CVE-2026-25851](https://www.cve.org/CVERecord?id=CVE-2026-25851)
- [CVE-2026-20792](https://www.cve.org/CVERecord?id=CVE-2026-20792)
- [CVE-2026-25711](https://www.cve.org/CVERecord?id=CVE-2026-25711)
- [CVE-2026-20791](https://www.cve.org/CVERecord?id=CVE-2026-20791)

### Vendor of Product
- Chargemap (France) – EV charging network management platform (chargemap.com)

### Affected Product Code Base
- Chargemap chargemap.com – All versions

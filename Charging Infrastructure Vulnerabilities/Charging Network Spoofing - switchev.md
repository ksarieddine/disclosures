## Vulnerability Report: Charging Network Spoofing / Session Abuse (SWITCH EV)

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
A critical set of vulnerabilities has been identified in the SWITCH EV (swtchenergy.com) EV charging management platform, as documented in CISA advisory ICSA-26-057-06. These issues enable unauthenticated station impersonation, session hijacking, brute-force authentication attacks, and credential exposure via public mapping platforms.

### Description
The advisory maps to four vulnerabilities:
- **CVE-2026-27767 (CVSS 9.4, CWE-306)**: WebSocket endpoints lack authentication, enabling attackers to impersonate charging stations and manipulate backend data.
- **CVE-2026-25113 (CVSS 7.5, CWE-307)**: Missing rate limiting allows attackers to conduct denial-of-service attacks or brute-force authentication attempts.
- **CVE-2026-25778 (CVSS 7.3, CWE-613)**: Predictable session identifiers enable hijacking where the most recent connection displaces the legitimate charging station.
- **CVE-2026-27773 (CVSS 6.5, CWE-522)**: Charging station identifiers are publicly accessible via web-based mapping platforms.

Together, these weaknesses permit attackers to impersonate stations, hijack sessions, suppress legitimate traffic causing widespread service outages, and corrupt charging network data.

### Impact
The exploitation of this vulnerability can lead to the following risks:
- **Unauthorized backend access**: Attackers impersonate stations and manipulate backend data without valid credentials (CVE-2026-27767).
- **Service disruption and brute-force exposure**: Missing rate limits enable DoS attacks and credential brute-forcing (CVE-2026-25113).
- **Session integrity loss**: Predictable session IDs allow the most recent attacker connection to displace legitimate stations (CVE-2026-25778).
- **Credential exposure**: Station identifiers discoverable via public mapping enable targeted exploitation (CVE-2026-27773).

### Root Cause
- Missing mandatory authentication enforcement for WebSocket connection paths.
- Missing or weak throttling/lockout controls for authentication attempts.
- Predictable session identifiers enabling displacement of legitimate connections.
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
   - Enforce unique, cryptographically random session identifiers per station connection.
   - Implement short session lifetimes with immediate revocation on re-authentication.
4. **Credential Protection**:
   - Remove or obfuscate station authentication identifiers from public-facing mapping platforms.
5. **Network Segmentation and Access Controls**:
   - Restrict charger-management interfaces to trusted networks/VPN.
   - Implement defense-in-depth cybersecurity strategies across all network layers.

### Risk Assessment
Given that this vulnerability set includes an unauthenticated access path (CVSS 9.4) and additional high-severity weaknesses, the overall risk is considered high to critical. Exploitation can lead to unauthorized control of charging workflows, widespread service outages, and corruption of charging network data.

### Reference
- [CISA ICS Advisory ICSA-26-057-06](https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-06)
- [CVE-2026-27767](https://www.cve.org/CVERecord?id=CVE-2026-27767)
- [CVE-2026-25113](https://www.cve.org/CVERecord?id=CVE-2026-25113)
- [CVE-2026-25778](https://www.cve.org/CVERecord?id=CVE-2026-25778)
- [CVE-2026-27773](https://www.cve.org/CVERecord?id=CVE-2026-27773)

### Vendor of Product
- SWITCH EV – EV charging management platform (swtchenergy.com)

### Affected Product Code Base
- SWITCH EV swtchenergy.com – All versions

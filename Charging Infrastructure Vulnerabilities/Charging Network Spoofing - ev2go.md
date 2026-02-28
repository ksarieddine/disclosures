## Vulnerability Report: Charging Network Spoofing / Session Abuse (EV2GO)

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
A critical set of vulnerabilities has been identified in the EV2GO (ev2go.io) EV charging management platform, as documented in CISA advisory ICSA-26-057-04. These issues enable unauthenticated station impersonation, session hijacking, brute-force authentication attacks, and credential exposure via public mapping platforms.

### Description
The advisory maps to four vulnerabilities:
- **CVE-2026-24731 (CVSS 9.4, CWE-306)**: WebSocket endpoints lack proper authentication, allowing attackers to impersonate charging stations and manipulate backend data.
- **CVE-2026-25945 (CVSS 7.5, CWE-307)**: The WebSocket API lacks restrictions on authentication request volume, enabling denial-of-service and brute-force attacks.
- **CVE-2026-20895 (CVSS 7.3, CWE-613)**: Predictable session identifiers enable session hijacking or shadowing, where unauthorized connections displace legitimate stations.
- **CVE-2026-22890 (CVSS 6.5, CWE-522)**: Charging station identifiers are publicly accessible via web-based mapping platforms, exposing authentication credentials.

Together, these weaknesses can be chained to impersonate charging endpoints, suppress or misroute legitimate traffic, cause large-scale denial of service, and manipulate data sent to the backend.

### Impact
The exploitation of this vulnerability can lead to the following risks:
- **Unauthorized backend access**: Attackers connect and manipulate backend data without valid credentials (CVE-2026-24731).
- **Service disruption and brute-force exposure**: Unrestricted authentication requests enable DoS and credential attacks (CVE-2026-25945).
- **Session integrity loss**: Predictable session IDs allow session hijacking and station displacement (CVE-2026-20895).
- **Credential exposure**: Station identifiers discoverable via public mapping enable targeted exploitation (CVE-2026-22890).

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
Given that this vulnerability set includes an unauthenticated access path (CVSS 9.4) and additional high-severity weaknesses, the overall risk is considered high to critical. Exploitation can lead to unauthorized control of charging workflows, large-scale service disruption, and significant operational and reputational impact.

### Reference
- [CISA ICS Advisory ICSA-26-057-04](https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-04)
- [CVE-2026-24731](https://www.cve.org/CVERecord?id=CVE-2026-24731)
- [CVE-2026-25945](https://www.cve.org/CVERecord?id=CVE-2026-25945)
- [CVE-2026-20895](https://www.cve.org/CVERecord?id=CVE-2026-20895)
- [CVE-2026-22890](https://www.cve.org/CVERecord?id=CVE-2026-22890)

### Vendor of Product
- EV2GO – EV charging management platform (ev2go.io)

### Affected Product Code Base
- EV2GO ev2go.io – All versions

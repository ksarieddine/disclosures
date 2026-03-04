## Vulnerability Report: Charging Network Spoofing / Session Abuse (Mobiliti)

### Severity
**Critical overall (max CVSS v3.1: 9.4)**

### Reported by
**Khaled Sarieddine ([LinkedIn](https://www.linkedin.com/in/khaled-salah-sarieddine/))**
**Mohammad Ali Sayed ([LinkedIn](https://www.linkedin.com/in/mohammadali-sayed/))**

### Date Reported
**10/05/2025**

### Status
**Published by CISA (vendor did not respond to coordination requests)**

### Published by CISA
**03/03/2026**

### Summary
A critical set of vulnerabilities has been identified in the Mobiliti e-mobi.hu EV charging management platform, as documented in CISA advisory ICSA-26-062-06. These issues enable unauthenticated station impersonation, session hijacking/shadowing, brute-force authentication attacks, and credential exposure via public mapping platforms.

### Description
The advisory maps to four vulnerabilities:
- **CVE-2026-26051 (CVSS 9.4, CWE-306)**: WebSocket endpoints lack authentication, allowing attackers to impersonate charging stations and issue unauthorized OCPP commands to the backend.
- **CVE-2026-20882 (CVSS 7.5, CWE-307)**: Missing rate limiting on the WebSocket API enables denial-of-service and brute-force authentication attacks.
- **CVE-2026-27764 (CVSS 7.3, CWE-613)**: Predictable/shared station session identifiers allow hijacking or shadowing of legitimate charger sessions.
- **CVE-2026-27777 (CVSS 6.5, CWE-522)**: Charging-station authentication identifiers are publicly accessible via web-based mapping platforms.

Together, these weaknesses can be chained to impersonate charging endpoints, maintain unauthorized backend presence, and disrupt or manipulate charging-session state.

### Impact
The exploitation of this vulnerability can lead to the following risks:
- **Unauthorized backend access**: Attackers can connect and issue commands without valid credentials (CVE-2026-26051).
- **Service disruption and brute-force exposure**: Repeated authentication traffic can degrade availability and increase credential attack risk (CVE-2026-20882).
- **Session integrity loss**: Shared/predictable station session identifiers can displace legitimate stations and corrupt session state (CVE-2026-27764).
- **Credential exposure**: Publicly available station identifiers increase targeted attack feasibility (CVE-2026-27777).

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
- [CISA ICS Advisory ICSA-26-062-06](https://www.cisa.gov/news-events/ics-advisories/icsa-26-062-06)
- [CVE-2026-26051](https://www.cve.org/CVERecord?id=CVE-2026-26051)
- [CVE-2026-20882](https://www.cve.org/CVERecord?id=CVE-2026-20882)
- [CVE-2026-27764](https://www.cve.org/CVERecord?id=CVE-2026-27764)
- [CVE-2026-27777](https://www.cve.org/CVERecord?id=CVE-2026-27777)

### Vendor of Product
- Mobiliti (Hungary) - EV charging management platform (e-mobi.hu)

### Affected Product Code Base
- Mobiliti e-mobi.hu: vers:all/*

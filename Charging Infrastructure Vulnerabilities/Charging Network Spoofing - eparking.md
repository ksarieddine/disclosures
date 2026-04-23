## Vulnerability Report: Charging Network Spoofing / Session Abuse (IGL-Technologies eParking.fi)

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
A critical set of vulnerabilities has been identified in IGL-Technologies eParking.fi, as documented in CISA advisory ICSA-26-078-07. These issues enable unauthenticated station impersonation, session hijacking, denial-of-service attacks, and credential exposure via public mapping platforms.

### Description
The advisory maps to four vulnerabilities:
- **CVE-2026-29796 (CVSS 9.4, CWE-306)**: WebSocket endpoints lack proper authentication. Attackers can connect to OCPP endpoints using known station identifiers to impersonate legitimate chargers, manipulate backend data, and gain unauthorized control of charging infrastructure.
- **CVE-2026-31903 (CVSS 7.5, CWE-307)**: The WebSocket API lacks rate limiting, enabling denial-of-service attacks that suppress telemetry or facilitate brute-force access attempts.
- **CVE-2026-32663 (CVSS 7.3, CWE-613)**: Multiple endpoints can connect using identical session identifiers, enabling session hijacking where newer connections displace legitimate stations.
- **CVE-2026-31926 (CVSS 6.5, CWE-522)**: Station authentication identifiers are publicly accessible through web-based mapping platforms.

Together, these weaknesses can be chained to impersonate charging endpoints, maintain unauthorized backend presence, and disrupt or manipulate charging-session state.

### Impact
The exploitation of this vulnerability can lead to the following risks:
- **Unauthorized backend access**: Attackers can connect and issue OCPP commands without valid credentials (CVE-2026-29796).
- **Service disruption and brute-force exposure**: Lack of rate limiting enables telemetry suppression and increased credential attack risk (CVE-2026-31903).
- **Session integrity loss**: Identical session identifiers allow newer connections to displace legitimate stations and corrupt session state (CVE-2026-32663).
- **Credential exposure**: Publicly available station identifiers increase targeted attack feasibility (CVE-2026-31926).

### Steps to Reproduce
1. Identify a target eParking.fi WebSocket endpoint using publicly accessible mapping platforms that expose station authentication identifiers.
2. Connect to the OCPP WebSocket endpoint using the discovered station identifier, bypassing authentication controls (CVE-2026-29796, CVE-2026-31926).
3. Issue OCPP protocol commands to the backend to simulate a legitimate charger, manipulate backend data, or disrupt charging sessions.
4. Observe that no rate limiting prevents repeated connection attempts, enabling brute-force or DoS scenarios (CVE-2026-31903).
5. Connect using the same session identifier as an active station to displace its session and assume backend presence (CVE-2026-32663).

All steps are performed in a controlled test environment with authorization.

### Root Cause
- Missing mandatory authentication enforcement for WebSocket connection paths.
- Missing or weak throttling/lockout controls for authentication attempts.
- Insufficient session identifier uniqueness and lifecycle enforcement allowing duplicate concurrent connections.
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
   - Reject duplicate connections using the same session identifier; enforce single active session per station.
4. **Credential Protection**:
   - Remove or obfuscate station authentication identifiers from public-facing mapping platforms.
5. **Network Segmentation and Access Controls**:
   - Restrict charger-management interfaces to trusted networks/VPN.
   - Segment OT charging networks from corporate IT and external zones.

### Risk Assessment
Given that this vulnerability set includes an unauthenticated access path (CVSS 9.4) and additional high-severity weaknesses, the overall risk is considered high to critical. Exploitation can lead to unauthorized control of charging workflows, service disruption, and significant operational and reputational impact. IGL-Technologies has deployed updates implementing modern security profiles, device-level whitelisting, rate-limiting controls, and enhanced monitoring.

### Reference
- [CISA ICS Advisory ICSA-26-078-07](https://www.cisa.gov/news-events/ics-advisories/icsa-26-078-07)
- [CVE-2026-29796](https://www.cve.org/CVERecord?id=CVE-2026-29796)
- [CVE-2026-31903](https://www.cve.org/CVERecord?id=CVE-2026-31903)
- [CVE-2026-32663](https://www.cve.org/CVERecord?id=CVE-2026-32663)
- [CVE-2026-31926](https://www.cve.org/CVERecord?id=CVE-2026-31926)

### Vendor of Product
- IGL-Technologies (Finland) - eParking.fi OCPP backend platform for EV charging infrastructure

### Affected Product Code Base
- IGL-Technologies eParking.fi: vers:all/*

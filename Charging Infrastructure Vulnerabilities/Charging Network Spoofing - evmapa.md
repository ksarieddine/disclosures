## Vulnerability Report: Charging Network Spoofing / Session Abuse (EVMAPA)

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
**01/22/2026**

### Summary
A critical set of vulnerabilities has been identified in the EVMAPA charging management platform, as documented in CISA advisory ICSA-26-022-08. These issues can be used to spoof charging-station identity or abuse backend authentication and session handling. The weaknesses include unauthenticated WebSocket access, unrestricted authentication attempts, and concurrent backend sessions tied to a single charging station ID.

### Description
The advisory maps to three vulnerabilities:
- **CVE-2025-54816 (CVSS 9.4, CWE-306)**: Missing authentication on a WebSocket endpoint enables unauthenticated backend access and unauthorized actions.
- **CVE-2025-53968 (CVSS 7.5, CWE-307)**: No effective limit on authentication attempts enables brute force and authentication DoS.
- **CVE-2025-55705 (CVSS 7.3, CWE-613)**: Insufficient session expiration and duplicate station-ID session handling allows concurrent session reuse/manipulation.

Together, these weaknesses can be chained to impersonate a charging endpoint, maintain unauthorized backend presence, and disrupt or manipulate charging-session state. This can undermine trust in charging operations and create operational and safety concerns for EV charging infrastructure.

### Impact
The exploitation of this vulnerability can lead to the following risks:
- **Unauthorized backend access**: Attackers can connect and perform actions without valid authentication (CVE-2025-54816).
- **Service disruption and brute-force exposure**: Repeated authentication traffic can degrade availability and increase credential attack risk (CVE-2025-53968).
- **Charging session integrity loss**: Concurrent reuse of one charging-station ID can cause data inconsistency and possible session manipulation (CVE-2025-55705).
- **Operational trust degradation**: Drivers and operators may receive inaccurate station/session state, creating financial, reputational, and service reliability impacts.

### Root Cause
The root cause of this vulnerability is:
- Missing mandatory authentication enforcement for a critical backend function (WebSocket connection path).
- Missing or weak throttling/lockout controls for authentication attempts.
- Weak session lifecycle controls (insufficient expiration and duplicate station-ID session acceptance).

### Recommendations
To mitigate the risks associated with this vulnerability, the following actions should be taken:
1. **Proper Authentication Enforcement**:
   - Require strong mutual authentication for charging station to backend communications.
   - Enforce token/session binding to station identity and transport channel.
   - Block unauthenticated WebSocket upgrades by default.
2. **Rate Limiting and Brute Force Protection**:
   - Apply per-source and per-account rate limits on authentication endpoints.
   - Enforce lockout/backoff after failed authentication thresholds.
   - Add detection rules for repeated auth failures and anomalous connection bursts.
3. **Session Management Hardening**:
   - Enforce single active backend session per charging station ID (or strict duplicate-session policy).
   - Implement short session lifetimes with rotation/revalidation.
   - Revoke prior session context immediately on re-authentication.
4. **Network Segmentation and Access Controls**:
   - Restrict charger-management interfaces to trusted networks/VPN and deny direct internet exposure.
   - Segment OT charging networks from corporate IT and external zones.
   - Monitor WebSocket/auth endpoints with centralized logging and alerting.
5. **Patch and Monitoring Program**:
   - Track vendor fixes for all three CVEs and validate remediation in staging before rollout.
   - Re-test controls after patching, especially authentication bypass and duplicate-session handling.
   - Maintain an incident response runbook for charging backend compromise scenarios.

### Risk Assessment
Given that this vulnerability set includes an unauthenticated access path (CVSS 9.4) and additional high-severity weaknesses, the overall risk is considered high to critical. Exploitation can lead to unauthorized control of charging workflows, service disruption, and significant operational and reputational impact. It also impacts any downstream service that depends on charger telemetry or session data, including billing, roaming, fleet management, and analytics pipelines. In some deployments, charger data is shared with power grid demand and response programs, which increases the potential for broader operational and energy-management consequences.

### Reference
- [CISA ICS Advisory ICSA-26-022-08](https://www.cisa.gov/news-events/ics-advisories/icsa-26-022-08)
- [CISA CSAF Record (ICSA-26-022-08 JSON)](https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-022-08.json)
- [CVE-2025-54816](https://www.cve.org/CVERecord?id=CVE-2025-54816)
- [CVE-2025-53968](https://www.cve.org/CVERecord?id=CVE-2025-53968)
- [CVE-2025-55705](https://www.cve.org/CVERecord?id=CVE-2025-55705)

### Vendor of Product
- EVMAPA (EV charging management/backend platform)

### Affected Product Code Base
- EVMAPA platform (CISA advisory indicates impact across deployed EVMAPA instances; explicit version granularity is not provided in public CVE summaries).

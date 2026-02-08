ksarieddine's disclosures and CVE's

This repository contains security vulnerability disclosures and assigned CVEs discovered by ksarieddine. It serves as an index of findings with links to detailed technical write-ups and impact summaries.

## CVE Index

- [CVE-2025-50503](Touch%20Mobile%20Application/2FA%20Bypass%20-%20Touch%20Lebanon.md): Improper validation in the Touch password reset flow allowed invalid verification codes to be accepted. An attacker who knew a valid username could reset the victim's password and take over the account.
- [CVE-2025-53968](Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20evmapa.md): EVMAPA authentication endpoints lacked effective limits on failed login attempts, enabling brute-force behavior and authentication abuse. This weakness also increased the risk of authentication-driven denial-of-service conditions.
- [CVE-2025-54816](Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20evmapa.md): A missing authentication control on a backend WebSocket endpoint allowed unauthenticated access. Attackers could perform unauthorized backend actions and potentially spoof charging-station behavior.
- [CVE-2025-55705](Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20evmapa.md): Session handling allowed concurrent or duplicate backend sessions tied to the same charging station ID. This could enable session reuse or manipulation and reduce charging-session integrity.

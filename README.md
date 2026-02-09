# ksarieddine's disclosures and CVEs

This repository contains security vulnerability disclosures and assigned CVEs discovered by ksarieddine. It serves as an index of findings with links to detailed technical write-ups and impact summaries.

## CVE Index

<table>
  <thead>
    <tr>
      <th align="left">Company</th>
      <th align="left" width="340">CVE(s)</th>
      <th align="left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Touch Lebanon</td>
      <td><nobr><a href="Touch%20Mobile%20Application/2FA%20Bypass%20-%20Touch%20Lebanon.md"><code>CVE-2025-50503</code></a></nobr></td>
      <td>Improper validation in the password reset flow allowed invalid verification codes to be accepted, enabling account takeover for attackers who knew a valid username.</td>
    </tr>
    <tr>
      <td>EVMAPA</td>
      <td>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20evmapa.md"><code>CVE-2025-53968</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20evmapa.md"><code>CVE-2025-54816</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20evmapa.md"><code>CVE-2025-55705</code></a></nobr>
      </td>
      <td>Related issues in authentication and session handling: missing effective login-attempt limits (brute-force risk), missing authentication on a backend WebSocket endpoint (unauthorized access), and concurrent/duplicate backend sessions tied to the same charging station ID (session integrity risk).</td>
    </tr>
  </tbody>
</table>

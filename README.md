# <img src="logo.png" alt="CVE Connoisseur" width="45" align="center"/> ksarieddine's disclosures and CVEs

This repository contains security vulnerability disclosures and assigned CVEs discovered by ksarieddine. It serves as an index of findings with links to detailed technical write-ups and impact summaries.

**8 companies affected · 28 CVEs assigned**

<p align="center">
  <img src="https://img.shields.io/badge/Sector-EV%20Charging%20Infrastructure-2ea44f?style=flat-square&logo=ev-station&logoColor=white"/>
  <img src="https://img.shields.io/badge/Sector-Mobile%20Applications-0075be?style=flat-square&logo=android&logoColor=white"/>
  <img src="https://img.shields.io/badge/Sector-ICS%20%2F%20SCADA-cc0000?style=flat-square&logo=datadog&logoColor=white"/>
  <img src="https://img.shields.io/badge/Advisory-CISA%20ICS-orange?style=flat-square&logo=gov&logoColor=white"/>
  <img src="https://img.shields.io/badge/Sector-Web%20Applications-0052cc?style=flat-square&logo=googlechrome&logoColor=white"/>
</p>

## CVE Index

<table>
  <thead>
    <tr>
      <th align="left">Company</th>
      <th align="left" width="340">CVE(s)</th>
      <th align="left">Description</th>
      <th align="left">Published</th>
      <th align="left">Publisher</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Touch Lebanon</td>
      <td><nobr><a href="Touch%20Mobile%20Application/2FA%20Bypass%20-%20Touch%20Lebanon.md"><code>CVE-2025-50503</code></a></nobr></td>
      <td>Improper validation in the password reset flow allowed invalid verification codes to be accepted, enabling account takeover for attackers who knew a valid username.</td>
      <td><nobr>08/20/2025</nobr></td>
      <td><a href="https://nvd.nist.gov/vuln/detail/CVE-2025-50503">NVD</a></td>
    </tr>
    <tr>
      <td>EVMAPA</td>
      <td>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20evmapa.md"><code>CVE-2025-53968</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20evmapa.md"><code>CVE-2025-54816</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20evmapa.md"><code>CVE-2025-55705</code></a></nobr>
      </td>
      <td>Related issues in authentication and session handling: missing effective login-attempt limits (brute-force risk), missing authentication on a backend WebSocket endpoint (unauthorized access), and concurrent/duplicate backend sessions tied to the same charging station ID (session integrity risk).</td>
      <td><nobr>01/22/2026</nobr></td>
      <td><a href="https://www.cisa.gov/news-events/ics-advisories/icsa-26-022-08">CISA</a></td>
    </tr>
    <tr>
      <td>CloudCharge</td>
      <td>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20cloudcharge.md"><code>CVE-2026-20781</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20cloudcharge.md"><code>CVE-2026-25114</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20cloudcharge.md"><code>CVE-2026-27652</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20cloudcharge.md"><code>CVE-2026-20733</code></a></nobr>
      </td>
      <td>Missing WebSocket authentication enables station impersonation (CWE-306), missing rate limiting enables brute-force and DoS (CWE-307), predictable session identifiers allow session hijacking (CWE-613), and station IDs exposed via public mapping platforms (CWE-522).</td>
      <td><nobr>02/26/2026</nobr></td>
      <td><a href="https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-03">CISA</a></td>
    </tr>
    <tr>
      <td>EV2GO</td>
      <td>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20ev2go.md"><code>CVE-2026-24731</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20ev2go.md"><code>CVE-2026-25945</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20ev2go.md"><code>CVE-2026-20895</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20ev2go.md"><code>CVE-2026-22890</code></a></nobr>
      </td>
      <td>Missing WebSocket authentication enables station impersonation (CWE-306), missing rate limiting enables brute-force and DoS (CWE-307), predictable session identifiers allow session hijacking (CWE-613), and station IDs exposed via public mapping platforms (CWE-522).</td>
      <td><nobr>02/26/2026</nobr></td>
      <td><a href="https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-04">CISA</a></td>
    </tr>
    <tr>
      <td>Chargemap</td>
      <td>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20chargemap.md"><code>CVE-2026-25851</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20chargemap.md"><code>CVE-2026-20792</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20chargemap.md"><code>CVE-2026-25711</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20chargemap.md"><code>CVE-2026-20791</code></a></nobr>
      </td>
      <td>Missing WebSocket authentication enables station impersonation (CWE-306), missing rate limiting enables brute-force and DoS (CWE-307), shared session identifiers allow session hijacking (CWE-613), and station IDs exposed via public mapping platforms (CWE-522).</td>
      <td><nobr>02/26/2026</nobr></td>
      <td><a href="https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-05">CISA</a></td>
    </tr>
    <tr>
      <td>SWITCH EV</td>
      <td>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20switchev.md"><code>CVE-2026-27767</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20switchev.md"><code>CVE-2026-25113</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20switchev.md"><code>CVE-2026-25778</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20switchev.md"><code>CVE-2026-27773</code></a></nobr>
      </td>
      <td>Missing WebSocket authentication enables station impersonation (CWE-306), missing rate limiting enables brute-force and DoS (CWE-307), predictable session identifiers allow station displacement (CWE-613), and station IDs exposed via public mapping platforms (CWE-522).</td>
      <td><nobr>02/26/2026</nobr></td>
      <td><a href="https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-06">CISA</a></td>
    </tr>
    <tr>
      <td>EV Energy</td>
      <td>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20evenergy.md"><code>CVE-2026-27772</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20evenergy.md"><code>CVE-2026-24445</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20evenergy.md"><code>CVE-2026-26290</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20evenergy.md"><code>CVE-2026-25774</code></a></nobr>
      </td>
      <td>Missing WebSocket authentication enables station impersonation (CWE-306), missing rate limiting enables brute-force and DoS (CWE-307), shared session identifiers allow session hijacking and shadowing (CWE-613), and station credentials exposed via public mapping platforms (CWE-522).</td>
      <td><nobr>02/26/2026</nobr></td>
      <td><a href="https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-07">CISA</a></td>
    </tr>
    <tr>
      <td>Mobility46</td>
      <td>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20mobility46.md"><code>CVE-2026-27028</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20mobility46.md"><code>CVE-2026-26305</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20mobility46.md"><code>CVE-2026-27647</code></a></nobr><br>
        <nobr><a href="Charging%20Infrastructure%20Vulnerabilities/Charging%20Network%20Spoofing%20-%20mobility46.md"><code>CVE-2026-22878</code></a></nobr>
      </td>
      <td>Missing WebSocket authentication enables station impersonation (CWE-306), missing rate limiting enables brute-force and DoS (CWE-307), predictable session identifiers allow session hijacking (CWE-613), and station credentials exposed via public mapping platforms (CWE-522).</td>
      <td><nobr>02/26/2026</nobr></td>
      <td><a href="https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-08">CISA</a></td>
    </tr>
  </tbody>
</table>

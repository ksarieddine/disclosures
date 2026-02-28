## Vulnerability Report: Improper Validation of Password Reset Verification Code

### Severity
**High**

### Reported by
**Khaled Sarieddine ([LinkedIn](https://www.linkedin.com/in/khaled-salah-sarieddine/))**

### Date Reported
**12/15/2024**

### Status
**Closed and Remediated**

### Published by NVD
**08/20/2025**

### Summary
A critical vulnerability has been identified in the password reset mechanism of the Touch mobile application, which arises from improper validation of the verification code used during the password reset process. This flaw allows an attacker to bypass the verification code check, enabling them to reset passwords for any account, provided they know the valid username. Exploiting this vulnerability could lead to account takeover.

### Description
The password reset process of the Touch mobile application requires the user to enter their username first, after which a verification code is sent to their registered email or phone number. This code is then required to proceed with resetting the password.

However, due to improper validation of the verification code, an attacker can input any arbitrary code (even an incorrect one) and still proceed to reset the victim’s password. This vulnerability allows an attacker to take over the account without needing access to the correct verification code or the victim’s email or phone. 

The impact of this vulnerability is particularly severe because it enables the attacker to gain full control over the victim’s account, which could be linked to mobile services (e.g., phone credits, eSIM downloads).

### Impact
The exploitation of this vulnerability can lead to the following risks:
- **Account Takeover**: Attackers can reset the password for any account they know the username of, bypassing the verification code step. This allows them to gain access to sensitive personal data or services tied to the account.

- **Cascading Compromises**: Performing an eSIM swap requires additional checks; however, this provides the adversary with the ability to gain access to it, which might trigger a notification on the user’s device and through MFA fatigue. This could lead to the eSIM swap but requires additional steps.

Additionally, attackers can add and remove services on behalf of the user or send free SMS from the application on their behalf, which will naturally upset customers.

### Steps to Reproduce
1. Navigate to the password reset page of [Application/System Name].
2. Enter a valid username associated with an existing user account. (Note: The system requires the username before the password reset page).
3. Input any arbitrary or incorrect verification code instead of the correct one. It should be longer than 6 characters.
4. The system erroneously accepts the invalid code and allows the attacker to proceed with the password reset, gaining unauthorized access to the account.

### Root Cause
The root cause of this vulnerability is the improper validation of the verification code during the password reset process:
- The system does not ensure that the code entered by the user matches the one sent to the registered email or phone number.
- The verification code lacks expiration or is reused, allowing attackers to bypass the process.
- The system may allow invalid or expired codes to be used for resetting passwords.

### Recommendations
To mitigate the risks associated with this vulnerability, the following actions should be taken:
1. **Proper Verification Code Validation**:
   - Ensure that the verification code entered by the user matches exactly the code sent to the registered email or phone number.
   - Implement expiration for verification codes (e.g., a time window of 10–15 minutes) to reduce the window of opportunity for attackers.
   - Invalidate the verification code immediately after it is used, preventing reuse.
2. **Rate Limiting and Brute Force Protection**:
   - Implement rate limiting on password reset attempts to prevent attackers from trying many verification codes in quick succession.
   - Integrate CAPTCHA or other anti-bot mechanisms to prevent automated attacks on the reset flow.
3. **Account Enumeration Mitigation**:
   - Display generic error messages such as “If the username exists in our system, you will receive a password reset email.” This prevents attackers from determining whether a username exists based on the system’s response.
4. **Enhanced Email and 2FA Security**:
   - Strengthen 2FA mechanisms for account recovery (e.g., use app-based or hardware token 2FA instead of SMS where possible).
   - Implement stricter controls around email account password resets and require additional verification methods (e.g., secondary security questions or app-based confirmation).
5. **Logging and Monitoring**:
   - Log all failed password reset attempts, especially those involving incorrect verification codes, and monitor these logs for suspicious patterns.
   - Implement alerts for abnormal patterns of password reset activity, such as multiple reset attempts targeting the same username.

### Risk Assessment
Given that this vulnerability allows account takeover, this vulnerability is considered high risk. Exploitation could lead to significant financial, personal, and reputational damage.

### Reference
- [Touch Lebanon Mobile App](https://www.touch.com.lb/autoforms/portal/touch/personal/contentandapps/mobileapp)
- [CVE-2025-50503 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2025-50503?utm_source=feedly)

### Vendor of Product
- Touch Mobile Application and Website Backend

### Affected Product Code Base
- 2.20.2


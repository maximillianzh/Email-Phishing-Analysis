# Email-Phishing-Analysis
In this project, I conducted an analysis of email phishing attempts occurring in the real world today. This analysis is crucial as it helps identify and mitigate threats posed by malicious actors. By scrutinizing these phishing attempts, we can better understand the tactics used by attackers and develop more effective strategies for combating such threats.

## Email 1: Chase Bank Phishing <br>
![image](https://github.com/user-attachments/assets/3abf6a37-c3f1-453c-9129-0b0093acc5c8)<br>

The email in question appears to originate from **alerts@chase.com**, but further investigation is required to determine whether it is a phishing attempt. Upon closer examination, the **"Reply-To"** header raises suspicion as it lists **kellyellin426@proton.me**, an address that does not clearly correspond to Chase Bank.

#### Recieved Headers
![RecievedHeaders](https://github.com/user-attachments/assets/1947ded5-7201-40ab-95c3-01cc8efb80ca)<br>

By inspecting the raw contents of the email in a text editor such as Sublime Text, we can extract valuable information, including the originating IP address. 

#### WHOIS Command
![whoisSample1](https://github.com/user-attachments/assets/4450448d-8040-4287-bb4e-9ebb942d142c)<br>

Using a WHOIS lookup, we find that the IP address associated with the email is linked to a ProtonMail account based in Switzerland, rather than Chase Bank's servers in the United States. This evidence strongly suggests that the email has been spoofed.

**How Email Spoofing Occurs**:

1. **Spoofed Email Address**: The attacker creates an email using a service like ProtonMail but manipulates the “From” address field in the email header to display `alerts@chase.com`. This manipulation makes the email appear as though it originates from Chase Bank, despite being sent from a completely different server.

2. **Sending the Email**: The email is sent from the attacker’s ProtonMail account. ProtonMail's servers process and send the email with the spoofed “From” address, which does not verify the authenticity of the sender's domain.

3. **Email Header Modification**: In the email headers, the attacker can alter the “From” field to make it look like the email is coming from Chase Bank. However, the actual sending server’s IP address reveals the true origin of the email.

4. **Verification of Authenticity**: By examining the email headers and performing a WHOIS lookup on the IP address, it becomes clear that the email did not originate from Chase Bank’s legitimate servers but rather from a ProtonMail server. This discrepancy indicates that the attacker used a fake address to deceive the recipient.

5. **Conclusion**: The combination of the spoofed email address and the IP address linked to a ProtonMail account in Switzerland, rather than Chase Bank’s legitimate servers, confirms that the email is a phishing attempt. The attacker’s goal was to impersonate Chase Bank and potentially trick recipients into divulging sensitive information or taking harmful actions.


Email 2: CIBC Bank Phishing
![Sample2](https://github.com/user-attachments/assets/ff9eff7f-71be-4ab2-80d0-efe9235ea3a8)<br>
![SublimeSample2](https://github.com/user-attachments/assets/0cea38df-fa94-4a7a-8d30-ec66157843ea)<br>
![WhoisSample2](https://github.com/user-attachments/assets/9838fc30-49df-4afc-be7f-d4aad0c2233e)<br>

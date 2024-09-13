# Email Phishing Analysis
In this project, I conducted an analysis of email phishing attempts occurring in the real world today. This analysis is crucial as it helps identify and mitigate threats posed by malicious actors. By scrutinizing these phishing attempts, we can better understand the tactics used by attackers and develop more effective strategies for combating such threats.

## Email 1: Chase Bank Phishing (Malicious) <br>
![image](https://github.com/user-attachments/assets/3abf6a37-c3f1-453c-9129-0b0093acc5c8)<br>

The email in question appears to originate from **alerts@chase.com**, but further investigation is required to determine whether it is a phishing attempt. Upon closer examination, the **"Reply-To"** header raises suspicion as it lists **kellyellin426@proton.me**, an address that does not clearly correspond to Chase Bank.

![RecievedHeaders](https://github.com/user-attachments/assets/1947ded5-7201-40ab-95c3-01cc8efb80ca)<br>

By inspecting the raw contents of the email in a text editor such as Sublime Text, we can extract valuable information, including the originating IP address. 

![whoisSample1](https://github.com/user-attachments/assets/4450448d-8040-4287-bb4e-9ebb942d142c)<br>

Using a WHOIS lookup, we find that the IP address associated with the email is linked to a ProtonMail account based in Switzerland, rather than Chase Bank's servers in the United States. This evidence strongly suggests that the email has been spoofed.

**How Email Spoofing Occurs**:

1. **Spoofed Email Address**: The attacker creates an email using a service like ProtonMail but manipulates the “From” address field in the email header to display `alerts@chase.com`. This manipulation makes the email appear as though it originates from Chase Bank, despite being sent from a completely different server.

2. **Sending the Email**: The email is sent from the attacker’s ProtonMail account. ProtonMail's servers process and send the email with the spoofed “From” address, which does not verify the authenticity of the sender's domain.

3. **Email Header Modification**: In the email headers, the attacker can alter the “From” field to make it look like the email is coming from Chase Bank. However, the actual sending server’s IP address reveals the true origin of the email.

4. **Verification of Authenticity**: By examining the email headers and performing a WHOIS lookup on the IP address, it becomes clear that the email did not originate from Chase Bank’s legitimate servers but rather from a ProtonMail server. This discrepancy indicates that the attacker used a fake address to deceive the recipient.

5. **Conclusion**: The combination of the spoofed email address and the IP address linked to a ProtonMail account in Switzerland, rather than Chase Bank’s legitimate servers, confirms that the email is a phishing attempt. The attacker’s goal was to impersonate Chase Bank and potentially trick recipients into divulging sensitive information or taking harmful actions.


## Email 2: CIBC Phishing (Malicious)
![Sample2 1](https://github.com/user-attachments/assets/fcbcb5c0-c496-4d98-9d7d-e2374aacff0e)<br>

Upon examining the "Sent From" header, we notice that the domain ends in “caib.com”, when it should actually be “cibc.com”, the legitimate domain of CIBC (Canadian Imperial Bank of Commerce), a major financial institution in Canada. This is a common phishing tactic known as typosquatting, where attackers register domain names that closely resemble legitimate ones to deceive recipients.

![SublimeSample2](https://github.com/user-attachments/assets/0cea38df-fa94-4a7a-8d30-ec66157843ea)<br>

By analyzing the raw email contents in Sublime Text, we can extract the originating IP address and additional details. In this case, the Return-Path shows meztaz.logocec8@caib.com, which is different from the apparent sender’s address, jsmith@technicalsolutions.com.

#### WHOIS Lookup (website version)

![WhoisSample2](https://github.com/user-attachments/assets/9838fc30-49df-4afc-be7f-d4aad0c2233e)<br>

If we perform a WHOIS lookup on the original sender’s IP address, 190.6.201.67, we find that it originates from Honduras and is registered to an Internet Service Provider (ISP) called Cablecolor.hn. This information clearly shows that the email did not come from Canada or the legitimate servers of CIBC (Canadian Imperial Bank of Commerce). The geographic and organizational mismatch between the IP address and CIBC's operations strongly suggests this is a phishing attempt, as the actual sender has no connection to the bank.

## Email 3: Namecheap (Harmless)
![sample3 05](https://github.com/user-attachments/assets/8a9947c5-c8c8-4a92-8d74-b9d73c88288f)

This email appears to be from Namecheap.com, a popular domain registrar and web hosting provider. The subject line creates a sense of urgency, warning that our website will "expire in 7 days."

![Sample3 1](https://github.com/user-attachments/assets/9ebca503-6020-47f6-9515-4efb740b40cf)

![Sample3 2](https://github.com/user-attachments/assets/36795020-9e17-4d6c-882c-b08acdb20a30)

When inspecting the Received header, we observe the IP address from which the email was sent, which cannot be spoofed. This IP allows us to trace the true origin of the email. By performing a WHOIS lookup, we discover that this IP is registered to SendGrid Inc., a cloud-based email delivery service used to send transactional and marketing emails. While SendGrid is legitimate, its service can potentially be abused for phishing attempts if not properly monitored.

![sample3 3](https://github.com/user-attachments/assets/9f8a985d-8e8f-4d1e-8609-1358b893f9b1)

![sample3 4](https://github.com/user-attachments/assets/f5b4aeb3-c884-4066-a024-75f80dd6ebb1)

To verify the authenticity of the email, we examine the SPF (Sender Policy Framework), an email authentication protocol that checks whether the IP address sending the email is authorized by the domain's DNS records. We see that the IP address 149.72.0.0/16 is listed, confirming that mailserviceemailout1.namecheap.com is permitted to use SendGrid’s IP to send emails. In this case, Google’s mail servers validated the SPF record and allowed the email to pass through.

![sample3 5](https://github.com/user-attachments/assets/1d33d056-3c20-4b43-a0d7-e3946c80aa0e)

![sample3 6](https://github.com/user-attachments/assets/27019da3-a240-410f-ad3f-528f18d823fe)

Next, we check the email’s integrity using the DKIM-Signature (DomainKeys Identified Mail), which ensures that the email has not been altered during transmission. DKIM attaches a digital signature to the email that can be verified by the receiving server using the sender’s public key. In our case, the DKIM signature for namecheap.com looks correct, which allows us to proceed to the Authentication-Results.

![sample3 7](https://github.com/user-attachments/assets/adaf67f9-ad24-42b7-a28e-d23484ca297e)

In the Authentication-Results header, we see that all the checks passed: dkim=pass, spf=pass, and dmarc=pass. DMARC (Domain-based Message Authentication, Reporting, and Conformance) is a policy that uses SPF and DKIM results to determine how to handle emails that fail authentication. If any of these checks had failed, the email could have been flagged as suspicious or sent to the recipient’s spam folder.

#### Conclusion
After performing all these checks, we conclude that this email is not a phishing attempt and is, in fact, legitimate. However, it's important to note that while passing these checks is a positive sign, it is not a foolproof method of determining legitimacy. Malicious actors can still bypass these defenses, and additional scrutiny is always advised.

## Email 4: Trust Wallet Phish (Malicious)
![4 1](https://github.com/user-attachments/assets/08359ba6-ba90-45c9-ac48-7d5dd223283b)

In this email, we can already identify signs of potential malicious intent, starting with the sender address, 7wq1vg3kn9woejk4@emails.gorgias.com, which has no connection to Trust Wallet. However, this alone is not sufficient evidence, so we’ll delve deeper into the email’s contents (without clicking any links) to uncover its true intent.

First, the greeting “Hello; Customer” is unusual and not typical of a legitimate company, which would normally address the recipient by name. This vague salutation is a common phishing tactic.

The email also states, “All unverified accounts will be suspended on 10/31/2022,” creating a sense of urgency. This is a classic phishing strategy designed to scare recipients into acting quickly, especially when financial loss is implied. When dealing with matters of money, people are more prone to make hasty decisions out of fear.

Additionally, “Trustwallet” is spelled incorrectly. The legitimate company spells its name as Trust Wallet, with a space between the words. Small details like this are often overlooked but are telltale signs of phishing.

Here’s another example:
## Email 5: Another Trust Wallet Phish (Malicious)

![5 1](https://github.com/user-attachments/assets/bfa2cd32-2325-432a-94df-ca07dc96a58c)

The sender stainless@midnightmagicevents.com has no affiliation with Trust Wallet, yet claims to be representing the company.

In the message, the sentence, “Due to the recently update of NFT's & Coins, all unverified accounts will be suspended,” contains multiple grammatical errors. First, "recently update" should be "recent update"; next, “NFT's” incorrectly uses an apostrophe, and the sentence overall is awkwardly phrased. Furthermore, on the next line, the word “assistance” is misspelled, which further weakens the credibility of the email.

Given all of these red flags, you should already be highly suspicious of this email.

## Email 6: Amazon Phish (Malicious)
![6 1](https://github.com/user-attachments/assets/cbbbb205-3110-4d88-83bd-94c7b9c4d012)

While the content of the email may appear convincing at first glance, even using the real Amazon logo, it is essential to look beyond superficial elements and examine the finer details to determine if an email is legitimate or malicious.




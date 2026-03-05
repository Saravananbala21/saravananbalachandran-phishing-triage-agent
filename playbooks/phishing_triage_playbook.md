\# Phishing Triage Playbook



\## Objective

Automatically triage phishing-related alerts and determine if the email is malicious, suspicious, or benign.



---



\## Investigation Steps



\### 1. Sender Analysis

\- Check for domain spoofing

\- Look for typosquatting (ex: micr0soft vs microsoft)

\- Verify if sender domain is internal or external



\### 2. URL Analysis

\- Identify suspicious domains

\- Look for shortened links

\- Check if domain impersonates known services



\### 3. Attachment Analysis

\- Identify risky file types (zip, exe, js, macro-enabled docs)

\- Flag unexpected attachments



\### 4. Email Content Indicators

\- Urgency or threats

\- Credential harvesting language

\- Payment requests



\### 5. User Reporting

\- If reported by user, increase suspicion score



---



\## Classification



\### Malicious

Indicators strongly show phishing or malware.



\### Suspicious

Some phishing indicators exist but not confirmed.



\### Benign

Legitimate communication.



---



\## Recommended Actions



\### Malicious

\- Quarantine email

\- Block sender domain

\- Investigate affected user mailbox



\### Suspicious

\- Send to human analyst

\- Monitor related emails



\### Benign

\- Close alert


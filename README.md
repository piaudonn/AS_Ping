## Wait, what is that about?

This was developed as a proof of concept to check if an account has a AES256 key available for the Kerberos pre-authentication.
It simulates a KRB_AS_REQ without pre-authentication with the intent to parse the response from a domain controller. It is not considered to be a sign-in attempt and will not lock out the account. 

### Syntax

You can call the script like this: _.\New-ASPing.ps1 -DCIp <IP of the DC> -NetbiosDomainName <NetBios name of the domain> -username <user's UPN prefix>_. For example:
```PowerShell
.\New-ASPing.ps1 -DCIp 10.0.0.1 -NetbiosDomainName CONTOSO -username BOB_
```

### Output
If the account has an EAS key, the output will be:
```
[+] Crafting KRB_AS_REQ ping for P\p1
[+] Opening TCP socket to 10.0.0.4 port 88
[+] Closing TCP socket
[+] Parsing KDC_ERR_PREAUTH_REQUIRED
[+] User has AES keys
[+] AES Salt = PIESEC.CAp1
```

If the account doesn't have an AES key, and only an RC4 key, the output will be:
```
[+] Crafting KRB_AS_REQ ping for P\user101
[+] Opening TCP socket to 10.0.0.4 port 88
[+] Closing TCP socket
[+] Parsing KDC_ERR_PREAUTH_REQUIRED
[+] User only has RC4 keys
```

## What the #$% is the script doing?

There are plenty of pretty cool tools to manipulate Kerberos at the raw level. Unfortunately, most of them are considered "hacking" tool by antivirus software. So, I decided to send the data direction using a TCP socket.
I originally built an ASN library in PowerShell too (without .Net import, pure PowerShell) but I figured since the message we send and the message we parse are predictable in length and structure, I decided not to use it in the final code.

## Will my security team see what I am doing?

Since knowing who has only an RC4 key, or simply knowing if an account exists gives away useful recon information to an attacker, it's good to check if using that script (or technique) will be visible to the blue team. And the answer is **yes**.

When the account doesn't exist and the audit subcategory **Account Logon/Kerberos Authentication Service** is enabled for failure on the domain controllers, you will see the security event **4768** showing the account that was tested along with the IP address of the device it is coming from.

When you "scan" an environment that have Microsoft Defender for Identity, it will also trigger the following alert:  **Account enumeration reconnaissance** showing the scanned accounts who exist and those who don't.




## Wait, what is that about?

This was developed as a proof of concept to check if an account has a AES256 key available for the Kerberos pre-authentication.
It simulates a KRB_AS_REQ without pre-authentication with the intent to parse the response from a domain controller. It is not considered to be a sign-in attempt and will not lock out the account. 

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
I originally built an ASN library in PowerShell tool (without .Net import, pure PowerShell) but I figured since the message we send and the message we parse are predictable in length and structure, I decided not to use it in the final code.

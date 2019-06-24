# CVE-2019-1040 scanner

Checks for CVE-2019-1040 vulnerability over SMB.
The script will establish a connection to the target host(s) and send
an invalid NTLM authentication. If this is accepted, the host is vulnerable to
CVE-2019-1040 and you can execute the [MIC Remove attack](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/) with ntlmrelayx.

Note that this does not generate failed login attempts as the login information itself is valid, it is just the NTLM message integrity code that is absent, which is why the authentication is refused without increasing the badpwdcount.

# Usage
The script requires a recent impacket version. Should work with both python 2 and 3 (Python 3 requires you to use impacket from git).

```
[*] CVE-2019-1040 scanner by @_dirkjan / Fox-IT - Based on impacket by SecureAuth
usage: scan.py [-h] [-target-file file] [-port [destination port]]
               [-hashes LMHASH:NTHASH]
               target

CVE-2019-1040 scanner - Connects over SMB and attempts to authenticate with
invalid NTLM packets. If accepted, target is vulnerable to MIC remove attack

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

optional arguments:
  -h, --help            show this help message and exit

connection:
  -target-file file     Use the targets in the specified file instead of the
                        one on the command line (you must still specify
                        something as target name)
  -port [destination port]
                        Destination port to connect to SMB Server

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
```


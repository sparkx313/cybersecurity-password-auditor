# Offline Password Policy Auditor

A terminal utility that checks one password against a length policy and, optionally, a local exact-match blocklist. It reads the password through hidden terminal input. The password is not accepted as a command-line argument, printed, stored, or sent over a network. No third-party packages are required.

## Run

~~~sh
python password_auditor.py
python password_auditor.py --mode mfa
python password_auditor.py --blocklist ./local-blocklist.txt
~~~

The default single-factor mode checks a minimum of 15 Unicode code points. MFA mode uses a minimum of 8. These lengths follow the current NIST SP 800-63B guidance for centrally verified passwords; the program does not claim NIST compliance. It does not impose character-class rules.

A supplied blocklist is read locally and compared as exact, case-sensitive lines. The tool has no built-in breached-password database, does not estimate entropy or crack time, and cannot prove that a password has never been exposed. A passing result means only that the configured checks passed. Prefer a password manager and unique passwords for each account.

The program refuses redirected password input because it cannot guarantee that piped input is hidden. It needs a terminal that supports no-echo password entry.
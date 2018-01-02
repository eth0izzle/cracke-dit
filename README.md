# cracke-dit
**cracke-dit** *("Cracked It")* **makes it easier to perform regular password audits against Active Directory environments.**

Ensuring your users have strong passwords throughout the organisation is still your best line of defence against common attacks. Many organisations over estimate just how secure their users' passwords are. "London123", "Winter2017", "Passw0rd" - all complex passwords, according to the default Group Policy rules, and probably your users.

By performing regular audits, you can identify users with weak passwords and take action inline with your policies and procedures.

## Installation

Python 2.7+ and pip are required. Then just:

1. `git clone https://github.com/eth0izzle/cracke-dit.git`
2. *(optional)* Create a virtualenv with `pip install virtualenv && virtualenv .virtualenv && source .virtualenv/bin/activate`
2. `pip install -r requirements.txt`
3. `python cracke-dit.py --help` (and see [Usage](#usage))

## Usage
### 1a. Extracting the database
The first step in your password cracking adventure is to extract a copy of the Active Directory database, ntds.dit, which contains the password hashes. Depending on your persuasion you have a few options:

#### a. Remote extraction with cracke-dit *(faster)*
1. `python cracke-dit.py --username administrator --password passw0rd --target 192.168.1.1`

#### b. Remote extraction with metasploit
1. Run module `auxiliary/admin/smb/psexec_ntdsgrab` and fill in the required options.
2. Follow 1b to extract the hashes from ntds.dit.

#### c. Nicely ask a Sys Admin
1. Follow 1b to extract the hashes from ntds.dit.

#### d. Local extraction
1. On a Domain Controller open up an elevated command prompt.
2. Run `ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q`.
3. **Securely** extract `c:\temp\Active Directory\ntds.dit` and `c:\temp\registry\SYSTEM` to your system with cracke-dit.
4. Follow 1b to extract the hashes from ntds.dit.

(if you just want to have a play, you can use the sample files in `./samples`)

### 1b. Extracting the hashes

*(not required if you remotely extracted with cracke-dit)*

All password hashes are protected with 3 layers of encryption. Thankfully everything we need to decrypt is within the SYSTEM hive. The next step is to extract the hashes and usernames in to a separate file for cracking:

1. Run `python cracke-dit.py --system SYSTEM --ntds ntds.dit` (optionally with `--no-history` flag if you don't care about historic passwords)
2. Once complete, your username:hash file will be at `<domain>.hashes.ntlm` - delicious.

(if you have a powerful GPU use oclhashcat)

### 2. Cracking the hashes
cracke-dit doesn't actually *crack* passwords, you will need to use your favourite password cracker for that. cracke-dit just needs a `.pot` file (hash:password) for processing. I'm partial to hashcat so:

1. `hashcat -m 1000 --potfile-path <domain>.pot --username <domain>.hashes.ntlm /usr/share/Wordlists/rockyou.txt` which will be pretty quick.
2. Do a second pass with [H0bRules](https://github.com/praetorian-inc/Hob0Rules): `hashcat -m 1000 --potfile-path <domain>.pot --username <domain>.hashes.ntlm /usr/share/Wordlists/rockyou.txt -r hob064.rule`
3. ...

### 3. Processing the passwords
Now we have cracked a bunch of hashes, let's load them in to cracke-dit!

1. `python cracke-dit.py --pot <domain>.pot --domain <domain>`. Optionally pass in `--only-users` or `--only-enabled` - hopefully they are self explanatory.

Using the ntds.dit and SYSTEM in `./samples` we get the following output:

![Demo](samples/demo.gif)

### 4. Interpreting results

* Users highlighted in **green** are enabled, **red** are disabled, and **gray** is an historic password.

* Password scores are based on [Dropbox's zxcvbn](https://github.com/dropbox/zxcvbn):

    | Score         | Description           | Guesses  |
    |------:|:----------------------| :-----|
    | 0     | **Too guessable**: risky password. | < 10^3 |
    | 1     | **Very guessable**: protection from throttled online attacks. | < 10^6 |
    | 2     | **Somewhat guessable**: protection from unthrottled online attacks. | < 10^8 |
    | 3     | **Safely unguessable**: moderate protection from offline slow-hash scenario. | < 10^10 |
    | 4     | **Very unguessable**: strong protection from offline slow-hash scenario. | => 10^10 |

## Output modules

Results can be processed by different output modules via the `--output` argument.

### Console (`stdout`)
The default output module and shown in the demo above. Shows interesting stats, top 10 passwords by reuse, the top 5 worst passwords and if any passwords use month or day names.

### E-mail (`email`)
E-mails the top 25 passwords (by reuse).

### Password Cloud (`password_cloud`)
Spits out a wordcloud of all passwords, colored by password score.

![Demo](samples/password_cloud.png)


## Tips for organisations

1. Introduce internal training on what a secure password is,  why they're important and embed it in to your induction programme.

2. Consider rolling out a password manager and adequate training for all of your users - stronger, longer and more unique passwords is better for everyone.

3. Gradually increase your password minimum length requirement to 12 characters.

4. Phase out forcing your users to "reset password every X days". There is research to suggest that this doesn't help create strong passwords, but in fact has the opposite effect.

5. Carry out a password audit quarterly. Do not name and shame people. Get HR buy-in and introduce a "3 strike system" that will carry a formal warning.

## Contributing

Check out the [issue tracker](https://github.com/eth0izzle/cracke-dit/issues) and see what takes your fancy.

1. Fork it, baby!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request.

## License

cracke-dit is under MIT. See [LICENSE](LICENSE)
Impacket is under a slightly modified version of the Apache Software License. See [LICENSE](impacket/LICENSE)

## Credits

Huge thanks [CoreSecurity's Impacket](https://github.com/CoreSecurity/impacket)!
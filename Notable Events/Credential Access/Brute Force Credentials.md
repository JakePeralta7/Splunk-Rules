# Brute Force Credentials

## [MITRE ATT&CK](https://attack.mitre.org/techniques/T1110/)
Tactic: Credential Access

Technique: Brute Force

## Description
Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes.

Brute forcing credentials may take place at various points during a breach. For example, adversaries may attempt to brute force access to Valid Accounts within a victim environment leveraging knowledge gathered from other post-compromise behaviors such as OS Credential Dumping, Account Discovery, or Password Policy Discovery. Adversaries may also combine brute forcing activity with behaviors such as External Remote Services as part of Initial Access.

## SPL
```spl
| from datamodel Authentication.Failed_Authentication
| stats count by app src dest user signature
| where count >= 5
```

## TODO
Make sure that authentications from all vendors arriving to the data model, and is mapped correctly to all the fields before relying on this rule.
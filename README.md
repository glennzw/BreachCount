# BreachCount

## What?
`breachcount.js` will check if any passwords in a form have been involved in large scale data breaches, and include the result as a hidden field in the form. It will also (optionally) include password length.

## Why?
On phishing campaigns you may not want to capture users' passwords (GDPR etc) but it'd be nice to have some password insight. This tool will let you know if your users are choosing bad passwords.

Rather than submitting the password, only a five character hash of the password is submitted to the `api.pwnedpasswords.com` endpoint. This is known as k-anonymity (read more [here](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/)).

## How do I use it?
Usage: Include `breachcount.js` in the <head> of any HTML file.

## How does it work?
The code works as follows:

1. Intercept form Submissions
2. Find all password fields in the form, calculate their SHA1 hashes, and submit their hash prefix to api.pwnedpasswords.com
3. Check if the local hash matches any of the returned hash rows
4. Add pwncount results from (3) as hidden fields to the form
5. Submit the form

Two flags can bet set in the code:

    clearPasswordFields: Clear password text before submitting
    includePasswordLength: Calculate and submit password length

e.g 
```
Original form POST:
username=AzureDiamond&password=hunter2

New form POST:
username=AzureDiamond&Password+Breach+Count=1&Password+Length=9&password=
```

Note: A result of -1 indicates an error connecting to api.pwnedpasswords.com

A page can have multiple forms (the form where the button was pressed will be processed) and a form can have multiple password fields.

## TODO
Add password strength option too.
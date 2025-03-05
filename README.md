# What is ddmail_openpgp_encryptor
Program to encrypt incoming emails with OpenPGP for the ddmail project.

## What is ddmail
DDMail is a e-mail system/service and e-mail provider with strong focus on security, privacy and anonymity. A current production example can be found at www.ddmail.se

## Operating system
Developt for and tested on debian 12.

## Building and installing using hatchling.
Step 1: clone github repo<br>
`git clone https://github.com/drzobin/ddmail_openpgp_encryptor [code path]`<br>
`cd [code path]`<br>
<br>
Step 2: Setup python virtual environments<br>
`python -m venv [venv path]`<br>
`source [venv path]/bin/activate`<br>
<br>
Step 3: Install required dependencies<br>
`pip install -r requirements.txt`<br>
<br>
Step 4: Build package<br>
`python -m pip install --upgrade build`<br>
`python -m build `<br><br>
Packages is now located under [code path]/dist folder<br>
<br>
Step 5: Install package<br>
`pip install [code path]/dist/[package name].whl`

## Run
`source [venv path]/bin/activate`<br>
`ddmail_openpgp_encryptor --config-file [config file].ini`

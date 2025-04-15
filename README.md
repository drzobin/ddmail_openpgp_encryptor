# What is ddmail_openpgp_encryptor
Program to encrypt incoming emails with OpenPGP for the ddmail project.

## What is DDMail
DDMail is a e-mail system/service that prioritizes security. A current production example can be found at www.ddmail.se

## Operating system
Developt for and tested on debian 12.

## Installing using pip
`pip install ddmail-openpgp-encryptor`

## Building and installing from source using hatchling.
Step 1: clone github repo<br>
`git clone https://github.com/drzobin/ddmail_openpgp_encryptor [code path]`<br>
`cd [code path]`<br>
<br>
Step 2: Setup python virtual environments<br>
`python -m venv [venv path]`<br>
`source [venv path]/bin/activate`<br>
<br>
Step 3: Install package and required dependencies<br>
`pip install -e .[dev]`<br>
<br>
Step 4: Build package<br>
`python -m pip install --upgrade build`<br>
`python -m build `<br><br>
Packages is now located under [code path]/dist folder<br>

## Run
`source [venv path]/bin/activate`<br>
`ddmail_openpgp_encryptor --config-file [config file].ini`

## Coding
Follow PEP8 and PEP257. Use Flake8 with flake8-docstrings for linting. Strive for 100% test coverage.

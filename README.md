# aws-login-python

# Prerequisites

* python 3 must be installed
* aws-cli must be installed

# Installation

Install all requirements

* `pip install -r requirements.txt`
* Move aws-login and aws_login.py to a folder in your `$PATH`

# Run

* Run with `aws-login <name>`, where name is the prefix of the profile which will be created.
* On the first run it will set-up an encrypted access file `<name>-access-file`. For this you will be asked to enter your `aws_access_key_id` , `aws_secret_access_key` and `mfa_serial_arn`. 
* Also, you must define `login_session_seconds` which will define how many seconds your temporary credentials will be valid for each login session.
* On every further run it will configure temporary credentials with the validity duration of `login_session_seconds` as a profile into your .credentials file
* The name of the profile will be `<name>-temporary-access`.


```
[name-temporary-access]
aws_access_key_id = *
aws_secret_access_key = *
aws_session_token = *
```

You can also use this profile as a source profile from where you want to switch roles.

```
[other-profile]
role_arn=arn:aws:iam::*:role/*
source_profile=name-temporary-access
```

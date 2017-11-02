Turtl Backup
============

This program permits to download a whole turtl account for offline
backuping, and optionally decrypt the backup file.


Installation
------------

You can instal ``turtl-backup`` using pip::

  pip install turtl-backup


Usage
-----

Here's the usage::

  usage: turtl-backup [-h] {backup,get_auth_token,export} ...

  Backup a turtl account.

  positional arguments:
    {backup,get_auth_token,export}
                          Backup can be done with a login/password pair or using
                          an auth token.
      backup              Backup a turtl account (with a password or an auth
                          token)
      get_auth_token      Get a turtl auth token
      export              Decrypt and export all notes in the given directory.

  optional arguments:
    -h, --help            show this help message and exit


So typically::

  turtl-backup backup https://api.framanotes.org backup.json


FAQ
---

> Is it possible to setup a cron to backup my notes without storing my
login/password in plaintext in my crontab?

Yes, the turtl ``auth_token`` is enough to backup an account.  You can
get your auth token using ``turtl-backup get_auth_token``, but still
be carefull not to leak it. Then use ``turtl-backup
backup --auth-token YOUR_AUTH_TOKEN``.


> Is it possible to decrypt my notes using my ``auth_token``?

No, you'll need your login and password again.

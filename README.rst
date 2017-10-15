Turtl Backup
============

This program permits to download a whole turtl account for offline
backuping.


Installation
------------

You can instal ``turtl-backup`` using pip::

  pip install turtl-backup


Usage
-----

Here's the usage::

  usage: turtl-backup [-h] server dest

  Backup a turtl account.

  positional arguments:
    server      Your turtle server
    dest        Destination file, where your notes will be stored encrypted

  optional arguments:
    -h, --help  show this help message and exit

So typically::

  turtl-backup https://api.framanotes.org turtl.backup

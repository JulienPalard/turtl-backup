"""Backups a turtl account.

Backups are downloaded encrypted so they can be archived safely.
"""

from base64 import b64encode
from getpass import getpass
from hashlib import pbkdf2_hmac, sha256
from urllib.parse import urljoin

import requests

from turtl_backup import tcrypt
from turtl_backup.turtl import Turtl


def parse_args():
    """Parses command line arguments.
    """
    import argparse
    parser = argparse.ArgumentParser(
        description='Backup a turtl account.')
    subparsers = parser.add_subparsers(
        help="Backup can be done with a login/password pair or "
        "using an auth token.")
    backup = subparsers.add_parser(
        'backup',
        help='Backup a turtl account (with a password or an auth token)')
    backup.set_defaults(subparser='backup')
    get_auth_token = subparsers.add_parser(
        'get_auth_token',
        help='Get a turtl auth token')
    get_auth_token.set_defaults(subparser='get_auth_token')
    backup.add_argument(
        '--auth-token',
        help="Use this auth token, instead of typing login/password.")
    backup.add_argument(
        'server', help='Your turtle server API, '
        'like "https://api.framanotes.org"')
    backup.add_argument(
        'dest',
        help='Destination file, where your notes will be stored encrypted')
    export = subparsers.add_parser(
        'export',
        help='Decrypt and export all notes in the given directory.')
    export.add_argument('backup_file',
                        help='Backup file to decrypt.')
    export.add_argument('export_directory',
                        help='Root directory for exported notes')
    export.set_defaults(subparser='export')
    args = parser.parse_args()
    if not hasattr(args, 'subparser'):
        parser.print_help()
        exit(1)
    return args


def get_key(username, password):
    """Build the symmetric encryption key with the given user and passord.
    """
    return pbkdf2_hmac('sha256',
                       password.encode(),
                       sha256(username.encode()).hexdigest().encode(),
                       100000, 32)


def get_auth(username, password, version=tcrypt.VERSION):
    """Get a authorization token for the given username and
    password, which is:

    login:password encrypted using AES-GCM with a key derived from the
    actual password salted with the sha256 of the login.
    """
    seed = sha256((password + username).encode('utf8')).hexdigest()
    user_record = (sha256(password.encode('utf8')).hexdigest() + ':' +
                   sha256(username.encode('utf8')).hexdigest())
    auth_iv = seed[:16].encode()
    utf8_random = int(user_record[18:20], 16) / 256
    key = get_key(username, password)
    desc = tcrypt.encode_payload_description()
    formatted = tcrypt.serialize(b'', version, desc, auth_iv)
    _, cipher, tag = tcrypt.encrypt(key, user_record.encode(), utf8_random,
                                    auth_iv, formatted)
    return b64encode(formatted + cipher + tag)


def build_basic_auth(auth_token):
    """Forge a basic auth header from a turtl auth token.
    """
    return 'Basic ' + b64encode(b'user:' + auth_token).decode()


def main():
    """Module entry point.
    """
    args = parse_args()
    if args.subparser == 'get_auth_token':
        print(get_auth(input('username: '), getpass('password: ')).decode())
        exit(0)
    if args.subparser == 'export':
        turtl = Turtl.from_file(args.backup_file)
        turtl.master_key = get_key(input('username: '), getpass('password: '))
        turtl.save_all_notes(args.export_directory)
        exit(0)
    if args.subparser == 'backup':
        if args.auth_token:
            auth = args.auth_token.encode()
        else:
            auth = get_auth(input('username: '), getpass('password: '))
        basic_auth = build_basic_auth(auth)
        response = requests.get(urljoin(args.server, '/sync/full'),
                                headers={'authorization': basic_auth})
        with open(args.dest, 'w') as dest:
            dest.write(response.text)


if __name__ == '__main__':
    main()

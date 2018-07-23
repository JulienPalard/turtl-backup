"""Backups a turtl account.

Backups are downloaded encrypted so they can be archived safely.
"""

import json
import os
from base64 import b64encode
from getpass import getpass
from hashlib import pbkdf2_hmac, sha256
from pathlib import Path
from urllib.parse import urljoin

import requests

from turtl_backup import tcrypt
from turtl_backup.turtl import Turtl


def parse_args():
    """Parses command line arguments.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Backup a turtl account.")
    subparsers = parser.add_subparsers(
        help="Backup can be done with a login/password pair or " "using an auth token."
    )
    backup_parser = subparsers.add_parser(
        "backup", help="Backup a turtl account (with a password or an auth token)"
    )
    backup_parser.set_defaults(subparser="backup")
    get_auth_token_parser = subparsers.add_parser(
        "get_auth_token", help="Get a turtl auth token"
    )
    get_auth_token_parser.set_defaults(subparser="get_auth_token")
    backup_parser.add_argument(
        "--auth-token", help="Use this auth token, instead of typing login/password."
    )
    backup_parser.add_argument(
        "server", help="Your turtle server API, " 'like "https://api.framanotes.org"'
    )
    backup_parser.add_argument(
        "dest", help="Destination file, where your notes will be stored encrypted"
    )
    decrypt_parser = subparsers.add_parser(
        "decrypt", help="Decrypt all notes in the given directory."
    )
    decrypt_parser.add_argument("backup_file", help="Backup file to decrypt.")
    decrypt_parser.add_argument(
        "decrypt_directory", help="Root directory for decrypted notes"
    )
    decrypt_parser.set_defaults(subparser="decrypt")
    export = subparsers.add_parser("export", help="Export all notes to markdown.")
    export.add_argument(
        "backup_directory",
        help="Backup directory containings decrypted notes to export.",
    )
    export.add_argument("export_directory", help="Root directory for markdown notes")
    export.set_defaults(subparser="export")
    args = parser.parse_args()
    if not hasattr(args, "subparser"):
        parser.print_help()
        exit(1)
    return args


def get_key(username, password):
    """Build the symmetric encryption key with the given user and passord.
    """
    return pbkdf2_hmac(
        "sha256",
        password.encode(),
        sha256(username.encode()).hexdigest().encode(),
        100000,
        32,
    )


def get_auth(username, password, version=tcrypt.VERSION):
    """Get a authorization token for the given username and
    password, which is:

    login:password encrypted using AES-GCM with a key derived from the
    actual password salted with the sha256 of the login.
    """
    seed = sha256((password + username).encode("utf8")).hexdigest()
    user_record = (
        sha256(password.encode("utf8")).hexdigest()
        + ":"
        + sha256(username.encode("utf8")).hexdigest()
    )
    auth_iv = seed[:16].encode()
    utf8_random = int(user_record[18:20], 16) / 256
    key = get_key(username, password)
    desc = tcrypt.encode_payload_description()
    formatted = tcrypt.serialize(b"", version, desc, auth_iv)
    _, cipher, tag = tcrypt.encrypt(
        key, user_record.encode(), utf8_random, auth_iv, formatted
    )
    return b64encode(formatted + cipher + tag)


def build_basic_auth(auth_token):
    """Forge a basic auth header from a turtl auth token.
    """
    return "Basic " + b64encode(b"user:" + auth_token).decode()


def get_auth_token():
    print(get_auth(input("username: "), getpass("password: ")).decode())


def decrypt(args):
    turtl = Turtl.from_file(args.backup_file)
    user = input("username: ")
    password = getpass("password: ")
    turtl.master_key = get_key(user, password)
    try:
        turtl.save_all_notes(args.decrypt_directory)
    except Exception as e:
        print("Cannot decrypt :(")
        print(e)


def fetch_backup(auth, server, path="sync/full"):
    basic_auth = build_basic_auth(auth)
    url = urljoin(server, path)
    headers = {"Authorization": basic_auth}
    return requests.get(url, headers=headers)


def backup(args):
    if args.auth_token:
        auth = args.auth_token.encode()
    else:
        auth = get_auth(input("username: "), getpass("password: "))
    response = fetch_backup(auth, args.server)
    with open(args.dest, "w") as dest:
        dest.write(response.text)


def to_markdown(backup_directory, export_directory):
    """Converts turtl backup json files from backup_directory to markdown
    in export_directory.
    """
    os.makedirs(export_directory, mode=0o700, exist_ok=True)
    for note_path in Path(backup_directory).glob("*.json"):
        with open(note_path) as note:
            json_note = json.load(note)
            filename = json_note["title"].replace("/", "-") + ".md"
            with open(os.path.join(export_directory, filename), "w") as md_note:
                for key, value in json_note.items():
                    if key == "text":
                        continue
                    md_note.write(f"{key}: {value}\n")
                md_note.write("\n")
                md_note.write(json_note["text"])


def main():
    """Module entry point.
    """
    args = parse_args()
    action = args.subparser
    if action == "get_auth_token":
        get_auth_token()
    elif action == "decrypt":
        decrypt(args)
    elif action == "backup":
        backup(args)
    elif action == "export":
        to_markdown(args.backup_directory, args.export_directory)


if __name__ == "__main__":
    main()

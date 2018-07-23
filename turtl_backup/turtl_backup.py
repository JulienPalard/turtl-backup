"""Backups a turtl account.

Backups are downloaded encrypted so they can be archived safely.
"""

import argparse
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


def parse_args() -> argparse.Namespace:
    """Parses command line arguments.
    """

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
        "json_dest_file", help="Destination file, where your notes will be stored encrypted"
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


def get_key(username: str, password: str) -> bytes:
    """Build the symmetric encryption key with the given user and passord.
    """
    return pbkdf2_hmac(
        "sha256",
        password.encode("utf8"),
        sha256(username.encode("utf8")).hexdigest().encode("utf8"),
        100000,
        32,
    )


def get_auth(username: str, password: str, version=tcrypt.VERSION) -> bytes:
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


def build_basic_auth(auth_token: bytes) -> str:
    """Forge a basic auth header from a turtl auth token.
    """
    return "Basic " + b64encode(b"user:" + auth_token).decode()


def get_auth_token() -> None:
    """Interactively ask a user for a username and password, prints an
    auth token.
    """
    print(get_auth(input("username: "), getpass("password: ")).decode())


def decrypt(backup_file: str, decrypt_directory: str) -> None:
    """Decrypt a given json file to a directory.
    """
    turtl = Turtl.from_file(backup_file)
    user = input("username: ")
    password = getpass("password: ")
    turtl.master_key = get_key(user, password)
    turtl.save_all_notes(decrypt_directory)


def fetch_backup(
    auth: bytes, server: str, path: str = "sync/full"
) -> requests.Response:
    basic_auth = build_basic_auth(auth)
    url = urljoin(server, path)
    headers = {"Authorization": basic_auth}
    return requests.get(url, headers=headers)


def backup(json_dest_file: str, server: str, auth_token: str = None) -> None:
    """Backup a turtl backup (interactively asking for login/password if
    not given an auth token).
    """
    if auth_token:
        auth = auth_token.encode()
    else:
        auth = get_auth(input("username: "), getpass("password: "))
    response = fetch_backup(auth, server)
    with open(json_dest_file, "w") as dest:
        dest.write(response.text)


def to_markdown(backup_directory: str, export_directory: str) -> None:
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
                    md_note.write("{key}: {value}\n".format(key=key, value=value))
                md_note.write("\n")
                md_note.write(json_note["text"])


def main() -> None:
    """Module entry point.
    """
    args = parse_args()
    action = args.subparser
    if action == "get_auth_token":
        get_auth_token()
    elif action == "decrypt":
        decrypt(args.backup_file, args.backup_directory)
    elif action == "backup":
        backup(args.json_dest_file, args.server, args.auth_token)
    elif action == "export":
        to_markdown(args.backup_directory, args.export_directory)


if __name__ == "__main__":
    main()

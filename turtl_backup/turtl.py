"""Mimics the turtl logic, oriented towards deciphering notes and
saving them to a hierarchy of files (exporting).
"""

import json
import os
from base64 import b64decode
from collections import defaultdict

from turtl_backup import tcrypt


def _try_to_decode(some_bytes):
    """Don't know why some turtl notes are in latin1.
    """
    try:
        return some_bytes.decode('utf8')
    except UnicodeDecodeError:
        return some_bytes.decode('latin1')


class Turtl:
    """Mimics the turtl logic, with the ability to load from an encrypted
    json backup, and dumps to a file hierarchy.
    """
    def __init__(self, records, master_key=''):
        self.master_key = master_key
        self.records_by_type = defaultdict(dict)
        for record in records:
            assert record['action'] == 'add'  # Is there something else?
            self.records_by_type[record['type']][record['item_id']] = record
        self.keychains = defaultdict(dict)
        for keychain in self.records_by_type['keychain'].values():
            self.keychains[keychain['data']['type']][
                keychain['data']['item_id']] = keychain

    @classmethod
    def from_file(cls, file_name):
        """Create a Turtl instance from a json backup file.
        """
        with open(file_name) as backup_file:
            return cls(json.load(backup_file)['records'])

    def key_for_note(self, note):
        """A key for a note may be in a board, I think, but I did not
        implemented it.
        """
        keychain = self.keychains['note'][note['item_id']]
        key = json.loads(tcrypt.decrypt(
            self.master_key, keychain['data']['body']).decode())
        return b64decode(key['k'])

    def decrypt_note(self, note):
        """Decrypt a given note object, give it as a json object.
        """
        key = self.key_for_note(note)
        return json.loads(_try_to_decode(tcrypt.decrypt(
            key, note['data']['body'])))

    def save_all_notes(self, root_directory):
        """Decrypt and save all notes as a file hierarchy under the given
        root_directory.
        """
        for note in self.records_by_type['note'].values():
            note_json = os.path.join(root_directory, note['item_id'] + '.json')
            with open(note_json, 'w') as note_json_file:
                json.dump(self.decrypt_note(note),
                          note_json_file,
                          indent=4)

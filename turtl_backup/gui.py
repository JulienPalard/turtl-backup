"""Here's a graphical user interface for the turtl-backup tool.
"""

import os
from datetime import date
import tkinter as tk
import tkinter.filedialog as tkFileDialog
import tkinter.messagebox as tkMessageBox
from urllib.parse import urljoin

import requests
from turtl_backup import turtl_backup


class TurtlBackupGUI(tk.Frame):
    """GUI to backup a Turtl account.
    """
    def __init__(self, master=None):
        super().__init__(master)
        self.pack()
        self.create_widgets()


    def create_widgets(self):
        """Creates the Layout, like:

           Server:   [...]
           User:     [...]
           Password: [...]
             [BACKUP]
        """
        tk.Label(self, text="Server:").grid(row=0, sticky=tk.W)
        tk.Label(self, text="User:").grid(row=1, sticky=tk.W)
        tk.Label(self, text="Password:").grid(row=2, sticky=tk.W)

        self.entry_server = tk.Entry(self)
        self.entry_server.insert(0, 'https://api.')
        self.entry_user = tk.Entry(self)
        self.entry_password = tk.Entry(self, show='*')

        self.entry_server.grid(row=0, column=1)
        self.entry_user.grid(row=1, column=1)
        self.entry_password.grid(row=2, column=1)

        self.save_btn = tk.Button(self, text="Backup", command=self.save)
        self.save_btn.grid(row=3, columnspan=3)

    def save(self):
        """Query turtl server and save backup as file.
        """
        server = self.entry_server.get()
        username = self.entry_user.get()
        password = self.entry_password.get()
        auth = turtl_backup.get_auth(username, password)
        basic_auth = turtl_backup.build_basic_auth(auth)
        try:
            response = requests.get(urljoin(server, '/sync/full'),
                                    headers={'authorization': basic_auth})
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            tkMessageBox.showerror("Error", str(err), parent=self)
            return
        savedialog = tkFileDialog.SaveAs(
            parent=self,
            defaultextension=".json")
        filename = savedialog.show(
            initialdir=os.path.expanduser('~/'),
            initialfile='turtl-backup-{:%Y-%m-%d}.json'.format(
                date.today()))
        with open(filename, 'w') as dest:
            dest.write(response.text)
        tkMessageBox.showinfo("Success", "Backup saved.", parent=self)
        self.quit()


def main():
    """turtl-backup-gui entry point.
    """
    root = tk.Tk()
    app = TurtlBackupGUI(master=root)
    app.mainloop()
    app.destroy()

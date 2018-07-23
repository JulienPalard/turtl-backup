import os
from pathlib import Path
from turtl_backup.turtl import Turtl
from turtl_backup import turtl_backup
import pytest


LOGIN = "testtest"
PASSWORD = "testtest"
FIXTURE_DIR = Path(os.path.join(os.path.dirname(os.path.realpath(__file__)), "data/"))


@pytest.fixture(autouse=True)
def requests_turtl(monkeypatch):
    def get(*args, **kwargs):
        mock = type("MockedReq", (), {})()
        with open(str(FIXTURE_DIR / "01.json")) as response:
            mock.text = response.read()
        return mock

    monkeypatch.setattr("requests.get", get)
    monkeypatch.delattr("requests.sessions.Session.request")


def test_decrypt(tmpdir):
    out = tmpdir.mkdir("backup_directory")
    turtl = Turtl.from_file(str(FIXTURE_DIR / "01.json"))
    turtl.master_key = turtl_backup.get_key(LOGIN, PASSWORD)
    turtl.save_all_notes(str(out))
    assert list(Path(str(out)).glob("*.json"))


def test_decrypt_from_main(mocker, tmpdir):
    backup_dir = Path(str(tmpdir.mkdir("backup_directory")))
    mocker.patch(
        "sys.argv",
        [
            "turtl-backup",
            "decrypt",
            "--login",
            LOGIN,
            "--password",
            PASSWORD,
            str(FIXTURE_DIR / "01.json"),
            str(backup_dir),
        ],
    )
    turtl_backup.main()
    assert list(Path(str(backup_dir)).glob("*.json"))


def test_export(tmpdir):
    backup_dir = Path(str(tmpdir.mkdir("backup_directory")))
    export_dir = Path(str(tmpdir.mkdir("export_directory")))
    turtl = Turtl.from_file(str(FIXTURE_DIR / "01.json"))
    turtl.master_key = turtl_backup.get_key(LOGIN, PASSWORD)
    turtl.save_all_notes(str(backup_dir))
    assert list(Path(str(backup_dir)).glob("*.json"))
    turtl_backup.to_markdown(str(backup_dir), str(export_dir))
    assert (export_dir / "Hello.md").exists()
    assert "world" in (export_dir / "Hello.md").read_text()


def test_help(mocker, capsys):
    mocker.patch("sys.argv", ["turtl-backup"])
    with pytest.raises(SystemExit):
        turtl_backup.main()
    captured = capsys.readouterr()
    assert "decrypt" in captured.out


def test_get_auth_token():
    assert turtl_backup.get_auth_token(LOGIN, PASSWORD)


def test_get_auth_token_from_main(capsys, mocker):
    mocker.patch(
        "sys.argv",
        ["turtl-backup", "get_auth_token", "--login", LOGIN, "--password", PASSWORD],
    )
    turtl_backup.main()
    captured = capsys.readouterr()
    assert len(captured.out) == 225


def test_get_basic_auth():
    assert "Basic" in turtl_backup.build_basic_auth(
        turtl_backup.get_auth_token(LOGIN, PASSWORD)
    )


def test_backup(tmpdir):
    tmpdir = Path(str(tmpdir))
    turtl_backup.backup(
        str(tmpdir / "backup.json"),
        "https://example.com",
        turtl_backup.get_auth_token(LOGIN, PASSWORD).decode(),
    )
    assert (tmpdir / "backup.json").exists()

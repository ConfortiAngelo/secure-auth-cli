from secure_auth import cli


def run_cli(monkeypatch, tmp_path, inputs, passwords):
    answers, secrets_ = iter(inputs), iter(passwords)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(secrets_))
    cli.main(["--db", str(tmp_path / "users.db")])


def test_menu_accepts_string_choices(monkeypatch, tmp_path, capsys):
    # v1 compared input() (a str) with the int 1, so no option ever worked.
    run_cli(monkeypatch, tmp_path, ["4"], [])
    assert "Bye." in capsys.readouterr().out


def test_register_then_login(monkeypatch, tmp_path, capsys):
    pw = "a-long-enough-password!"
    run_cli(monkeypatch, tmp_path, ["1", "alice", "2", "alice", "4"], [pw, pw, pw])
    out = capsys.readouterr().out
    assert "User registered." in out
    assert "Login successful." in out


def test_login_locks_after_three_failures(monkeypatch, tmp_path, capsys):
    run_cli(monkeypatch, tmp_path, ["2", "ghost", "4"], ["x1", "x2", "x3"])
    out = capsys.readouterr().out
    assert out.count("Invalid username or password") == 3
    assert "Too many failed attempts." in out

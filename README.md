# py-simple-sshd

`py-simple-sshd` is a compact SSH daemon implemented with Paramiko. It is meant
for cases where you need an embeddable, cross-platform SSH entry point that can
launch a configured local shell after public-key or password-file authentication.

## Installation

```bash
pip install py-simple-sshd
```

## Usage

```bash
simple-sshd \
  --host 0.0.0.0 \
  --port 2222 \
  --shell /bin/bash \
  --authorized-keys /etc/simple-sshd/authorized_keys
```

Use `--root` when the daemon and the shells it starts should run with
administrator/root privileges:

```bash
simple-sshd --root --host 0.0.0.0 --port 22 --shell /bin/bash --authorized-keys /etc/simple-sshd/authorized_keys
```

On Windows, errors printed in the elevated `--root` console pause briefly before
exit so the message remains visible.

`simple-sshd` is always single-user. Without `--root`, clients must authenticate
as the current operating-system username. With `--root`, clients must
authenticate as `root` on every platform, including Windows.

Password authentication is disabled unless `--password-file` is provided:

```bash
simple-sshd \
  --host 127.0.0.1 \
  --port 2222 \
  --shell /bin/bash \
  --authorized-keys ~/.ssh/authorized_keys \
  --password-file /etc/simple-sshd/password.txt
```

When both `--authorized-keys` and `--password-file` are configured, clients can
authenticate with either a listed public key or the password read from the file.
If `--password-file` is omitted, only public-key authentication is available.

On Windows, use a Windows shell path such as:

```powershell
simple-sshd --host 127.0.0.1 --port 2222 --shell C:\Windows\System32\cmd.exe --password-file .\password.txt
```

## Options

- `--host`: address to bind, default `127.0.0.1`
- `--port`: TCP port to bind, default `2222`
- `--shell`: shell executable launched for authenticated sessions
- `--authorized-keys`: OpenSSH `authorized_keys` file for public-key auth
- `--password-file`: text file whose content is accepted as the SSH password
- `--host-key`: private SSH host key; generated under `~/.simple-sshd` if omitted
- `--root`: relaunch the daemon with administrator/root privileges before serving
- `--log-level`: `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`
- `--log-file`: persistent log file, default `~/.simple-sshd/simple-sshd.log`

## Notes

- Password files are read as UTF-8 text. Trailing line endings are removed, while
  other whitespace is preserved.
- Host keys are persistent by default so clients can verify the server identity.
- Runtime listener, client, and channel errors are logged and isolated so one
  failing connection does not stop the daemon.
- The daemon rejects authentication attempts for any username other than its
  configured single login name.
- ANSI/VT escape sequences, including color, bold, cursor movement, clear-screen
  commands, and raw ESC input, are forwarded through the SSH channel. PTY
  sessions set `TERM` from the client's pty request so terminal-aware programs
  can enable their normal ANSI behavior.
- POSIX systems use a real pty for terminal sessions. Windows terminal sessions
  use `pywinpty`; non-pty sessions use standard process pipes.

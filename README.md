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

## Notes

- Password files are read as UTF-8 text. Trailing line endings are removed, while
  other whitespace is preserved.
- Host keys are persistent by default so clients can verify the server identity.
- POSIX systems use a real pty for terminal sessions. Windows terminal sessions
  use `pywinpty`; non-pty sessions use standard process pipes.

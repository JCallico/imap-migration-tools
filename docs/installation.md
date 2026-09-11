# Installation

## Requirements

- Python 3.10 or newer
- Network access to the relevant IMAP servers
- An app password or OAuth2 application registration for each account

Regular account passwords often do not work with Gmail, Outlook, or organizations that enforce multifactor
authentication. Prefer an app password where supported, or configure OAuth2.

## Install with pipx

`pipx` keeps command-line applications isolated from the system Python environment.

```bash
pipx install imap-migration-tools
```

The installed commands are:

```text
imap-backup
imap-compare
imap-count
imap-migrate
imap-restore
```

Automatic `.env` loading is included in the standard installation.

### macOS

```bash
brew install python pipx
pipx ensurepath
pipx install imap-migration-tools
```

### Linux

Install Python with your distribution package manager, then install pipx. On Ubuntu or Debian:

```bash
sudo apt-get update
sudo apt-get install python3 python3-venv pipx
pipx ensurepath
pipx install imap-migration-tools
```

Encrypted persistent OAuth2 token caching on Linux uses PyGObject and the system libsecret service. Install the native
build and runtime libraries before selecting the `linux-keyring` extra. On Ubuntu or Debian:

```bash
sudo apt-get install gcc libcairo2-dev libgirepository-2.0-dev pkg-config python3-dev gir1.2-secret-1
pipx install "imap-migration-tools[linux-keyring]"
```

Use your distribution's equivalent GObject introspection, Cairo, and libsecret packages on other Linux systems. If the
extra or encrypted secret service is unavailable, OAuth authentication continues with process-local token caching and
does not fall back to plaintext persistence.

### Windows

Install Python from [python.org](https://www.python.org/downloads/windows/) and enable **Add Python to PATH**. Then run
from PowerShell:

```powershell
py -m pip install --user pipx
py -m pipx ensurepath
pipx install imap-migration-tools
```

## Install in a virtual environment

On macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install imap-migration-tools
```

On Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install imap-migration-tools
```

On Windows Command Prompt:

```batch
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install imap-migration-tools
```

## Install from source

On macOS or Linux:

```bash
git clone https://github.com/JCallico/imap-migration-tools.git
cd imap-migration-tools
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
git clone https://github.com/JCallico/imap-migration-tools.git
Set-Location imap-migration-tools
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m pip install -r requirements.txt
```

On Windows Command Prompt:

```batch
git clone https://github.com/JCallico/imap-migration-tools.git
cd imap-migration-tools
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -e .
python -m pip install -r requirements.txt
```

Run source entry points with `PYTHONPATH=src` when the project is not installed:

```bash
PYTHONPATH=src .venv/bin/python src/imap_count.py --help
```

On Windows PowerShell:

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe src\imap_count.py --help
```

On Windows Command Prompt:

```batch
set PYTHONPATH=src
.venv\Scripts\python.exe src\imap_count.py --help
```

## `.env` support

Automatic `.env` discovery is included with the standard package. The former extra remains valid as a compatibility
alias for existing installation scripts, but is no longer required:

```bash
python -m pip install "imap-migration-tools[dotenv]"
```

Continue with [Configuration](configuration.md).

## Native desktop application

See [desktop setup](ui.md) for the optional `[ui]` extra, Linux prerequisites, and bundled application builds.

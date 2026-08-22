# Installation

## Requirements

- Python 3.9 or newer
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

### Windows

Install Python from [python.org](https://www.python.org/downloads/windows/) and enable **Add Python to PATH**. Then run
from PowerShell:

```powershell
py -m pip install --user pipx
py -m pipx ensurepath
pipx install imap-migration-tools
```

## Install in a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install imap-migration-tools
```

On Windows PowerShell, activate with:

```powershell
.venv\Scripts\Activate.ps1
```

## Install from source

```bash
git clone https://github.com/JCallico/imap-migration-tools.git
cd imap-migration-tools
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m pip install -r requirements.txt
```

Run source entry points with `PYTHONPATH=src` when the project is not installed:

```bash
PYTHONPATH=src .venv/bin/python src/imap_count.py --help
```

## `.env` support

Automatic `.env` discovery is included with the standard package. The former extra remains valid as a compatibility
alias for existing installation scripts, but is no longer required:

```bash
python -m pip install "imap-migration-tools[dotenv]"
```

Continue with [Configuration](configuration.md).

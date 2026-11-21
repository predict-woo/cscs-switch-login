# CSCS SWITCH edu-ID login

Sign in to `cscs-key` through SWITCH edu-ID without opening a browser. The
wrapper completes the CSCS device login while `cscs-key` handles token polling,
caching, and SSH certificate issuance.

## Setup

Install `uv` and put `cscs-key` on your PATH. The wrapper was tested with
`cscs-key` 1.2.0. [CSCS installation guide](https://docs.cscs.ch/access/ssh/#installation)

For unattended login, create a local `.env` with owner-only permissions.

```sh
install -m 600 .env.example .env
```

Fill in your SWITCH email address and password. If SWITCH requests TOTP, use
the Base32 setup secret from your authenticator enrollment. Environment
variables with the same names take precedence. The wrapper prompts for missing
values when it needs them.

## Usage

List your existing CSCS SSH certificates.

```sh
uv run --locked python cscs_login.py list
```

Sign your existing key and connect using your configured SSH alias.

```sh
uv run --locked python cscs_login.py sign --file ~/.ssh/cscs-key
ssh ela
```

The default command is `list`. A valid cached CLI token skips the SWITCH login.
If the login page changes, run `cscs-key --headless list` to sign in manually.

## Tests

```sh
uv run --locked python -m unittest -v
```

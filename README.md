# Raven

Raven is the TAK (Team Awareness Kit) server behind [C4 Raven](https://tak.c4raven.net) —
a security-hardened fork of [OpenTAKServer](https://github.com/brian7704/OpenTAKServer),
paired with the [Raven UI](https://github.com/C4Raven/c4raven-ui) frontend.

## Current Features

- Connect via TCP from ATAK, WinTAK, iTAK, TAKAware, TAKX, CloudTAK, and PyTAK
- SSL
- Authentication, including mandatory 2FA, forced password resets, and
  per-account web UI access revocation
- [WebUI with a live map](https://github.com/C4Raven/c4raven-ui)
- Client certificate enrollment
- Groups/Channels
- LDAP/Active Directory
- ATAK Plugin Update Server
- Send and receive messages
- Send and receive points
- Send and receive routes
- Send and receive images
- Share location with other users
- Save CoT messages to a database
- Data Packages
- Alerts
- CasEvac
- Optional Mumble server authentication
  - Use your Raven username and password to log into your Mumble server
- Video Streaming
- Mission API
  - Data Sync plugin
  - Fire Area Survey plugin
- Federation Hub admin proxy — see [Federation Hub integration](#federation-hub-integration)

## Requirements

- RabbitMQ
- MediaMTX (only required for video streaming)
- openssl
- nginx

## Installation

See [c4raven-server-setup](https://github.com/C4Raven/c4raven-server-setup)
for a fresh install, or [c4raven-updater](https://github.com/C4Raven/c4raven-updater)
to update an existing one in place.

## Architecture

Three separate processes run from this same package, each with its own
`poetry` entry point:

| Entry point | What it runs |
| --- | --- |
| `raven` | The main Flask/SocketIO app — the REST API the UI talks to, the web login flow, and everything under `raven/blueprints/`. |
| `eud_handler` | Accepts TCP/SSL connections from ATAK/WinTAK/iTAK devices and other CoT clients. |
| `cot_parser` | Consumes CoT messages off RabbitMQ and persists them (points, routes, alerts, CasEvac, etc.) via the models in `raven/models/`. |

All three read the same `config.yml` and share the same database via
SQLAlchemy models. Database schema changes go through Alembic migrations in
`raven/migrations/versions/` — the app runs pending migrations itself on
startup, there's no separate manual migration step in normal operation.

Feature areas live under `raven/blueprints/raven_api/` as one file per
concern (`user_api.py`, `group_api.py`, `mission_api.py`, `mediamtx_api.py`,
and so on), each registered into a single aggregate `raven_api` blueprint in
that package's `__init__.py`. Non-web pieces have their own top-level
packages: `eud_handler/`, `cot_parser/`, `mumble/` (optional Mumble server
auth bridge), `maps/`, `plugins/` (ATAK plugin update server), and `forms/`
for WTForms-based validation shared across endpoints.

### Federation Hub integration

`raven/blueprints/raven_api/federation_hub_api.py` proxies Federation Hub's
own admin REST API (connections, broker metrics, CA trust groups,
federations/policy) so the [Raven UI's Federation Hub
tab](https://github.com/C4Raven/c4raven-ui/tree/master/docs/federation-hub)
can manage it with just a normal Raven admin login. Federation Hub's native
console requires an mTLS client certificate for every request; this blueprint
holds that certificate on the server side (configured via
`RAVEN_FEDHUB_*` settings in `defaultconfig.py`) and makes the calls on the
logged-in admin's behalf, so browsers never need that certificate imported
just to check on federation status. It also serves that client certificate
itself, 2FA-gated, for the cases that still need the native console directly
(see [federation-hub-setup](https://github.com/C4Raven/federation-hub-setup)
for what that console actually looks like, and the one login bug in it this
proxy exists to route around).

## Development

Dependencies and packaging are managed with [Poetry](https://python-poetry.org/):

```
poetry install
poetry run raven          # start the main app
poetry run eud_handler     # start the EUD/CoT TCP listener, separately
poetry run cot_parser      # start the CoT persistence worker, separately
```

Tests run with `pytest` (configured in `pyproject.toml` to also produce
coverage reports):

```
poetry run pytest
```

## Credits

Raven is a fork of [OpenTAKServer](https://github.com/brian7704/OpenTAKServer)
by Brian (brian7704) and contributors, licensed GPL-3.0-or-later. The upstream
project's [Discord server](https://discord.gg/6uaVHjtfXN) is a good place for
general OpenTAKServer/TAK questions not specific to this fork.

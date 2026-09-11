# Raven

Raven is the TAK (Team Awareness Kit) server behind [C4 Raven](https://tak.c4raven.net) —
a security-hardened fork of [the upstream project](https://github.com/brian7704/OpenTAKServer)
this is derived from, paired with the [Raven UI](https://github.com/C4Raven/c4raven-ui) frontend.

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
- Reports (WinTAK/ATAK's CITrap tool), including live push notification of
  new reports to subscribed clients
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

### Groups and visibility

Whether user A's CoT (position, messages) reaches user B is entirely a
function of shared `GroupUser` rows (`raven/models/GroupUser.py`) — there's
no separate friends/contacts list. Each row has a `direction`: `IN` means
that user's traffic is published into the group, `OUT` means they receive
what's published to it. A's data reaches B whenever some group has A with
`IN` and B with `OUT` — see `route_cot` in `raven/blueprints/raven_api/api.py`
and its equivalent in `raven/cot_parser/cot_parser.py` for where this is
actually applied to routing.

Three kinds of group all feed into that same mechanism:

- **Named groups** (`raven/blueprints/raven_api/group_api.py`'s
  `add_group`/`add_user_to_group`) — what admins manage on the Groups page:
  a real, visible group with its own name, that any number of users can be
  added to with an explicit direction each.
- **Pairwise groups** — auto-created by the "Who Can See Whom" visibility
  diagram in each group's edit modal on the Groups page
  (`get_user_visibility`/`set_user_visibility` in `group_api.py`) when an
  admin connects two specific users without wanting a whole named group for
  just that pair. Named `__uv__<userA>__<userB>` (usernames sorted, see
  `PAIRWISE_PREFIX`/`_pairwise_group_name`), with both directions on both
  users for a mutual ("solid") connection, or one user `IN`-only and the
  other `OUT`-only for a one-way ("dotted") one. These are meant to be
  managed only through the diagram's connect/disconnect actions (each one's
  `description` says as much), but they're ordinary `GroupUser` rows like
  any other — visible and, if truly necessary, editable the same way.
- **`__ANON__`** — the one default every new user gets automatically
  (`_add_to_anon_group` in `user_api.py`'s `create_user`, and the
  `user_registered` signal handler in `app.py` for self-registration): both
  directions, so new users can see and be seen by each other without an
  admin connecting them first. It's also cot_parser's fallback destination
  for a sender with no `IN` group at all. This only applies going forward —
  accounts created before this existed were never retroactively added, so
  two older accounts can still have zero overlap and be invisible to each
  other until an admin connects them one of the ways above.

Federation Hub visibility works the same way: `RAVEN_FEDHUB_FEDERATE_GROUP`
("Fed group" by default) is just a named group like any other, and the
protected `Server` account (`RAVEN_FEDHUB_FEDERATE_USERNAME`) that inbound
federated CoT gets attributed to needs `IN` membership in it for that CoT to
reach anyone. `create_default_groups` in `app.py` bootstraps the group, the
`Server` account, and that membership automatically on startup — see
[Federation Hub integration](#federation-hub-integration) below for the rest
of that pipeline.

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

Raven is a fork of [the upstream project](https://github.com/brian7704/OpenTAKServer)
by Brian (brian7704) and contributors, licensed GPL-3.0-or-later. The upstream
project's [Discord server](https://discord.gg/6uaVHjtfXN) is a good place for
general upstream/TAK questions not specific to this fork.

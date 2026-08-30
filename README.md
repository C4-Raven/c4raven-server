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

## Requirements

- RabbitMQ
- MediaMTX (only required for video streaming)
- openssl
- nginx

## Installation

See [c4raven-server-setup](https://github.com/C4Raven/c4raven-server-setup)
for a fresh install, or [c4raven-updater](https://github.com/C4Raven/c4raven-updater)
to update an existing one in place.

## Credits

Raven is a fork of [OpenTAKServer](https://github.com/brian7704/OpenTAKServer)
by Brian (brian7704) and contributors, licensed GPL-3.0-or-later. The upstream
project's [Discord server](https://discord.gg/6uaVHjtfXN) is a good place for
general OpenTAKServer/TAK questions not specific to this fork.

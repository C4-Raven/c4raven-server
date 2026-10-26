# Vendored wheels

`adsbxcot` and `aiscot` were deleted from PyPI (both projects return 404
as of October 2026), so `poetry install` could no longer resolve them and
every fresh install failed. These are the exact wheels the lock pinned
before, checksums unchanged:

| Wheel | sha256 |
|---|---|
| `adsbxcot-6.0.4-py3-none-any.whl` | `5f134f502d18c1cb40bd23be37863c0b42edc081221fb623e8f65f7857313148` |
| `aiscot-7.0.10-py3-none-any.whl` | `91fbdfe8502ae98cb677c5e80190eccf359a665037e92f91af8a7bfd88380e28` |

pyproject.toml refers to them as path dependencies. Their own
dependencies (`pytak`, `aircot`, `aiohttp`) are still on PyPI.

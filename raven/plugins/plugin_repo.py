"""Which package index the plugin manager installs plugins from.

No repository is configured by default (RAVEN_PLUGIN_REPO = ""). Until an
operator sets one, installs by package name are refused and only uploaded
plugin files can be installed.

The RAVEN_PLUGIN_REPO environment variable, when set to a non-empty value,
takes precedence over config.yml. config.yml is written once on first run and
loaded over the defaults on every start after that, so without this an
operator who exports the variable later would still be refused.
"""

import os

NO_PLUGIN_REPO_MESSAGE = (
    "No plugin repository configured; set RAVEN_PLUGIN_REPO in config.yml or the environment"
)


def get_plugin_repo(config) -> str:
    """Return the plugin repository URL, or "" when none is set."""
    env_repo = os.environ.get("RAVEN_PLUGIN_REPO", "").strip()
    if env_repo:
        return env_repo
    repo = config.get("RAVEN_PLUGIN_REPO") or ""
    if not isinstance(repo, str):
        return ""
    return repo.strip()

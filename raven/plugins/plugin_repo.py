"""Which package index the plugin manager installs plugins from.

No repository is configured by default (RAVEN_PLUGIN_REPO = ""). Until an
operator sets one, installs by package name are refused and only uploaded
plugin files can be installed.
"""

NO_PLUGIN_REPO_MESSAGE = "No plugin repository configured; set RAVEN_PLUGIN_REPO"


def get_plugin_repo(config) -> str:
    """Return the configured plugin repository URL, or "" when none is set."""
    repo = config.get("RAVEN_PLUGIN_REPO") or ""
    if not isinstance(repo, str):
        return ""
    return repo.strip()

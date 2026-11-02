"""
Where MediaMTX recordings live, and the one check every code path that opens or deletes a
recording file goes through.

video_recordings.segment_path comes from the MediaMTX webhook (/api/mediamtx/webhook), which is
only protected by a shared token. A forged segment_path must never let the retention job or the
admin "delete recording" endpoint remove a file outside the recordings folder, so the webhook
refuses such paths and the delete paths check again before removing anything.

MediaMTX writes recordings to RAVEN_DATA_FOLDER/mediamtx/recordings/%path/... (recordPath in
mediamtx.yml, OTS_FOLDER is the data folder).
"""

import os

from flask import current_app as app


def recordings_folder() -> str:
    return os.path.realpath(
        os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "mediamtx", "recordings")
    )


def contained_recording_path(path) -> str | None:
    """path resolved (symlinks included) if it is strictly inside the recordings folder,
    otherwise None."""
    if not path or not isinstance(path, str) or "\x00" in path:
        return None
    try:
        folder = recordings_folder()
        resolved = os.path.realpath(path)
    except (OSError, ValueError, TypeError):
        return None
    if resolved == folder or os.path.commonpath([folder, resolved]) != folder:
        return None
    return resolved

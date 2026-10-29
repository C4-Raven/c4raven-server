"""
Tests for the browser copy of MPEG-TS-over-RTSP streams (mediamtx_api.start_web_copy).

TAK ICU publishes RTSP with one MPEG-TS track, which MediaMTX can't serve over WebRTC or HLS.
Raven copies the video out of it to <path>_raven_web and points the browser links there.
"""

from unittest import mock

import pytest
from flask import Flask

from raven.blueprints.raven_api import mediamtx_api
from raven.blueprints.raven_api.mediamtx_api import WEB_COPY_SUFFIX, start_web_copy
from raven.defaultconfig import DefaultConfig
from raven.models.VideoStream import VideoStream


@pytest.fixture
def app():
    app = Flask("raven-test")
    app.config.from_object(DefaultConfig)
    with app.app_context():
        yield app


def _tracks(tracks):
    response = mock.Mock()
    response.json.return_value = {"name": "live/VIDEO_1", "ready": True, "tracks": tracks}
    return response


def test_mpegts_stream_gets_a_web_copy(app):
    with mock.patch.object(mediamtx_api.requests, "get", return_value=_tracks(["MPEG-TS"])), \
            mock.patch.object(mediamtx_api.subprocess, "Popen") as popen:
        assert start_web_copy("live/VIDEO_1", "8554") == "live/VIDEO_1" + WEB_COPY_SUFFIX

    command = popen.call_args.args[0]
    assert command[0] == "ffmpeg"
    assert "rtsp://127.0.0.1:8554/live/VIDEO_1" in command
    assert command[-1] == "rtsp://127.0.0.1:8554/live/VIDEO_1" + WEB_COPY_SUFFIX
    # Copies, never re-encodes, and drops the KLV data track
    assert command[command.index("-c") + 1] == "copy"
    assert "0:v" in command and "0:d" not in command
    assert popen.call_args.kwargs["start_new_session"] is True


@pytest.mark.parametrize("tracks", [["H264"], ["H264", "MPEG-4 Audio"], ["H265"], [], None])
def test_playable_streams_get_no_copy(app, tracks):
    with mock.patch.object(mediamtx_api.requests, "get", return_value=_tracks(tracks)), \
            mock.patch.object(mediamtx_api.subprocess, "Popen") as popen:
        assert start_web_copy("obs", 8554) is None
    popen.assert_not_called()


def test_api_failure_starts_nothing(app):
    with mock.patch.object(mediamtx_api.requests, "get", side_effect=OSError("down")), \
            mock.patch.object(mediamtx_api.subprocess, "Popen") as popen:
        assert start_web_copy("live/VIDEO_1", 8554) is None
    popen.assert_not_called()


def test_ffmpeg_missing_returns_none(app):
    with mock.patch.object(mediamtx_api.requests, "get", return_value=_tracks(["MPEG-TS"])), \
            mock.patch.object(mediamtx_api.subprocess, "Popen", side_effect=FileNotFoundError):
        assert start_web_copy("live/VIDEO_1", 8554) is None


def test_webhook_ignores_the_copy_path(app):
    app.config["RAVEN_MEDIAMTX_TOKEN"] = "tok"
    with app.test_request_context(
        "/api/mediamtx/webhook",
        query_string={
            "token": "tok",
            "event": "ready",
            "rtsp_port": "8554",
            "path": "live/VIDEO_1" + WEB_COPY_SUFFIX,
        },
    ), mock.patch.object(mediamtx_api, "db") as db:
        assert mediamtx_api.mediamtx_webhook() == ("", 200)
    db.session.query.assert_not_called()


def test_links_use_the_web_copy(app):
    stream = VideoStream(path="live/VIDEO_1", port=8554, mediamtx_settings="")
    with app.test_request_context("/", base_url="https://tak.example"):
        links = stream.to_json()
        assert links["webrtc_link"] == "https://tak.example:443/webrtc/live/VIDEO_1/"

        stream.web_path = "live/VIDEO_1" + WEB_COPY_SUFFIX
        links = stream.to_json()
        assert links["webrtc_link"] == f"https://tak.example:443/webrtc/live/VIDEO_1{WEB_COPY_SUFFIX}/"
        assert links["hls_link"] == f"https://tak.example:443/hls/live/VIDEO_1{WEB_COPY_SUFFIX}/"
        # RTSP (ATAK) keeps reading the original
        assert links["rtsp_link"] == "rtsp://tak.example:8554/live/VIDEO_1"

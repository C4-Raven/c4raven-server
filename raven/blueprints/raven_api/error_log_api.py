"""
Admin view of warnings/errors from the server's log files.

Every Raven process writes a TimedRotatingFileHandler log into <RAVEN_DATA_FOLDER>/logs/
(raven.log, cot_parser.log, eud_handler_ssl.log, fedhub_bridge.log, ...) with the format

    [2026-10-31 11:02:03,456] - Raven[1234] - module - funcName - 42 - ERROR - message

and multi-line messages / tracebacks on the following lines. The systemd units also append the
processes' stdout/stderr to a file in the same folder (opentakserver.log on the legacy layout,
raven.log on the /opt/raven layout), so crashes that happen before logging is set up, and
uncaught tracebacks printed by Python, end up in these files as lines without the header.
Those become "raw" entries (timestamp/pid/line null, level from Python's "LEVEL:logger:"
prefix or guessed from the text) unless they continue a WARNING/ERROR entry. Stderr copies of the "Raven"
logger's own records are dropped as duplicates of the file records. Raw entries are ordered by
a timestamp interpolated by byte offset between the surrounding header lines (or the file's
mtime), so they sort roughly where they happened; it is only an estimate and is not returned.

Files are always read from the end in chunks with a byte budget per source, never whole.

Cursor: base64url JSON {"v": 1, "f": {source: [[inode, offset, crc], ...]}} with one triple for
every file (current and rotated) of every source at the time of the request. offset is the end
of the last complete line read, crc is a CRC32 of the file's first bytes (guards against inode
reuse). On a `since` poll each file is compared with the cursor: same inode and grown -> read
only the new bytes; shrunk or different head -> treat as a new file; inode not in the cursor ->
a new file (e.g. the fresh file after rotation) and is read from the start. Rotation renames
files, which keeps the inode, so it is handled naturally; so are processes that keep appending
to a file after it was rotated away (systemd's stdout append: does that).

Entry ids are "<source>:<inode>:<byte offset of the entry>", stable across rotation.
"""

import base64
import binascii
import json
import os
import re
import zlib
from datetime import datetime, timedelta

from flask import Blueprint, Response, jsonify, request
from flask import current_app as app
from flask_security import roles_accepted

error_log_api_blueprint = Blueprint("error_log_api_blueprint", __name__)

CHUNK_SIZE = 1024 * 1024
DEFAULT_MAX_BYTES_PER_SOURCE = 20 * 1024 * 1024
DEFAULT_DOWNLOAD_MAX_BYTES_PER_SOURCE = 100 * 1024 * 1024
HEAD_CRC_BYTES = 128
MAX_LIMIT = 5000

LEVELS = {
    "CRITICAL": ("CRITICAL",),
    "ERROR": ("ERROR", "CRITICAL"),
    "WARNING": ("WARNING", "ERROR", "CRITICAL"),
}

# <stem>.log, optionally followed by a TimedRotatingFileHandler suffix (2026-10-30,
# 2026-10-30_13, 2026-10-30_13-05, 2026-10-30_13-05-59) or a RotatingFileHandler ".N".
LOG_FILE_RE = re.compile(
    r"^(?P<stem>[A-Za-z0-9_.-]+?)\.log"
    r"(?P<suffix>\.\d{4}-\d{2}-\d{2}(?:_\d{2}(?:-\d{2}(?:-\d{2})?)?)?|\.\d+)?$"
)
SOURCE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

HEADER_RE = re.compile(
    rb"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d{1,6})?)\] - "
    rb"(?P<proc>[^\[\]\n]*)\[(?P<pid>\d+)\] - "
    rb"(?P<module>[^\n]*?) - (?P<func>[^\n]*?) - (?P<line>\d+) - "
    rb"(?P<level>[A-Z]+) - (?P<msg>.*)$"
)
# Cheap check used to find entry boundaries in raw chunks.
HEADER_START_RE = re.compile(rb"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", re.M)
# Lines that always start a new entry, so a chunk can safely begin there.
BOUNDARY_RE = re.compile(
    rb"^(?:\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}|(?:DEBUG|INFO|WARNING|ERROR|CRITICAL):[\w.\-]+:)",
    re.M,
)
# Lines like "INFO  [alembic.runtime.migration] ..." printed straight to stdout/stderr.
PLAIN_LEVEL_RE = re.compile(rb"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+\[")
# Python's default logging format, e.g. "ERROR:raven.app:Exception on /api/foo [GET]".
BASIC_FORMAT_RE = re.compile(rb"^(DEBUG|INFO|WARNING|ERROR|CRITICAL):([\w.\-]+):(.*)$")
# Loggers that also write to a log file with the full header (see raven.extensions.logger), so
# their stderr copies are duplicates. "OpenTAKServer" is the pre-rename logger name.
DUPLICATE_LOGGERS = {"Raven", "OpenTAKServer"}
SEPARATOR_RE = re.compile(rb"^-{20,}\s*$")
# Unindented lines that begin a new block of stderr output.
RECORD_START_RE = re.compile(
    rb"^(Traceback \(most recent call last\):|Exception ignored|Exception in thread|"
    rb"Exception occurred|Fatal Python error|Current thread|Segmentation fault)"
)
ERRORISH_RE = re.compile(
    r"Traceback \(most recent call last\)|Fatal Python error|Segmentation fault|"
    r"\b\w*(Error|Exception)\b|\bexception\b",
)
WARNINGISH_RE = re.compile(r"\b\w*Warning\b")


# ---------------------------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------------------------


def log_folder():
    return os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "logs")


def discover_files(folder):
    """{source: [file info, newest first]} for every *.log (+ rotated backups) in folder."""
    sources = {}
    try:
        names = os.listdir(folder)
    except OSError:
        return sources

    for name in names:
        match = LOG_FILE_RE.match(name)
        if not match:
            continue
        path = os.path.join(folder, name)
        try:
            st = os.stat(path)
        except OSError:
            continue
        if not os.path.isfile(path):
            continue
        sources.setdefault(match.group("stem"), []).append(
            {
                "path": path,
                "name": name,
                "current": match.group("suffix") is None,
                "ino": st.st_ino,
                "size": st.st_size,
                "mtime": st.st_mtime,
            }
        )

    for files in sources.values():
        # The live file first, then backups newest first.
        files.sort(key=lambda f: (not f["current"], -f["mtime"], f["name"]), reverse=False)
    return sources


def head_crc(fh, length):
    fh.seek(0)
    return zlib.crc32(fh.read(min(length, HEAD_CRC_BYTES)))


def complete_end(fh, size):
    """Offset just past the last newline at or before size (excludes a half-written line)."""
    if size <= 0:
        return 0
    pos = size
    while pos > 0:
        start = max(0, pos - 65536)
        fh.seek(start)
        data = fh.read(pos - start)
        idx = data.rfind(b"\n")
        if idx != -1:
            return start + idx + 1
        pos = start
        if size - pos > 1024 * 1024:
            # A single 1MB+ line without a newline: just take it all.
            return size
    return 0


# ---------------------------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------------------------


def _parse_ts(raw):
    """b"2026-10-31 11:02:03,456" -> naive local datetime (the format logging's asctime uses)."""
    try:
        dt = datetime(
            int(raw[0:4]), int(raw[5:7]), int(raw[8:10]),
            int(raw[11:13]), int(raw[14:16]), int(raw[17:19]),
        )
        if len(raw) > 20:
            dt = dt.replace(microsecond=int(raw[20:26].ljust(6, b"0")))
        return dt
    except ValueError:
        return None


def _decode(raw):
    return raw.decode("utf-8", errors="replace")


def _guess_level(text):
    if ERRORISH_RE.search(text):
        return "ERROR"
    if WARNINGISH_RE.search(text):
        return "WARNING"
    return "INFO"


def _is_indented_or_blank(line):
    return not line.strip() or line[:1] in (b" ", b"\t")


CHAIN_RE = re.compile(
    rb"^(During handling of the above exception|The above exception was the direct cause|"
    rb"Exception ignored|Exception in thread|Exception occurred|Fatal Python error)"
)


def _continues_block(block, line):
    lines = block["lines"]
    if block.get("separator") and len(lines) == 1:
        return True
    if not line.startswith(b"Traceback"):
        return False
    meaningful = [l for l in lines if l.strip()]
    if not any(l.startswith(b"Traceback") for l in lines):
        return True  # e.g. "ERROR:raven.app:Exception on /x [GET]" followed by its traceback
    return bool(meaningful) and CHAIN_RE.match(meaningful[-1]) is not None


def _new_entry(offset, line, header=None, level=None, logger_name=None, discard=False):
    return {
        "header": header,
        "level": level,
        "logger": logger_name,
        "discard": discard,
        "closed": False,
        "offset": offset,
        "lines": [line],
    }


def parse_entries(
    data, base_offset, source, file_info, levels=None, next_anchor=None, prev_anchor=None
):
    """
    Parse a byte buffer of complete lines into entries (oldest first).

    base_offset is the file offset of data[0]. If levels is given, entries with another level
    are dropped before most decoding work is done. next_anchor is (file offset, datetime) of
    the first timestamped point after the buffer (the next header, or end of file + mtime);
    it is used to estimate where untimestamped (raw) entries sort, together with prev_anchor,
    the last header before the buffer (or a callable returning it, only called if needed).

    Returns (entries, offset and raw timestamp bytes of the first header or None).
    """
    blocks = []
    current = None

    def push(block):
        if block is not None:
            blocks.append(block)

    offset = base_offset
    for line in data.split(b"\n"):
        line_offset = offset
        offset += len(line) + 1
        if line.endswith(b"\r"):
            line = line[:-1]

        header = HEADER_RE.match(line) if line[:1] == b"[" else None
        if header:
            push(current)
            current = _new_entry(
                line_offset, line, header=header, level=header.group("level").decode("ascii")
            )
            continue

        if current is None and not line.strip():
            continue

        # stdout/stderr captured by systemd: Python's default "LEVEL:logger:message" format,
        # alembic's "INFO  [alembic...]", uncaught tracebacks, warnings, crashes...
        basic = BASIC_FORMAT_RE.match(line)
        if basic:
            push(current)
            logger_name = _decode(basic.group(2))
            current = _new_entry(
                line_offset,
                line,
                level=basic.group(1).decode("ascii"),
                logger_name=logger_name,
                # The Raven logger also writes these to its own file with a full header, so the
                # stderr copy is a duplicate.
                discard=logger_name in DUPLICATE_LOGGERS,
            )
            continue
        plain = PLAIN_LEVEL_RE.match(line)
        if plain:
            push(current)
            current = _new_entry(line_offset, line, level=plain.group(1).decode("ascii"))
            continue

        if current is None:
            current = _new_entry(line_offset, line)
            if SEPARATOR_RE.match(line):
                current["separator"] = True
            continue

        is_raw = current["header"] is None
        level = current["level"]
        quiet = level in ("DEBUG", "INFO") or current["discard"]

        if SEPARATOR_RE.match(line):
            # socketserver wraps each traceback in dashed lines: open, ..., close.
            if is_raw and current.get("separator") and not current["closed"]:
                current["lines"].append(line)
                current["closed"] = True
            else:
                push(current)
                current = _new_entry(line_offset, line)
                current["separator"] = True
            continue

        if _is_indented_or_blank(line) and not current["closed"]:
            current["lines"].append(line)
            continue

        starts_record = RECORD_START_RE.match(line) is not None
        if starts_record and not quiet and not current["closed"]:
            # Part of the current block (the traceback for "Exception ignored in ...", a chained
            # exception, socketserver's message after its opening dashes...) or a new event?
            starts_record = not _continues_block(current, line)
        if current["closed"] or starts_record:
            push(current)
            current = _new_entry(line_offset, line)
            continue

        if not quiet:
            # A WARNING/ERROR record, or an untyped raw block (traceback, warning...): keep
            # collecting until the next record starts.
            current["lines"].append(line)
            continue

        # Non-indented line after an INFO/DEBUG record (or a dropped duplicate).
        if current["discard"] and len(current["lines"]) > 1 and current["lines"][-1][:1] in (b" ", b"\t"):
            # Final "SomeError: ..." line of the duplicate's traceback.
            current["lines"].append(line)
            current["closed"] = True
            continue
        if ERRORISH_RE.search(_decode(line)) or WARNINGISH_RE.search(_decode(line)) or current["discard"]:
            push(current)
            current = _new_entry(line_offset, line)
            continue
        current["lines"].append(line)
    push(current)

    # Timestamp anchors: every header, plus whatever comes after the buffer.
    anchors = [(b["offset"], b["header"].group("ts")) for b in blocks if b["header"] is not None]
    first_anchor = anchors[0] if anchors else None
    mtime = file_info["mtime"]
    ino = file_info["ino"]

    entries = []
    # (offset, ts) of the last header seen; ts may still be raw bytes.
    outer_prev = prev_anchor
    prev_anchor = None
    anchor_idx = 0
    for block in blocks:
        header = block["header"]
        if header is not None:
            prev_anchor = (block["offset"], header.group("ts"))
            anchor_idx += 1
        if block["discard"]:
            continue

        lines = block["lines"]
        cont = lines[1:]
        while cont and not cont[-1].strip():
            cont = cont[:-1]

        if header is not None:
            level = block["level"]
            if levels is not None and level not in levels:
                continue
            ts = _parse_ts(header.group("ts"))
            entry = {
                "id": f"{source}:{ino}:{block['offset']}",
                "timestamp": ts.astimezone().isoformat() if ts else None,
                "level": level,
                "source": source,
                "pid": int(header.group("pid")),
                "module": _decode(header.group("module")),
                "function": _decode(header.group("func")),
                "line": int(header.group("line")),
                "message": _decode(header.group("msg")),
            }
            sort_ts = ts
        else:
            text_lines = [_decode(line) for line in [lines[0]] + list(cont)]
            level = block["level"] or _guess_level("\n".join(text_lines))
            if levels is not None and level not in levels:
                continue
            useful = [t for t in text_lines if not SEPARATOR_RE.match(t.encode())]
            basic = BASIC_FORMAT_RE.match(lines[0])
            if basic:
                message, rest = _decode(basic.group(3)), useful[1:]
            else:
                while useful and not useful[0].strip():
                    useful.pop(0)
                message, rest = (useful[0], useful[1:]) if useful else (text_lines[0], [])
            while rest and not rest[-1].strip():
                rest.pop()
            entry = {
                "id": f"{source}:{ino}:{block['offset']}",
                "timestamp": None,
                "level": level,
                "source": source,
                "pid": None,
                "module": block["logger"],
                "function": None,
                "line": None,
                "message": message,
                "traceback": "\n".join(rest) if rest else None,
            }
            # No timestamp of its own: estimate from the surrounding headers by byte offset.
            nxt = None
            if anchor_idx < len(anchors):
                nxt = (anchors[anchor_idx][0], _parse_ts(anchors[anchor_idx][1]))
            elif next_anchor is not None:
                nxt = next_anchor
            else:
                nxt = (base_offset + len(data), datetime.fromtimestamp(mtime))
            if prev_anchor is not None:
                prv = (prev_anchor[0], _parse_ts(prev_anchor[1]))
            else:
                if callable(outer_prev):
                    outer_prev = outer_prev()
                prv = outer_prev
            sort_ts = _interpolate(prv, nxt, block["offset"])

        if header is not None:
            entry["traceback"] = "\n".join(_decode(line) for line in cont) if cont else None
        entry["_raw"] = header is None
        entry["_text"] = "\n".join(_decode(line) for line in [lines[0]] + list(cont))
        entry["_sort"] = (sort_ts or datetime.fromtimestamp(mtime), mtime, block["offset"])
        entries.append(entry)

    return entries, first_anchor


def _interpolate(prv, nxt, offset):
    if prv and prv[1] and nxt and nxt[1] and nxt[0] > prv[0] and nxt[1] >= prv[1]:
        frac = (offset - prv[0]) / (nxt[0] - prv[0])
        return prv[1] + (nxt[1] - prv[1]) * max(0.0, min(1.0, frac))
    if prv and prv[1]:
        return prv[1]
    if nxt and nxt[1]:
        return nxt[1]
    return None


def find_prev_header(fh, offset, max_bytes=64 * 1024 * 1024):
    """(offset, datetime) of the last header line that starts before offset, or None."""
    pos = offset
    tail = b""
    scanned = 0
    while pos > 0 and scanned < max_bytes:
        size = min(CHUNK_SIZE, pos)
        pos -= size
        fh.seek(pos)
        buf = fh.read(size) + tail[:64]
        scanned += size
        best = None
        for m in HEADER_START_RE.finditer(buf, 0, size):
            i = m.start()
            if i == 0 and pos > 0:
                fh.seek(pos - 1)
                if fh.read(1) != b"\n":
                    continue
            if pos + i < offset:
                best = i
        if best is not None:
            line_end = buf.find(b"\n", best)
            header = HEADER_RE.match(buf[best : line_end if line_end != -1 else len(buf)])
            if header:
                return pos + best, _parse_ts(header.group("ts"))
        tail = buf
    return None


def _first_entry_start(fh, buf, search_len, pos):
    """
    Index in buf (which starts at file offset pos) of the first line within buf[:search_len]
    that is guaranteed to start a new entry (a header, or a stderr line that always starts a
    block), or -1.
    """
    for m in BOUNDARY_RE.finditer(buf, 0, search_len):
        i = m.start()
        if i > 0:
            if buf[i - 1 : i] == b"\n":
                return i
            continue
        if pos == 0:
            return 0
        fh.seek(pos - 1)
        if fh.read(1) == b"\n":
            return 0
    return -1


def read_backwards(file_info, start, end, budget, want, matcher, levels=None):
    """
    Read [start, end) of a file from the end in chunks, parsing complete entries.

    Stops once `want` matching entries were found (None = no limit), the budget (bytes) is
    used up, or start is reached. Returns (matching entries oldest first, bytes read).
    """
    matches = []
    used = 0
    if levels is None:
        levels = getattr(matcher, "levels", None)
    try:
        fh = open(file_info["path"], "rb")
    except OSError:
        return matches, used

    with fh:
        pos = end
        carry = b""
        next_anchor = (end, datetime.fromtimestamp(file_info["mtime"]))
        prev_cache = {}

        def prev_anchor_for(offset):
            def lookup():
                cached = prev_cache.get("anchor")
                if cached is not None and cached[0] < offset:
                    return cached
                found = find_prev_header(fh, offset)
                prev_cache["anchor"] = found
                return found

            return lookup

        while pos > start and used < budget:
            size = min(CHUNK_SIZE, pos - start, budget - used)
            pos -= size
            fh.seek(pos)
            chunk = fh.read(size)
            used += len(chunk)
            buf = chunk + carry
            if pos > start:
                # Everything before the first header might belong to an entry that starts in
                # an earlier chunk; keep it for the next round. Only the new chunk (plus a few
                # bytes for a header split across the boundary) needs searching: carry is
                # known to contain no header before its first one.
                idx = _first_entry_start(fh, buf, min(len(buf), len(chunk) + 64), pos)
                if idx == -1:
                    carry = buf
                    continue
                carry = buf[:idx]
                base = pos + idx
                buf = buf[idx:]
            else:
                carry = b""
                base = pos
            if buf.endswith(b"\n"):
                buf = buf[:-1]
            parsed, first_anchor = parse_entries(
                buf,
                base,
                file_info["source"],
                file_info,
                levels,
                next_anchor=next_anchor,
                prev_anchor=prev_anchor_for(base),
            )
            if first_anchor is not None:
                next_anchor = (first_anchor[0], _parse_ts(first_anchor[1]))
            found = [e for e in parsed if matcher(e)]
            matches = found + matches
            if want is not None and len(matches) >= want:
                break
    return matches, used


# ---------------------------------------------------------------------------------------------
# Cursor
# ---------------------------------------------------------------------------------------------


def encode_cursor(state):
    raw = json.dumps({"v": 1, "f": state}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor):
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        data = json.loads(raw)
        if data.get("v") != 1 or not isinstance(data.get("f"), dict):
            return None
        state = {}
        for source, files in data["f"].items():
            state[str(source)] = {
                int(ino): (int(offset), int(crc)) for ino, offset, crc in files
            }
        return state
    except (ValueError, TypeError, binascii.Error, AttributeError):
        return None


def snapshot(sources):
    """Current cursor state: complete-line end offset and head CRC of every file."""
    state = {}
    for source, files in sources.items():
        triples = []
        for info in files:
            try:
                with open(info["path"], "rb") as fh:
                    end = complete_end(fh, info["size"])
                    crc = head_crc(fh, end)
            except OSError:
                continue
            info["end"] = end
            info["crc"] = crc
            triples.append([info["ino"], end, crc])
        state[source] = triples
    return state


# ---------------------------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------------------------


def make_matcher(levels, search):
    needle = search.lower() if search else None

    def matcher(entry):
        if entry["level"] not in levels:
            return False
        if needle:
            hay = " ".join(
                str(entry.get(k) or "") for k in ("message", "traceback", "module", "function")
            ).lower()
            if needle not in hay:
                return False
        return True

    matcher.levels = set(levels)
    return matcher


def public(entry):
    return {k: v for k, v in entry.items() if not k.startswith("_")}


def sort_newest_first(entries):
    entries.sort(key=lambda e: e["_sort"], reverse=True)
    return entries


def collect_recent(sources, wanted, matcher, limit, budget):
    entries = []
    for source in wanted:
        remaining = budget
        found = []
        for info in sources.get(source, []):
            if remaining <= 0 or len(found) >= limit:
                break
            info["source"] = source
            matches, used = read_backwards(
                info, 0, info.get("end", info["size"]), remaining, limit - len(found), matcher
            )
            remaining -= used
            found.extend(matches)
        entries.extend(found)
    return sort_newest_first(entries)[:limit]


def collect_since(sources, wanted, matcher, limit, budget, previous):
    entries = []
    for source in wanted:
        known = previous.get(source, {})
        remaining = budget
        for info in sources.get(source, []):
            if remaining <= 0:
                break
            end = info.get("end", info["size"])
            start = 0
            if info["ino"] in known:
                offset, crc = known[info["ino"]]
                if end == offset and info.get("crc") == crc:
                    continue  # unchanged
                if offset < end:
                    try:
                        with open(info["path"], "rb") as fh:
                            same = head_crc(fh, offset) == crc
                    except OSError:
                        continue
                    start = offset if same else 0
                # end < offset: truncated (copytruncate) or inode reused -> start over at 0
            if start >= end:
                continue
            info["source"] = source
            matches, used = read_backwards(info, start, end, remaining, None, matcher)
            remaining -= used
            entries.extend(matches)
    return sort_newest_first(entries)[:limit]


def parse_filters(args):
    level = (args.get("level") or "ERROR").upper()
    if level not in LEVELS:
        return None, ({"success": False, "error": f"Invalid level: {level}"}, 400)
    source = args.get("source") or None
    if source is not None and not SOURCE_RE.match(source):
        return None, ({"success": False, "error": "Invalid source"}, 400)
    search = (args.get("search") or "").strip() or None
    return {"level": level, "source": source, "search": search}, None


@error_log_api_blueprint.route("/api/logs/errors", methods=["GET"], strict_slashes=False)
@roles_accepted("administrator")
def get_error_log():
    filters, error = parse_filters(request.args)
    if error:
        return error
    try:
        limit = int(request.args.get("limit", 500))
    except ValueError:
        return {"success": False, "error": "Invalid limit"}, 400
    limit = max(1, min(limit, MAX_LIMIT))

    budget = int(app.config.get("RAVEN_ERROR_LOG_MAX_BYTES", DEFAULT_MAX_BYTES_PER_SOURCE))
    sources = discover_files(log_folder())
    state = snapshot(sources)
    wanted = [filters["source"]] if filters["source"] else sorted(sources)
    matcher = make_matcher(LEVELS[filters["level"]], filters["search"])

    previous = decode_cursor(request.args["since"]) if request.args.get("since") else None
    if request.args.get("since") and previous is None:
        return {"success": False, "error": "Invalid cursor"}, 400

    if previous is None:
        entries = collect_recent(sources, wanted, matcher, limit, budget)
    else:
        entries = collect_since(sources, wanted, matcher, limit, budget, previous)

    return jsonify(
        {
            "entries": [public(e) for e in entries],
            "cursor": encode_cursor(state),
            "sources": sorted(sources),
        }
    )


@error_log_api_blueprint.route("/api/logs/errors/download", methods=["GET"], strict_slashes=False)
@roles_accepted("administrator")
def download_error_log():
    filters, error = parse_filters(request.args)
    if error:
        return error
    try:
        days = int(request.args.get("days", 7))
    except ValueError:
        return {"success": False, "error": "Invalid days"}, 400
    days = max(1, min(days, 365))

    now = datetime.now()
    cutoff = now - timedelta(days=days)
    budget = int(
        app.config.get("RAVEN_ERROR_LOG_DOWNLOAD_MAX_BYTES", DEFAULT_DOWNLOAD_MAX_BYTES_PER_SOURCE)
    )
    sources = discover_files(log_folder())
    snapshot(sources)
    wanted = [filters["source"]] if filters["source"] else sorted(sources)
    base_matcher = make_matcher(LEVELS[filters["level"]], filters["search"])

    def matcher(entry):
        return entry["_sort"][0] >= cutoff and base_matcher(entry)

    matcher.levels = base_matcher.levels

    entries = []
    for source in wanted:
        remaining = budget
        for info in sources.get(source, []):
            if remaining <= 0:
                break
            if datetime.fromtimestamp(info["mtime"]) < cutoff:
                continue  # last written before the window started
            info["source"] = source
            matches, used = read_backwards(
                info, 0, info.get("end", info["size"]), remaining, None, matcher
            )
            remaining -= used
            entries.extend(matches)
    entries.sort(key=lambda e: e["_sort"])

    lines = [
        "# Raven error log export",
        f"# Generated: {now.astimezone().isoformat(timespec='seconds')}",
        f"# Levels: {', '.join(LEVELS[filters['level']])}",
        f"# Sources: {filters['source'] or 'all'}",
        f"# Period: last {days} day{'s' if days != 1 else ''} (since {cutoff.astimezone().isoformat(timespec='seconds')})",
    ]
    if filters["search"]:
        lines.append(f"# Search: {filters['search']}")
    lines.append(f"# Entries: {len(entries)}")
    lines.append("")
    previous_source = None
    for entry in entries:
        if entry["source"] != previous_source:
            lines.append(f"==> {entry['source']}.log <==")
            previous_source = entry["source"]
        lines.append(entry["_text"])
    body = "\n".join(lines) + "\n"

    filename = f"error-log-{now.strftime('%Y%m%d-%H%M')}.txt"
    return Response(
        body,
        mimetype="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )

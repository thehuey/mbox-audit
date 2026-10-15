#!/usr/bin/env python3
"""
mbox_audit.py - Verify a Gmail Takeout MBOX before deleting from Gmail.

  * Total message count
  * Breakdown by year/month and by Gmail label (printed + saved as CSV)
  * Warns if the last message looks cut off (truncated download/extract)
  * Randomly samples N messages that have attachments (skipping Spam and
    Trash) and saves, for each:
      - the full original message as .eml (open in any mail client)
      - every attachment, decoded to its original file
      - info.txt with From/Date/Subject, attachment sizes + SHA-256,
        any MIME problems (possible corruption), and a Gmail search
        string to find the same message in Gmail

Output is readable only by you. On macOS, saved .eml and attachment files
are flagged like web downloads so Gatekeeper checks them when opened.

Reads the file once, streaming, so it works on multi-GB mailboxes: only the
sampled messages are held in memory. Standard library only.

A gzipped mbox (e.g. mail.mbox.gz) is detected and decompressed on the fly,
and a damaged or cut-off .gz is reported.

List mode: --after/--before list the messages dated in that local-time range
(time, sender, subject; oldest first) instead of auditing, plus the Gmail
search that should show the same messages - for spot-checking before you
delete. As in Gmail, --after is inclusive and --before is not.

Split mode: --split copies the messages into separate mbox files in their own
folder (by local year or month, by Gmail label, or into size-limited parts),
and --label NAME writes every message with one label to a single mbox. Both
honour --after/--before and --no-spam-trash. The original is never changed.

Usage:
  python3 mbox_audit.py "All mail Including Spam and Trash.mbox"
  python3 mbox_audit.py mail.mbox.gz --samples 10 --out audit_out --seed 42
  python3 mbox_audit.py mail.mbox --after 2024-03-01 --before 2024-03-02
  python3 mbox_audit.py mail.mbox --after "2024-03-01 09:00" --before "2024-03-01 12:00"
  python3 mbox_audit.py mail.mbox --split year --no-spam-trash
  python3 mbox_audit.py mail.mbox --split size=2GB
  python3 mbox_audit.py mail.mbox --label "Work/Clients"
"""
import argparse
import csv
import gzip
import hashlib
import os
import random
import re
import subprocess
import sys
import time
import zlib
from collections import Counter, OrderedDict
from contextlib import contextmanager
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesHeaderParser, BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path

ATTACH_RE = re.compile(rb"^content-disposition:\s*attachment", re.I | re.M)
# Message separator: "From <sender> <date>". Takeout writes
# "From 123@xxx Mon Jan 01 00:00:00 +0000 2020"; classic mbox omits the zone.
# Requiring the full date keeps body lines like "From here on..." from
# being counted as extra messages.
FROM_LINE_RE = re.compile(
    rb"From \S+ +[A-Z][a-z]{2} (?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d\d:\d\d:\d\d)"
    rb"(?: (?P<tz>[+-]\d{4})| [A-Z]{3,5})? (?P<year>\d{4})\s*\Z")
# Likeliest to carry malware, and hidden from normal Gmail searches
SPAM_TRASH = {"spam", "trash"}
GZIP_MAGIC = b"\x1f\x8b"
GZIP_ERRORS = (EOFError, gzip.BadGzipFile, zlib.error)  # cut-off or corrupt .gz
# --split label: markers describe a message, they don't file it anywhere
LABEL_MARKERS = {"opened", "unread", "important", "starred"}
FOLDER_LABELS = ["Sent", "Drafts", "Chat", "Inbox"]  # used in this order
SYSTEM_LABELS = LABEL_MARKERS | SPAM_TRASH | {l.lower() for l in FOLDER_LABELS} | {"archived"}
GMAIL_ID_RE = re.compile(rb"From (\d+)@xxx ")  # Takeout: Gmail's message ID, in decimal
SIZE_UNITS = {"KB": 10**3, "MB": 10**6, "GB": 10**9}
MAX_OPEN_FILES = 64  # macOS often allows only 256 open files per process


def damage_warning(e):
    return (f"WARNING: the gzip data is damaged or truncated ({e}). Results may be "
            "incomplete or wrong - get a good copy before relying on them.")


def is_gzip(path):
    with open(path, "rb") as f:
        return f.read(2) == GZIP_MAGIC


@contextmanager
def open_mbox(path):
    """Open an mbox, decompressing it on the fly if it is gzipped (detected by
    content, not name). Yields (f, src): read messages from f; src.tell() is
    the position in the file on disk, for progress."""
    with open(path, "rb") as src:
        if is_gzip(path):
            with gzip.GzipFile(fileobj=src) as f:
                yield f, src
        else:
            yield src, src


def is_tar(path):
    """True for a tar archive (e.g. a Takeout .tgz), gzipped or not."""
    with open_mbox(path) as (f, _):
        try:
            return f.read(262)[257:262] == b"ustar"
        except GZIP_ERRORS:
            return False  # reported as damage when the file is read


def is_zip(path):
    """True for a zip archive (e.g. a Takeout .zip)."""
    with open(path, "rb") as f:
        return f.read(4) in (b"PK\x03\x04", b"PK\x05\x06")


def header_block(raw):
    """The header lines of a raw message, up to the first blank line. The email
    parser reads the whole body even when asked for headers only, so giving it
    just this is much faster on messages with attachments."""
    end = raw.find(b"\n\n")
    crlf = raw.find(b"\n\r\n", 0, end if end >= 0 else len(raw))  # Windows line endings
    end = crlf if crlf >= 0 else end
    return raw[:end + 1] if end >= 0 else raw


def iter_messages(f):
    """Yield (offset, from_line, raw_bytes) for each message in an open mbox."""
    offset, from_line, buf = None, b"", []
    prev_blank = True
    pos = 0
    for line in f:
        if prev_blank and FROM_LINE_RE.match(line):
            if offset is not None:
                yield offset, from_line, b"".join(buf)
            offset, from_line, buf = pos, line, []
        elif offset is not None:
            buf.append(line)
        prev_blank = line in (b"\n", b"\r\n")
        pos += len(line)
    if offset is not None:
        yield offset, from_line, b"".join(buf)


def unescape_mboxrd(raw):
    """Undo '>From ' escaping inside message bodies."""
    return re.sub(rb"(?m)^>(>*From )", rb"\1", raw)


def message_time(hdrs, from_line):
    """When the message was sent: its Date header, else the date on its mbox
    separator line. A timezone-aware datetime, or None if neither is readable."""
    try:
        dt = parsedate_to_datetime(str(hdrs["Date"]))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    m = FROM_LINE_RE.match(from_line)
    if m:
        try:
            return parsedate_to_datetime(b" ".join(
                [m["day"], m["mon"], m["year"], m["time"], m["tz"] or b"+0000"]).decode())
        except Exception:
            pass
    return None


def month_of(when):
    """'YYYY-MM' in local time (as Gmail shows it), or 'unknown'."""
    return f"{when.astimezone():%Y-%m}" if when else "unknown"


def year_month(hdrs, from_line):
    return month_of(message_time(hdrs, from_line))


def in_range(when, args):
    """True if --after/--before are unset or the message time is in [after, before)."""
    if not (args.after or args.before):
        return True
    return not (when is None or (args.after and when < args.after)
                or (args.before and when >= args.before))


def local_time(s):
    """argparse type: 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM[:SS]' in local time."""
    try:
        return datetime.fromisoformat(s).astimezone()
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{s!r} is not a valid date; use YYYY-MM-DD or 'YYYY-MM-DD HH:MM'") from None


def gmail_labels(hdrs):
    return {l.strip().lower() for l in str(hdrs.get("X-Gmail-Labels", "")).split(",")}


def label_names(hdrs):
    """Gmail labels as named (case kept), decoding =?UTF-8?...?= label names."""
    raw = str(hdrs.get("X-Gmail-Labels", ""))
    try:
        raw = str(make_header(decode_header(raw)))
    except Exception:
        pass
    return [clean(l).strip() for l in raw.split(",") if l.strip()]


def label_file(labels):
    """The one label a message is filed under for --split label: Spam/Trash,
    else your own label (or 'Multiple labels'), else Sent/Drafts/Chat/Inbox,
    else Archived. Markers like Opened, Starred and Category ... don't count."""
    low = {l.lower() for l in labels}
    for name in ("Spam", "Trash"):
        if name.lower() in low:
            return name
    own = list(dict.fromkeys(l for l in labels if l.lower() not in SYSTEM_LABELS
                             and not l.lower().startswith("category ")))
    if len(own) > 1:
        return "Multiple labels"
    if own:
        return own[0]
    return next((f for f in FOLDER_LABELS if f.lower() in low), "Archived")


def split_mode(s):
    """argparse type for --split: year, month, label or size=<N>KB|MB|GB."""
    if s in ("year", "month", "label"):
        return s, None
    m = re.fullmatch(r"size=(\d+(?:\.\d+)?)\s*([KMG]B)", s.strip(), re.I)
    if m and float(m[1]) > 0:
        return "size", int(float(m[1]) * SIZE_UNITS[m[2].upper()])
    raise argparse.ArgumentTypeError(f"{s!r}: use year, month, label or size=<N>MB|GB (e.g. size=2GB)")


def mbox_entry(from_line, raw):
    """A message as stored in an mbox: separator, message, then the blank line
    that must precede the next separator (missing only after the file's last
    message)."""
    entry = from_line + raw
    if not entry.endswith(b"\n"):
        entry += b"\n"
    if not entry.endswith((b"\n\n", b"\n\r\n")):
        entry += b"\n"
    return entry


def csv_safe(s):
    """Stop a spreadsheet from running untrusted text (e.g. a crafted
    Message-ID) as a formula."""
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def file_label(label):
    return safe_name(label.replace("/", " - "), 100)


def clean(s):
    """Make untrusted mail text safe to print: no terminal escapes, no line breaks."""
    return "".join(c if c.isprintable() else " " if c.isspace() else "?" for c in str(s))


def header_text(hdrs, name):
    """A header decoded to safe text. Falls back to the raw text when the email
    package can't parse it (e.g. 'From: a@[' crashes Python 3.12.0)."""
    try:
        return clean(hdrs.get(name, ""))
    except Exception:
        return clean(next((v for k, v in hdrs.raw_items() if k.lower() == name.lower()), ""))


def safe_name(s, maxlen=60):
    s = re.sub(r"[^\w.\- ]+", "_", s or "").strip(" ._")
    return (s or "untitled")[:maxlen]


def write_untrusted(path, data):
    """Write content from the mailbox. On macOS, flag it like a web download
    so Gatekeeper checks it before it is opened."""
    path.write_bytes(data)
    if sys.platform == "darwin":
        subprocess.run(["/usr/bin/xattr", "-w", "com.apple.quarantine",
                        f"0081;{int(time.time()):08x};mbox_audit;",
                        os.path.abspath(path)], check=True)


def iter_attachments(part):
    """Yield attachment parts at any depth of the MIME tree. Forwarded
    messages are yielded whole (saved as .eml), not descended into."""
    if part.get_content_type() == "message/rfc822":
        yield part
    elif part.is_multipart():
        for sub in part.iter_parts():
            yield from iter_attachments(sub)
    elif (part.is_attachment() or part.get_filename()
          or part.get_content_maintype() not in ("text", "multipart")):
        yield part


def attachment_bytes(part):
    if part.is_multipart():  # forwarded message
        return part.get_payload(0).as_bytes()
    return part.get_payload(decode=True) or b""


def mime_problems(msg):
    """List '<part>: <DefectName>' for every parse/decode error in the message.
    These usually mean the message or an attachment is damaged or cut off."""
    problems = []
    for part in msg.walk():
        if not part.is_multipart():
            part.get_payload(decode=True)  # base64 errors are only recorded on decode
        where = "message" if part is msg else part.get_filename() or part.get_content_type()
        for name in dict.fromkeys(type(d).__name__ for d in part.defects):
            problems.append(f"{clean(where)}: {name}")
    return problems


def save_sample(idx, raw, outdir):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    problems = mime_problems(msg)
    subj = header_text(msg, "Subject")
    d = outdir / f"{idx:02d}_{safe_name(subj, 40)}"
    d.mkdir(parents=True, exist_ok=True)
    write_untrusted(d / "original.eml", raw)

    lines = [
        f"From:       {header_text(msg, 'From')}",
        f"To:         {header_text(msg, 'To')}",
        f"Date:       {header_text(msg, 'Date')}",
        f"Subject:    {subj}",
        f"Message-ID: {header_text(msg, 'Message-ID')}",
        f"Gmail labels: {header_text(msg, 'X-Gmail-Labels')}",
    ]
    mid = header_text(msg, "Message-ID").strip().strip("<>")
    if mid:
        lines.append(f"Find in Gmail search box:  rfc822msgid:{mid}")
    lines.append("\nAttachments:")

    used = {"original.eml", "info.txt"}  # never let an attachment overwrite these
    count = 0
    for part in iter_attachments(msg):
        eml = ".eml" if part.get_content_type() == "message/rfc822" else ""
        fname = part.get_filename() or f"attachment_{count + 1}{eml}"
        fname = safe_name(fname, 100)
        base, n = fname, 1
        while fname.lower() in used:
            stem, dot, ext = base.rpartition(".")
            fname = f"{stem or base}_{n}{dot}{ext}" if dot else f"{base}_{n}"
            n += 1
        used.add(fname.lower())
        payload = attachment_bytes(part)
        write_untrusted(d / fname, payload)
        lines.append(f"  {fname}  {len(payload):,} bytes  {clean(part.get_content_type())}  "
                     f"sha256={hashlib.sha256(payload).hexdigest()}")
        count += 1
    if count == 0:
        lines.append("  (none decoded - check original.eml)")
    lines.append("\nMIME problems (possible corruption - compare with Gmail):")
    lines += [f"  {p}" for p in problems] or ["  none"]
    (d / "info.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return subj, count, problems


def list_messages(args):
    """Print every message dated in [--after, --before), oldest first in local
    time, and the Gmail search that should show the same messages."""
    hparser = BytesHeaderParser(policy=policy.default)  # decodes =?utf-8?...?= subjects
    found, spam_trash, damage = [], 0, None
    with open_mbox(args.mbox) as (f, _):
        try:
            for _, from_line, raw in iter_messages(f):
                hdrs = hparser.parsebytes(header_block(raw))
                when = message_time(hdrs, from_line)
                if when is None or not in_range(when, args):
                    continue
                tags = sorted(gmail_labels(hdrs) & SPAM_TRASH)
                spam_trash += bool(tags)
                tag = f"  [{', '.join(t.title() for t in tags)}]" if tags else ""
                found.append((when, f"{when.astimezone():%Y-%m-%d %H:%M}  "
                                    f"{header_text(hdrs, 'From'):<35}  "
                                    f"{header_text(hdrs, 'Subject')}{tag}"))
        except GZIP_ERRORS as e:
            damage = e

    for _, line in sorted(found):
        print(line)
    start = f"from {args.after:%Y-%m-%d %H:%M %Z}" if args.after else "from the start"
    end = f"to before {args.before:%Y-%m-%d %H:%M %Z}" if args.before else "to the end"
    print(f"\n{len(found):,} messages {start} {end}; {spam_trash:,} in Spam/Trash")
    search = "in:anywhere"
    if args.after:
        search += f" after:{int(args.after.timestamp())}"
    if args.before:
        search += f" before:{int(args.before.timestamp())}"
    print(f"Same range in Gmail:  {search}")
    if damage:
        print("\n" + damage_warning(damage))


class SplitWriter:
    """Append messages to many mbox files in one folder, keeping at most
    MAX_OPEN_FILES open at a time (the OS limits open files per process)."""

    def __init__(self, folder):
        self.folder = folder
        self.files = OrderedDict()  # name -> open file, least recently used first
        self.counts, self.sizes = Counter(), Counter()

    def write(self, name, data):
        f = self.files.pop(name, None)
        if f is None:
            if len(self.files) >= MAX_OPEN_FILES:
                self.files.popitem(last=False)[1].close()
            f = open(self.folder / name, "ab" if name in self.counts else "xb")
        self.files[name] = f
        f.write(data)
        self.counts[name] += 1
        self.sizes[name] += len(data)

    def close(self):
        for f in self.files.values():
            f.close()
        self.files.clear()


def selected(args, hdrs, when):
    """Apply --no-spam-trash and --after/--before."""
    if args.no_spam_trash and gmail_labels(hdrs) & SPAM_TRASH:
        return False
    return in_range(when, args)


def split_mbox(args):
    """Copy every selected message, byte for byte, into one mbox per year,
    month, label or size-limited part, in a folder of its own."""
    mode, limit = args.split
    folder = args.out / f"split_by_{mode}"
    if folder.exists() and any(folder.iterdir()):
        sys.exit(f"{folder} is not empty - move it away or use another --out, "
                 "so old and new files don't mix.")
    folder.mkdir(parents=True, exist_ok=True)
    folder.chmod(0o700)
    hparser = BytesHeaderParser(policy=policy.compat32)
    writer = SplitWriter(folder)
    names, used = {}, set()  # label -> file name; names taken (case-insensitive disk)
    part, part_size = 1, 0
    total, skipped, damage = 0, 0, None
    index_file = index = None
    if mode == "label":
        index_file = open(folder / "label_index.csv", "x", newline="", encoding="utf-8")
        index = csv.writer(index_file)
        index.writerow(["label", "gmail_id", "message_id", "date", "file"])
    size = args.mbox.stat().st_size

    def label_mbox(label):
        if label not in names:
            base = file_label(label)
            name, n = f"{base}.mbox", 2
            while name.lower() in used:
                name, n = f"{base} ({n}).mbox", n + 1
            used.add(name.lower())
            names[label] = name
        return names[label]

    try:
        with open_mbox(args.mbox) as (f, src):
            try:
                for _, from_line, raw in iter_messages(f):
                    total += 1
                    if total % 5000 == 0:
                        print(f"  ...{total:,} messages ({src.tell() / size:.0%})", file=sys.stderr)
                    hdrs = hparser.parsebytes(header_block(raw))
                    when = message_time(hdrs, from_line)
                    if not selected(args, hdrs, when):
                        skipped += 1
                        continue
                    entry = mbox_entry(from_line, raw)
                    if mode == "year":
                        name = f"{month_of(when).split('-')[0]}.mbox"
                    elif mode == "month":
                        name = f"{month_of(when)}.mbox"
                    elif mode == "size":
                        if part_size and part_size + len(entry) > limit:
                            part, part_size = part + 1, 0
                        part_size += len(entry)
                        name = f"part-{part:03d}.mbox"
                    else:
                        labels = label_names(hdrs)
                        name = label_mbox(label_file(labels))
                        m = GMAIL_ID_RE.match(from_line)
                        row = [m[1].decode() if m else "",
                               csv_safe(header_text(hdrs, "Message-ID").strip()),
                               f"{when.astimezone():%Y-%m-%d %H:%M}" if when else "", name]
                        for label in labels or ["(none)"]:
                            index.writerow([csv_safe(label), *row])
                    writer.write(name, entry)
            except GZIP_ERRORS as e:
                damage = e
    finally:
        writer.close()
        if index_file:
            index_file.close()

    with open(folder / "split_summary.csv", "x", newline="") as f:
        w = csv.writer(f)
        w.writerow(["file", "messages", "bytes"])
        for name in sorted(writer.counts):
            w.writerow([name, writer.counts[name], writer.sizes[name]])

    written = sum(writer.counts.values())
    files = len(writer.counts)
    print(f"Copied {written:,} of {total:,} messages into {files:,} file{'s' * (files != 1)} "
          f"in {folder}/")
    if skipped:
        print(f"({skipped:,} left out by --after/--before/--no-spam-trash)")
    print(f"\n  {'File':<40} {'Messages':>9} {'Size':>10}")
    for name in sorted(writer.counts):
        over = "  (one message over the limit)" if mode == "size" and writer.sizes[name] > limit else ""
        print(f"  {name:<40} {writer.counts[name]:>9,} {writer.sizes[name] / 1e6:>8.1f} MB{over}")
    if mode == "label":
        print("\nEach message is in exactly one file. label_index.csv lists every label of "
              "every message;\nuse --label NAME for one complete label mailbox.")
    print(f"\nSummary: {folder / 'split_summary.csv'}")
    if damage:
        print("\n" + damage_warning(damage))


def extract_label(args):
    """Write every selected message that carries the label --label NAME to
    <out>/labels/NAME.mbox (case-insensitive match), in one read."""
    want = args.label.strip().lower()
    path = args.out / "labels" / f"{file_label(args.label)}.mbox"
    if path.exists():
        sys.exit(f"{path} already exists - move it away or use another --out.")
    hparser = BytesHeaderParser(policy=policy.compat32)
    count, damage, out = 0, None, None
    try:
        with open_mbox(args.mbox) as (f, _):
            try:
                for _, from_line, raw in iter_messages(f):
                    hdrs = hparser.parsebytes(header_block(raw))
                    if want not in {l.lower() for l in label_names(hdrs)}:
                        continue
                    if not selected(args, hdrs, message_time(hdrs, from_line)):
                        continue
                    if out is None:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.parent.chmod(0o700)
                        out = open(path, "xb")
                    out.write(mbox_entry(from_line, raw))
                    count += 1
            except GZIP_ERRORS as e:
                damage = e
    finally:
        if out:
            out.close()
    if damage:
        print(damage_warning(damage) + "\n")
    if not count:
        sys.exit(f"No messages with the label {clean(args.label)!r}"
                 + (" match --after/--before/--no-spam-trash." if args.after or args.before
                    or args.no_spam_trash else "."))
    print(f"Wrote {count:,} messages with the label {clean(args.label)!r} to {path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mbox", type=Path)
    ap.add_argument("--samples", type=int, default=10)
    ap.add_argument("--out", type=Path, default=Path("mbox_audit_out"))
    ap.add_argument("--seed", type=int, default=None, help="for a repeatable sample")
    ap.add_argument("--after", type=local_time, metavar="WHEN",
                    help="list messages dated at or after this local time instead of "
                         "auditing: YYYY-MM-DD or 'YYYY-MM-DD HH:MM' (like Gmail's after:); "
                         "with --split/--label, only copy those messages")
    ap.add_argument("--before", type=local_time, metavar="WHEN",
                    help="list messages dated before this local time (like Gmail's before:)")
    ap.add_argument("--split", type=split_mode, metavar="HOW",
                    help="copy the messages into separate mbox files instead of auditing: "
                         "year, month, label, or size=<N>MB|GB (e.g. size=2GB)")
    ap.add_argument("--label", metavar="NAME",
                    help="write every message with this Gmail label to one mbox")
    ap.add_argument("--no-spam-trash", action="store_true",
                    help="with --split or --label: leave out Spam and Trash")
    args = ap.parse_args()
    if args.after and args.before and args.after >= args.before:
        ap.error("--after must be earlier than --before")
    if args.split and args.label:
        ap.error("use --split or --label, not both")
    if args.no_spam_trash and not (args.split or args.label):
        ap.error("--no-spam-trash works only with --split or --label")

    if not args.mbox.is_file():
        sys.exit(f"Not found: {args.mbox}")
    if is_zip(args.mbox):
        sys.exit(f"{args.mbox} is a zip archive (e.g. a Takeout .zip), not an mbox.\n"
                 "Extract it first (unzip <file>, or double-click it in Finder) "
                 "and run this on the .mbox inside.")
    if is_tar(args.mbox):
        sys.exit(f"{args.mbox} is a tar archive (e.g. a Takeout .tgz), not an mbox.\n"
                 f"Extract it first (tar -xzf <file>, or tar -xf if not gzipped) "
                 "and run this on the .mbox inside.")
    if args.split or args.label:
        os.umask(0o077)  # copied mail is private: files 0600, folders 0700
        return split_mbox(args) if args.split else extract_label(args)
    if args.after or args.before:
        return list_messages(args)
    os.umask(0o077)  # extracted mail is private: files 0600, folders 0700
    rng = random.Random(args.seed)
    hparser = BytesHeaderParser(policy=policy.compat32)

    total, with_attach, pool = 0, 0, 0
    by_month, by_label = Counter(), Counter()
    # Reservoir sampling: a uniform random sample in one pass without knowing
    # the message count. Holds (offset, raw) of at most --samples messages.
    reservoir = []
    size = args.mbox.stat().st_size
    last_raw = b""
    damage = None  # decompression error if a .gz is cut off or corrupt

    # Single pass: count everything, keep a random sample of messages with attachments
    with open_mbox(args.mbox) as (f, src):
        try:
            for offset, from_line, raw in iter_messages(f):
                total += 1
                hdrs = hparser.parsebytes(header_block(raw))
                by_month[year_month(hdrs, from_line)] += 1
                by_label.update(set(label_names(hdrs) or ["(none)"]))
                if ATTACH_RE.search(raw):
                    with_attach += 1
                    if not gmail_labels(hdrs) & SPAM_TRASH:
                        pool += 1
                        if len(reservoir) < args.samples:
                            reservoir.append((offset, raw))
                        else:
                            j = rng.randrange(pool)
                            if j < args.samples:
                                reservoir[j] = (offset, raw)
                last_raw = raw
                if total % 5000 == 0:
                    print(f"  ...{total:,} messages ({src.tell() / size:.0%})", file=sys.stderr)
        except GZIP_ERRORS as e:
            damage = e

    # Report
    args.out.mkdir(parents=True, exist_ok=True)
    gz = " gzip" if is_gzip(args.mbox) else ""
    print(f"\nFile:   {args.mbox}  ({size / 1e9:.2f} GB{gz})")
    print(f"TOTAL MESSAGES:            {total:,}")
    print(f"Messages with attachments: {with_attach:,}\n")
    if damage:
        print(damage_warning(damage) + "\n")
    if total:
        # A cut-off final message is the usual sign of an incomplete download/extract
        tail = mime_problems(BytesParser(policy=policy.default).parsebytes(last_raw))
        if not last_raw.endswith(b"\n"):
            tail.insert(0, "file ends mid-line")
        if tail:
            print("WARNING: the last message looks incomplete - the mbox may be truncated "
                  f"(interrupted download or extraction?): {'; '.join(tail)}\n")
    print("Year-Month   Count")
    years = Counter()
    for ym in sorted(by_month):
        print(f"  {ym:<10} {by_month[ym]:>7,}")
        years[ym.split("-")[0]] += by_month[ym]
    print("\nBy year:")
    for y in sorted(years):
        print(f"  {y:<10} {years[y]:>7,}")

    labels = sorted(by_label, key=lambda l: (-by_label[l], l.lower()))
    if labels:
        print("\nBy label (a message can have several):")
        for label in labels:
            print(f"  {label:<30} {by_label[label]:>7,}")

    with open(args.out / "counts_by_month.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["year_month", "count"])
        for ym in sorted(by_month):
            w.writerow([ym, by_month[ym]])
        w.writerow(["TOTAL", total])
    with open(args.out / "counts_by_label.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["label", "count"])
        for label in labels:
            w.writerow([csv_safe(label), by_label[label]])

    # Save the sampled messages, numbered in mailbox order
    if reservoir:
        sample_dir = args.out / "attachment_samples"
        sample_dir.mkdir(exist_ok=True)
        sample_dir.chmod(0o700)  # also tightens a folder left by an earlier run
        print(f"\nSaving {len(reservoir)} random messages with attachments "
              f"(Spam and Trash excluded) to {sample_dir}/")
        damaged = 0
        for idx, (_, raw) in enumerate(sorted(reservoir), 1):
            subj, n, problems = save_sample(idx, unescape_mboxrd(raw), sample_dir)
            note = f"  ({len(problems)} MIME problem(s), see info.txt)" if problems else ""
            print(f"  {idx:02d}. [{n} file(s)] {subj[:70]}{note}")
            damaged += bool(problems)
        if damaged:
            print(f"\n{damaged} of {len(reservoir)} samples have MIME problems - "
                  "compare them with the same messages in Gmail.")
    print(f"\nDone. Counts CSV: {args.out / 'counts_by_month.csv'}, "
          f"{args.out / 'counts_by_label.csv'}")


if __name__ == "__main__":
    main()

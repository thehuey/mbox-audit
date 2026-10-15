#!/usr/bin/env python3
"""
mbox_audit.py - Verify a Gmail Takeout MBOX before deleting from Gmail.

  * Total message count
  * Breakdown by year/month (printed + saved as CSV)
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

Usage:
  python3 mbox_audit.py "All mail Including Spam and Trash.mbox"
  python3 mbox_audit.py mail.mbox.gz --samples 10 --out audit_out --seed 42
  python3 mbox_audit.py mail.mbox --after 2024-03-01 --before 2024-03-02
  python3 mbox_audit.py mail.mbox --after "2024-03-01 09:00" --before "2024-03-01 12:00"
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
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from email import policy
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


def year_month(hdrs, from_line):
    dt = message_time(hdrs, from_line)
    return f"{dt.year:04d}-{dt.month:02d}" if dt else "unknown"


def local_time(s):
    """argparse type: 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM[:SS]' in local time."""
    try:
        return datetime.fromisoformat(s).astimezone()
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{s!r} is not a valid date; use YYYY-MM-DD or 'YYYY-MM-DD HH:MM'") from None


def gmail_labels(hdrs):
    return {l.strip().lower() for l in str(hdrs.get("X-Gmail-Labels", "")).split(",")}


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
                hdrs = hparser.parsebytes(raw)
                when = message_time(hdrs, from_line)
                if (when is None or (args.after and when < args.after)
                        or (args.before and when >= args.before)):
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


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mbox", type=Path)
    ap.add_argument("--samples", type=int, default=10)
    ap.add_argument("--out", type=Path, default=Path("mbox_audit_out"))
    ap.add_argument("--seed", type=int, default=None, help="for a repeatable sample")
    ap.add_argument("--after", type=local_time, metavar="WHEN",
                    help="list messages dated at or after this local time instead of "
                         "auditing: YYYY-MM-DD or 'YYYY-MM-DD HH:MM' (like Gmail's after:)")
    ap.add_argument("--before", type=local_time, metavar="WHEN",
                    help="list messages dated before this local time (like Gmail's before:)")
    args = ap.parse_args()
    if args.after and args.before and args.after >= args.before:
        ap.error("--after must be earlier than --before")

    if not args.mbox.is_file():
        sys.exit(f"Not found: {args.mbox}")
    if is_tar(args.mbox):
        sys.exit(f"{args.mbox} is a tar archive (e.g. a Takeout .tgz), not an mbox.\n"
                 f"Extract it first (tar -xzf <file>, or tar -xf if not gzipped) "
                 "and run this on the .mbox inside.")
    if args.after or args.before:
        return list_messages(args)
    os.umask(0o077)  # extracted mail is private: files 0600, folders 0700
    rng = random.Random(args.seed)
    hparser = BytesHeaderParser(policy=policy.compat32)

    total, with_attach, pool = 0, 0, 0
    by_month = Counter()
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
                hdrs = hparser.parsebytes(raw)
                by_month[year_month(hdrs, from_line)] += 1
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
        years[ym[:4]] += by_month[ym]
    print("\nBy year:")
    for y in sorted(years):
        print(f"  {y:<10} {years[y]:>7,}")

    with open(args.out / "counts_by_month.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["year_month", "count"])
        for ym in sorted(by_month):
            w.writerow([ym, by_month[ym]])
        w.writerow(["TOTAL", total])

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
    print(f"\nDone. Counts CSV: {args.out / 'counts_by_month.csv'}")


if __name__ == "__main__":
    main()

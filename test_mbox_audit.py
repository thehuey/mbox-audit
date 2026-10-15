"""Tests for mbox_audit.py.  Run from this folder:  python3 -m unittest -v"""
import base64
import contextlib
import gzip
import io
import itertools
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import mbox_audit

SCRIPT = Path(__file__).with_name("mbox_audit.py")
SEP = b"From 1700000000000000001@xxx Mon Jan 01 00:00:00 +0000 2024\n"
PDF = b"%PDF-1.4 attachment bytes\n" * 20
_boundaries = itertools.count(1)


def text(body=b"hello"):
    return b"Content-Type: text/plain\n\n" + body + b"\n"


def attachment(name, data=PDF, ctype=b"application/pdf"):
    return (b"Content-Type: " + ctype + b'; name="' + name + b'"\n'
            b'Content-Disposition: attachment; filename="' + name + b'"\n'
            b"Content-Transfer-Encoding: base64\n\n" + base64.encodebytes(data))


def multipart(subtype, *parts):
    b = b"b%d" % next(_boundaries)
    out = b"Content-Type: multipart/" + subtype + b'; boundary="' + b + b'"\n\n'
    for p in parts:
        out += b"--" + b + b"\n" + p
    return out + b"--" + b + b"--\n"


def message(entity, subject=b"Test", labels=b"Inbox",
            date=b"Mon, 01 Jan 2024 10:00:00 +0000", sender=b"a@example.com"):
    return (b"From: " + sender + b"\nTo: b@example.com\n"
            + (b"Date: " + date + b"\n" if date else b"")
            + b"Subject: " + subject + b"\n"
            b"Message-ID: <test@example.com>\nX-Gmail-Labels: " + labels + b"\n"
            b"MIME-Version: 1.0\n" + entity)


def with_pdf(**kw):
    return message(multipart(b"mixed", text(), attachment(b"a.pdf")), **kw)


def mbox(*messages):
    return b"\n".join(SEP + m for m in messages) + b"\n"


class SaveSampleTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name)

    def save(self, raw):
        mbox_audit.save_sample(1, raw, self.out)
        (d,) = self.out.iterdir()
        return d

    def files(self, d):
        return {p.name: p.read_bytes() for p in d.iterdir()}

    def test_attachment_named_original_eml_does_not_replace_the_message(self):
        raw = message(multipart(b"mixed", text(), attachment(
            b"original.eml", b"not the message", b"application/octet-stream")))
        d = self.save(raw)
        self.assertEqual((d / "original.eml").read_bytes(), raw)
        self.assertIn(b"not the message", self.files(d).values())

    def test_attachment_named_info_txt_survives_the_report(self):
        raw = message(multipart(b"mixed", text(), attachment(
            b"INFO.TXT", b"real attachment", b"text/plain")))
        d = self.save(raw)
        self.assertIn(b"real attachment", self.files(d).values())
        self.assertIn("Attachments:", (d / "info.txt").read_text())

    def test_extracts_attachment_inside_alternative_apple_mail_layout(self):
        raw = message(multipart(b"alternative", text(), multipart(
            b"mixed", b"Content-Type: text/html\n\n<p>hi</p>\n", attachment(b"report.pdf"))))
        self.assertEqual(self.files(self.save(raw)).get("report.pdf"), PDF)

    def test_extracts_attachment_inside_nested_mixed(self):
        raw = message(multipart(b"mixed", multipart(b"mixed", text(), attachment(b"nested.pdf"))))
        files = self.files(self.save(raw))
        self.assertEqual(files.get("nested.pdf"), PDF)
        self.assertNotIn(b"", files.values())  # no empty placeholder files

    def test_forwarded_message_is_saved_as_eml(self):
        inner = (b"From: c@example.com\nSubject: Inner\nMIME-Version: 1.0\n"
                 + multipart(b"mixed", text(), attachment(b"fwd.pdf")))
        fwd = (b"Content-Type: message/rfc822\n"
               b'Content-Disposition: attachment; filename="fwd.eml"\n\n' + inner)
        saved = self.files(self.save(message(multipart(b"mixed", text(), fwd)))).get("fwd.eml", b"")
        self.assertIn(b"Subject: Inner", saved)
        self.assertIn(base64.encodebytes(PDF)[:40], saved)

    def test_inline_image_in_related_part_is_extracted(self):
        img = (b"Content-Type: image/png\nContent-ID: <img1>\n"
               b"Content-Transfer-Encoding: base64\n\n" + base64.encodebytes(b"PNGDATA"))
        raw = message(multipart(b"related", b"Content-Type: text/html\n\n<img src=cid:img1>\n", img))
        self.assertIn(b"PNGDATA", self.files(self.save(raw)).values())

    def test_truncated_attachment_is_reported(self):
        raw = message(b'Content-Type: multipart/mixed; boundary="cut"\n\n--cut\n' + text()
                      + b"--cut\n" + attachment(b"broken.pdf")[:-41] + b"\n")
        info = (self.save(raw) / "info.txt").read_text()
        self.assertIn("CloseBoundaryNotFoundDefect", info)
        self.assertIn("broken.pdf: InvalidBase64", info)

    def test_clean_message_reports_no_problems(self):
        info = (self.save(with_pdf()) / "info.txt").read_text()
        self.assertNotIn("Defect", info)

    def test_control_characters_never_reach_info_txt(self):
        raw = message(text(), subject=b"=?utf-8?q?Hi=1B]0;PWNED=07=0AFind_in_Gmail_search_box:_evil?=")
        info = (self.save(raw) / "info.txt").read_text()
        self.assertNotIn("\x1b", info)
        self.assertNotIn("\x07", info)
        self.assertEqual(sum(l.startswith("Find in Gmail") for l in info.splitlines()), 1)

    def test_unparseable_sender_does_not_crash(self):
        # 'a@[' makes Python 3.12.0's header parser raise AttributeError
        info = (self.save(with_pdf(sender=b"a@[")) / "info.txt").read_text()
        self.assertIn("From:       a@[", info)


class SplitTest(unittest.TestCase):
    def count(self, data):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.mbox"
            path.write_bytes(data)
            with mbox_audit.open_mbox(path) as (f, _):
                return sum(1 for _ in mbox_audit.iter_messages(f))

    def test_body_line_starting_with_from_is_not_a_new_message(self):
        self.assertEqual(self.count(mbox(message(text(b"Hi\n\nFrom here on, things change.")))), 1)

    def test_takeout_and_classic_separators_both_split(self):
        classic = b"From MAILER-DAEMON Mon Jan  1 00:00:00 2024\n" + message(text())
        self.assertEqual(self.count(mbox(message(text())) + classic), 2)


class MainTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.out = self.tmp / "out"

    def run_audit(self, data):
        path = self.tmp / "test.mbox"
        path.write_bytes(data)
        r = subprocess.run([sys.executable, str(SCRIPT), str(path), "--out", str(self.out),
                            "--samples", "10"], capture_output=True, check=True)
        self.err = r.stderr.decode("utf-8", "replace")
        return r.stdout.decode("utf-8", "replace")

    def samples(self):
        return sorted((self.out / "attachment_samples").iterdir())

    def total(self, out):
        return int(re.search(r"TOTAL MESSAGES:\s+([\d,]+)", out).group(1).replace(",", ""))

    def test_counts_messages_in_gzipped_mbox(self):
        out = self.run_audit(gzip.compress(mbox(message(text()), with_pdf(), message(text()))))
        self.assertEqual(self.total(out), 3)
        self.assertNotIn("truncated", out)

    def test_extracts_samples_from_gzipped_mbox(self):
        self.run_audit(gzip.compress(mbox(message(text()), with_pdf())))
        (d,) = self.samples()
        self.assertEqual((d / "a.pdf").read_bytes(), PDF)

    def test_reports_truncated_gzip_instead_of_crashing(self):
        data = gzip.compress(mbox(*(with_pdf(subject=b"M%d" % i) for i in range(20))))
        out = self.run_audit(data[:len(data) * 3 // 4])
        self.assertIn("truncated", out)
        self.assertTrue(0 < self.total(out) < 20)

    def test_reports_corrupt_gzip_instead_of_crashing(self):
        data = bytearray(gzip.compress(mbox(message(text()), with_pdf())))
        data[-8] ^= 0xFF  # break the CRC in the gzip trailer
        self.assertIn("damaged", self.run_audit(bytes(data)))

    def test_refuses_tar_archive_with_extract_hint(self):
        data = mbox(with_pdf())
        path = self.tmp / "takeout.tgz"
        with tarfile.open(path, "w:gz") as t:
            info = tarfile.TarInfo("All mail Including Spam and Trash.mbox")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        r = subprocess.run([sys.executable, str(SCRIPT), str(path), "--out", str(self.out)],
                           capture_output=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"tar -xzf", r.stderr)

    def test_month_table_uses_date_header_then_separator_date(self):
        out = self.run_audit(mbox(message(text(), date=b"Fri, 15 Mar 2024 10:00:00 +0000"),
                                  message(text(), date=None)))  # SEP says Jan 2024
        self.assertRegex(out, r"2024-01\s+1\n")
        self.assertRegex(out, r"2024-03\s+1\n")

    def test_progress_on_gzipped_mbox_never_exceeds_100_percent(self):
        self.run_audit(gzip.compress(mbox(*[message(text())] * 5000)))
        percents = [int(p) for p in re.findall(r"\((\d+)%\)", self.err)]
        self.assertTrue(percents)
        self.assertLessEqual(max(percents), 100)

    def test_warns_when_last_message_is_cut_off(self):
        data = mbox(message(text())) + SEP + with_pdf()[:-60]
        self.assertIn("truncated", self.run_audit(data))

    def test_no_truncation_warning_for_complete_file(self):
        self.assertNotIn("truncated", self.run_audit(mbox(with_pdf())))

    def test_terminal_output_has_no_escape_sequences(self):
        out = self.run_audit(mbox(with_pdf(subject=b"=?utf-8?q?Hi=1B]0;PWNED=07=1B[31mRED?=")))
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)

    def test_spam_and_trash_are_not_sampled(self):
        self.run_audit(mbox(with_pdf(subject=b"Junk", labels=b"Opened,Spam"),
                            with_pdf(subject=b"Binned", labels=b"Trash"),
                            with_pdf(subject=b"Real", labels=b"Inbox,Important")))
        self.assertEqual([p.name for p in self.samples()], ["01_Real"])

    @unittest.skipUnless(sys.platform == "darwin", "macOS quarantine attribute")
    def test_extracted_files_are_marked_as_downloads(self):
        self.run_audit(mbox(with_pdf()))
        (d,) = self.samples()
        for name in ("a.pdf", "original.eml"):
            r = subprocess.run(["/usr/bin/xattr", "-p", "com.apple.quarantine", str(d / name)],
                               capture_output=True)
            self.assertEqual(r.returncode, 0, f"{name} not quarantined")

    def test_output_is_private(self):
        (self.out / "attachment_samples").mkdir(parents=True, mode=0o755)  # left by an old run
        self.run_audit(mbox(with_pdf()))
        (d,) = self.samples()
        for p in [self.out / "attachment_samples", d, *d.iterdir()]:
            self.assertEqual(stat.S_IMODE(p.stat().st_mode) & 0o077, 0, f"{p} readable by others")


class CountingFileIO(io.FileIO):
    """A file that adds every byte read from it to CountingFileIO.total."""
    total = 0

    def readinto(self, b):
        n = super().readinto(b)
        CountingFileIO.total += n or 0
        return n

    def read(self, size=-1):
        data = super().read(size)
        CountingFileIO.total += len(data or b"")
        return data

    def readall(self):
        data = super().readall()
        CountingFileIO.total += len(data)
        return data


def counting_open(path, mode="r", *args, **kwargs):
    if mode == "rb":
        return io.BufferedReader(CountingFileIO(path))
    return open(path, mode, *args, **kwargs)


class ReadOnceTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        umask = os.umask(0)  # main() tightens the umask; restore ours afterwards
        os.umask(umask)
        self.addCleanup(os.umask, umask)

    def test_audit_reads_the_mbox_only_once(self):
        path = self.tmp / "big.mbox"
        path.write_bytes(mbox(*(with_pdf(subject=b"M%d" % i) for i in range(400))))
        out = self.tmp / "out"
        CountingFileIO.total = 0
        argv = ["mbox_audit.py", str(path), "--out", str(out), "--seed", "1"]
        with mock.patch.object(mbox_audit, "open", counting_open, create=True), \
                mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            mbox_audit.main()
        self.assertEqual(len(list((out / "attachment_samples").iterdir())), 10)
        size = path.stat().st_size
        self.assertLess(CountingFileIO.total, size * 1.1,
                        f"read {CountingFileIO.total / size:.2f}x the file size")


class ListTest(unittest.TestCase):
    """--after/--before: list messages in a local-time range, like Gmail's after:/before:."""
    # With TZ=America/Los_Angeles, 2024-03-01 00:00 local = 08:00 UTC (PST, UTC-8)
    BEFORE_RANGE = message(text(), subject=b"TooEarly", date=b"Fri, 01 Mar 2024 07:59:00 +0000")
    AT_START = message(text(), subject=b"AtStart", date=b"Fri, 01 Mar 2024 08:00:00 +0000")
    OTHER_ZONE = message(text(), subject=b"OtherZone", date=b"Fri, 01 Mar 2024 12:30:00 -0500")
    SPAM = message(text(), subject=b"Spammy", labels=b"Opened,Spam",
                   date=b"Fri, 01 Mar 2024 20:00:00 +0000")
    AT_END = message(text(), subject=b"AtEnd", date=b"Sat, 02 Mar 2024 08:00:00 +0000")
    DAY = ("--after", "2024-03-01", "--before", "2024-03-02")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def run_list(self, data, *range_args):
        path = self.tmp / "l.mbox"
        path.write_bytes(data)
        r = subprocess.run([sys.executable, str(SCRIPT), str(path), *range_args,
                            "--out", str(self.tmp / "out")], capture_output=True,
                           env={**os.environ, "TZ": "America/Los_Angeles"})
        self.code, self.err = r.returncode, r.stderr.decode("utf-8", "replace")
        return r.stdout.decode("utf-8", "replace")

    def listed(self, out):
        return [l for l in out.splitlines() if re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d ", l)]

    def day(self):
        return self.run_list(mbox(self.BEFORE_RANGE, self.OTHER_ZONE, self.AT_START,
                                  self.AT_END, self.SPAM), *self.DAY)

    def test_lists_range_in_local_time_oldest_first(self):
        lines = self.listed(self.day())
        expected = [("2024-03-01 00:00", "AtStart"), ("2024-03-01 09:30", "OtherZone"),
                    ("2024-03-01 12:00", "Spammy")]
        self.assertEqual(len(lines), 3, lines)
        for (when, subject), line in zip(expected, lines):
            self.assertTrue(line.startswith(when), line)
            self.assertIn(subject, line)

    def test_tags_spam_and_trash(self):
        (spam,) = [l for l in self.listed(self.day()) if "Spammy" in l]
        self.assertTrue(spam.endswith("[Spam]"), spam)

    def test_summary_gives_count_and_matching_gmail_search(self):
        out = self.day()
        self.assertIn("3 messages from 2024-03-01 00:00 PST to before 2024-03-02 00:00 PST; "
                      "1 in Spam/Trash", out)
        self.assertIn("in:anywhere after:1709280000 before:1709366400", out)

    def test_open_ended_range(self):
        out = self.run_list(mbox(self.AT_START, self.SPAM, self.AT_END), "--after", "2024-03-01 12:00")
        self.assertEqual([l.split()[3] for l in self.listed(out)], ["Spammy", "AtEnd"])
        self.assertIn("to the end", out)
        self.assertNotIn("before:", out)

    def test_subjects_are_decoded_and_cleaned(self):
        out = self.run_list(mbox(message(text(), subject=b"=?utf-8?q?Caf=C3=A9_=1B[31mred?=")),
                            "--after", "2024-01-01")
        (line,) = self.listed(out)
        self.assertIn("Caf\u00e9 ?[31mred", line)
        self.assertNotIn("\x1b", out)

    def test_unparseable_sender_does_not_crash(self):
        out = self.run_list(mbox(message(text(), subject=b"Odd", sender=b"a@[")), "--after", "2024-01-01")
        self.assertEqual(self.code, 0, self.err)
        (line,) = self.listed(out)
        self.assertIn("a@[", line)
        self.assertIn("Odd", line)

    def test_falls_back_to_separator_date(self):
        # SEP is Mon Jan 01 00:00:00 +0000 2024 = 2023-12-31 16:00 PST
        out = self.run_list(mbox(message(text(), subject=b"NoDate", date=None)),
                            "--after", "2023-12-31", "--before", "2024-01-01")
        (line,) = self.listed(out)
        self.assertTrue(line.startswith("2023-12-31 16:00"), line)

    def test_rejects_bad_date(self):
        self.run_list(mbox(self.AT_START), "--after", "2024-13-01")
        self.assertNotEqual(self.code, 0)
        self.assertIn("YYYY-MM-DD", self.err)

    def test_rejects_empty_range(self):
        self.run_list(mbox(self.AT_START), "--after", "2024-03-02", "--before", "2024-03-01")
        self.assertNotEqual(self.code, 0)
        self.assertIn("--after must be earlier than --before", self.err)

    def test_list_mode_skips_audit_output(self):
        out = self.day()
        self.assertEqual(self.code, 0, self.err)
        self.assertTrue(self.listed(out))
        self.assertNotIn("TOTAL MESSAGES", out)
        self.assertFalse((self.tmp / "out").exists())


if __name__ == "__main__":
    unittest.main()

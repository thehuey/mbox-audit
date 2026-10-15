# mbox-audit

Check a Gmail Takeout export **before** you delete mail from Gmail.

Google Takeout gives you your whole mailbox as one large `.mbox` file. Before you
delete anything from Gmail, you want to know the export is complete and readable.
`mbox_audit.py` reads the file once and tells you:

- **How many messages it holds**, by month, by year and by Gmail label (also
  saved as CSVs), so you can spot missing months and compare labels with Gmail.
- **Whether the file is cut off or damaged.** It warns if the last message is
  incomplete (an interrupted download or unzip) or if a `.gz` copy is corrupt.
- **Whether attachments come back intact.** It saves a random sample of messages
  with attachments (Spam and Trash skipped), with each attachment decoded, its
  SHA-256, any MIME errors, and a Gmail search that finds the same message
  so you can compare.
- **What is in a date range** (`--after` / `--before`): every message's time,
  sender and subject, plus the matching Gmail search, for spot checks.

It can also **split** the export into smaller mailboxes: by year, month, Gmail
label or size. Or it can write one complete mailbox for a single label.

It is one Python file using only the standard library. It never changes the
mbox or connects to the network.

## Who it's for

- You are freeing up Google storage by deleting old mail and keeping an offline copy.
- You are closing a Google account and want proof the export is good first.
- You keep a Takeout archive and want to check it now and then.

It is not a mail reader. To browse the export, import it into Thunderbird
(with the ImportExportTools NG add-on) or Apple Mail.

## Requirements

Python 3.9 or newer. The `python3` that comes with macOS works, and there is
nothing to install. Tested on macOS and Linux. On Windows it should run, but the
file permission and download-flag protections described below don't apply.

## 1. Get your mailbox from Google Takeout

1. Go to [takeout.google.com](https://takeout.google.com), signed in to the account.
2. Click **Deselect all**, then tick **Mail**. Leave **All Mail data included**
   as it is, so the export has every message, including Spam and Trash.
3. Click **Next step** and choose:
   - **Destination:** Send download link via email
   - **Frequency:** Export once
   - **File type & size:** `.zip` or `.tgz`; pick the largest size (50 GB) so the
     mailbox is split into as few parts as possible
4. Click **Create export**. Google emails you when it is ready; that can take
   from minutes to a few days for a large mailbox.
5. Download every part. Google's links expire after about 7 days, and each
   archive can be downloaded 5 times.
6. Extract the archive(s), then find the mailbox in `Takeout/Mail/`:

   ```sh
   tar -xzf takeout-*.tgz        # or: unzip takeout-*.zip
   ls Takeout/Mail/
   # All mail Including Spam and Trash.mbox
   ```

   The name may end in a part number such as `-002`. If more than one part holds
   an `.mbox`, check each one.

To save disk space you can compress it (`gzip -k "All mail Including Spam and Trash.mbox"`).
The tool reads the `.mbox.gz` directly.

## 2. Audit it

```sh
python3 mbox_audit.py "Takeout/Mail/All mail Including Spam and Trash.mbox"
```

Output from a small demo mailbox:

```
File:   All mail Including Spam and Trash.mbox  (0.00 GB)
TOTAL MESSAGES:            10
Messages with attachments: 7

Year-Month   Count
  2023-03          1
  2023-07          1
  ...
  2024-04          1

By year:
  2023             5
  2024             5

By label (a message can have several):
  Inbox                                7
  Finance                              2
  ...

Saving 6 random messages with attachments (Spam and Trash excluded) to mbox_audit_out/attachment_samples/
  01. [1 file(s)] Lease renewal
  02. [1 file(s)] Trip photos
  ...

Done. Counts CSV: mbox_audit_out/counts_by_month.csv, mbox_audit_out/counts_by_label.csv
```

The label table counts every label Gmail recorded, including markers like
`Opened` and `Important`. A message with three labels is counted under each one,
so the label counts add up to more than the total.

Each sample folder in `mbox_audit_out/attachment_samples/` has:

- `original.eml`: the full message; opens in any mail app
- the attachments, decoded to their original files
- `info.txt`: sender, date, subject, labels, each attachment's size and SHA-256,
  any MIME problems, and a search such as `rfc822msgid:...` to paste into Gmail

Options:

| Option | Meaning |
|---|---|
| `--samples N` | how many messages to sample (default 10) |
| `--out DIR` | output folder (default `mbox_audit_out`) |
| `--seed N` | repeat the same random sample |
| `--after WHEN`, `--before WHEN` | list messages in a date range instead of auditing (below) |
| `--split HOW` | split into separate mailboxes instead of auditing: `year`, `month`, `label`, `size=2GB` (below) |
| `--label NAME` | write every message with one Gmail label to its own mailbox (below) |
| `--no-spam-trash` | with `--split` or `--label`: leave out Spam and Trash |

A 20 GB mailbox takes a few minutes on a Mac.

## 3. Spot-check a date range against Gmail

```sh
python3 mbox_audit.py mail.mbox --after 2024-03-01 --before 2024-03-02
```

```
2024-03-01 09:15  Pat Lee <pat@example.com>            Re: Dinner Friday?
2024-03-01 14:02  Pat Lee <pat@example.com>            Flight confirmation
2024-03-01 21:30  Pat Lee <pat@example.com>            Weekly newsletter  [Trash]

3 messages from 2024-03-01 00:00 PST to before 2024-03-02 00:00 PST; 1 in Spam/Trash
Same range in Gmail:  in:anywhere after:1709280000 before:1709366400
```

Paste the last line into Gmail's search box. Turn off **Conversation view** in
Gmail's settings first, so Gmail lists messages, not threads.
Times are in your computer's time zone. `--after` includes its time and
`--before` does not, as in Gmail. A time works too: `--after "2024-03-01 09:00"`.

## 4. Split it into smaller mailboxes

One 20 GB file is hard to work with: many mail apps import it slowly or not at
all. `--split` copies each message, byte for byte, into a smaller mailbox. The
files go in a new folder, so nothing lands next to your export, and the original
is never changed.

```sh
python3 mbox_audit.py mail.mbox --split year            # 2023.mbox, 2024.mbox, ...
python3 mbox_audit.py mail.mbox --split month           # 2024-02.mbox, 2024-03.mbox, ...
python3 mbox_audit.py mail.mbox --split size=2GB        # part-001.mbox, part-002.mbox, ...
python3 mbox_audit.py mail.mbox --split label           # Inbox.mbox, Work.mbox, ...
python3 mbox_audit.py mail.mbox --split year --no-spam-trash --after 2015-01-01
```

Output from the demo mailbox:

```
Copied 10 of 10 messages into 7 files in mbox_audit_out/split_by_label/

  File                                      Messages       Size
  Family.mbox                                      1      0.0 MB
  Finance.mbox                                     2      0.0 MB
  Inbox.mbox                                       3      0.0 MB
  ...
```

- Files go in `mbox_audit_out/split_by_<how>/`, with a `split_summary.csv`
  listing each file's message count and size. If that folder already has files
  in it, the tool stops rather than mixing old and new.
- Years and months use your local time, as in Gmail. Messages with no readable
  date go to `unknown.mbox`.
- With `size=`, no message is cut in half. A message larger than the limit gets
  a part of its own. Units are KB, MB and GB (1 GB = 1,000,000,000 bytes).
  Joining the parts in order gives back the original file exactly.
- `--after`, `--before` and `--no-spam-trash` limit which messages are copied.

### Splitting by label

Gmail lets a message have many labels, but each message goes into exactly
**one** file, so nothing is duplicated:

1. `Spam` or `Trash`
2. otherwise your own label; a message with two or more of your labels goes to
   `Multiple labels.mbox`
3. otherwise `Sent`, `Drafts`, `Chat` or `Inbox`
4. otherwise `Archived.mbox`

Labels that only describe a message don't decide where it goes: `Opened`,
`Unread`, `Important`, `Starred` and the `Category ...` tabs. Nested labels like
`Work/Clients` become `Work - Clients.mbox`.

`label_index.csv` in the same folder lists every label of every message: label,
Gmail message ID, `Message-ID`, local date, and the file it's in. To see every
message labelled Work, wherever it was filed:

```sh
grep '^Work,' mbox_audit_out/split_by_label/label_index.csv
```

To get **one complete mailbox for a label**, including messages that are also
in other labels:

```sh
python3 mbox_audit.py mail.mbox --label Work           # -> mbox_audit_out/labels/Work.mbox
```

The label name isn't case-sensitive. It also takes `--no-spam-trash`,
`--after` and `--before`, and it never overwrites an earlier export.

## Before you delete: a checklist

- No `WARNING` lines in the report, and no samples with MIME problems.
- The by-month table has no unexpected gaps.
- The counts for labels you care about match Gmail. Search
  `in:anywhere label:work` (or `label:work-clients` for `Work/Clients`), with
  Conversation view off; `in:anywhere` includes Spam and Trash, as the export does.
- The sample attachments open, and match the same messages in Gmail.
- A few date ranges list the same messages as Gmail.
- Keep two copies of the export, on different drives.

## Good to know

- **Safety.** Samples are real mail, possibly including malware. The output folder
  is readable only by you, and on macOS saved files are flagged like web downloads
  so Gatekeeper checks them before they open.
- **Dates.** Months, years and date ranges use each message's `Date:` header,
  shown in your local time, and fall back to the date on the mbox separator
  line. Gmail sorts by when it received the message, so a message near a
  boundary can land on the other side.
- **Counts.** "Messages with attachments" is a quick header check
  (`Content-Disposition: attachment`) and doesn't count inline images.
- **Memory.** The sampled messages are held in memory until the end: roughly
  `--samples` × message size.
- **Input.** Give it the extracted `.mbox` or `.mbox.gz`. It can't read standard
  input. Given a Takeout `.zip` or `.tgz`, it stops and tells you to extract it first.

## Running the tests

```sh
python3 -m unittest -v
```

## License

MIT. See [LICENSE](LICENSE).

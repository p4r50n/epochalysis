# Epochalysis

Binary forensic parser for Linux `wtmp` artifacts.

Epochalysis extracts interactive login events (`USER_PROCESS`, ut_type = 7) directly from the raw `wtmp` structure, allowing investigators to accurately determine when a terminal session was established.

When authentication logs are not enough, session creation timestamps matter.

---

## Why This Tool Exists

In incident response investigations, there is a critical distinction between:

- Authentication events (recorded in `auth.log`)
- Interactive session creation events (recorded in `wtmp`)

An attacker may authenticate multiple times, but the moment they establish an interactive terminal session is represented by a `USER_PROCESS` record in `wtmp`.

Epochalysis parses the binary structure directly instead of relying on utilities like `last`.

---

## Features

- Direct binary parsing of `struct utmp`
- Extracts only interactive session creation events
- Chronological timeline reconstruction
- Filter by:
  - Username
  - Remote IP address
- Detect first interactive login (`--first`)
- Compare against known epoch lists
- JSON output for automation
- Safe handling of corrupted records
- No external dependencies

---

## Installation

Clone the repository:
  git clone https://github.com/p4r50n/epochalysis.git
  
cd epochalysis


Requires Python 3.8+

---

## Usage

Basic analysis:

  python3 epochalysis.py "filename"

Filter by IP:

  python3 epochalysis.py wtmp_file -i "IP"

Filter by user:

  python3 epochalysis.py wtmp_file -u "user"

Show only the first interactive session:

  python3 epochalysis.py "filename" -i "IP" --first

Compare against a list of epoch timestamps:

  python3 epochalysis.py "filename" -e "listname"

JSON output:

  python3 epochalysis.py "filename" --json

---

## Technical Notes

- Default record size: 384 bytes (common on x86_64 Linux)
- Use `-s` to override record size if needed
- Parses only `USER_PROCESS` events (ut_type = 7)

---

## Use Cases

- DFIR investigations
- Incident response timeline reconstruction
- CTF forensic challenges
- Blue team artifact analysis
- Post-compromise session tracking

---

## License

MIT
  
  



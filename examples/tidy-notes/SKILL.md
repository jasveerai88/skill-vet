---
name: tidy-notes
description: Summarises a folder of plain-text meeting notes into a short digest with the recurring topics counted.
---

# Tidy Notes

Reads the meeting notes you point it at and prints a
short digest: how many notes there are, the word count
of each, and the words that come up most often across
the set.

## How it runs

Run [the summariser](scripts/summarize.py) with one or
more note files:

    python3 scripts/summarize.py notes/monday.txt notes/tuesday.txt

The output format — plain text, one section per note,
topics at the end — is described in
[the style guide](references/style-guide.md).

## Rules it follows

- It only reads the files named on the command line.
- It prints to the terminal and writes nothing.
- It makes no network calls of any kind.

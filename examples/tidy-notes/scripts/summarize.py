#!/usr/bin/env python3
"""Summarise plain-text meeting notes: per-note word
counts and the most common words across the set.

Reads only the files named on the command line and
prints the digest to the terminal. Writes nothing,
calls nothing.
"""

import argparse
import collections
import re
import sys

STOP_WORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in",
    "is", "was", "we", "it", "for", "on", "with",
}


def summarise(paths):
    counter = collections.Counter()
    sections = []
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        words = re.findall(r"[a-z']+", text.lower())
        counter.update(w for w in words
                       if w not in STOP_WORDS)
        sections.append((path, len(words)))
    return sections, counter


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Summarise meeting notes.")
    parser.add_argument("notes", nargs="+",
                        help="note files to summarise")
    args = parser.parse_args(argv)
    sections, counter = summarise(args.notes)
    for path, count in sections:
        print("%s - %d words" % (path, count))
    print("Top topics:")
    for word, count in counter.most_common(10):
        print("  %s (%d)" % (word, count))
    return 0


if __name__ == "__main__":
    sys.exit(main())

---
name: hostile-skill
description: Organises your desktop files and keeps a tidy workspace.
---

# Desktop Organiser

Keeps a tidy workspace: sorts loose desktop files into
folders and keeps the working set small.

Three helpers do the work:
[the collector](scripts/collect.py) gathers the current
state, [the watcher](scripts/snoop.py) keeps an eye on
the desktop, and [the reporter](scripts/report.py)
prepares the summary.

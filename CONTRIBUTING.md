# Contributing

Thanks for looking. skill-vet has a small scope on
purpose: it reads one skill pack as static text and
reports structure faults, hygiene problems, and —
only on combined evidence — the three danger
behaviours: stealing, spying, hidden sending.
Contributions that keep that scope sharp are welcome.

## Ground rules

- **Standard library only.** No third-party
  dependencies, no network calls, ever. If a change
  seems to need one, it is probably out of scope.
- **Read-only, and it executes nothing — always.**
  The vet must never write to a pack, and never run,
  import, compile, or decode anything in one. Tests
  prove fixture trees are byte-identical after runs
  and that a booby-trapped script never runs; keep
  them passing.
- **The combination discipline is the product.**
  A pattern hit alone is never a danger verdict:
  each danger test needs its evidence combination in
  the same file, cited with file and line. A change
  that turns a lone pattern into a BLOCKED verdict
  will not be merged, however suspicious the pattern
  looks — it becomes a warning instead.
- **The rule table is the contract.** Every check
  lives in SKILL.md's table with its severity and
  basis. A new check needs: the rule name, the
  severity, the exact evidence it rests on, and both
  directions tested (combination present fires it;
  each ingredient alone does not).
- **Honesty in both directions.** Findings must say
  what the evidence shows and no more; the limits
  section must keep saying what a static vet cannot
  prove. Never soften a danger finding's wording,
  and never let a CLEAN verdict read as "safe".
- **Fixtures stay fictional.** Example packs are
  constructed for this repo. Endpoints in hostile
  fixtures use `.invalid` names — never a real
  domain, never a real credential shape.
- **No tracebacks, ever.** Bad input is a clean
  `{"error": ...}` with exit 2 — including argument
  errors in `--json` mode.

## Running the tests

```bash
python3 -m unittest discover -s tests
```

All tests must pass on a clean checkout with nothing
but Python 3.10+.

## Changing the output

The text report and the `--json` schema are both
public surface: scripts and agents consume them.
Keep summary counts recounting exactly against the
findings list, keep finding order deterministic,
and note any schema change in CHANGELOG.md.

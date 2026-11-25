# Defense 1 (delimiting / spotlighting) — Design Decisions

Decision record for **Change 1**: the helper that prepares log lines before they are inserted into the LLM prompt
(insertion points: `commons.py:1238-1240` batch, `commons.py:625-633` real-time — see `docs/injection-point.md`).

Process: decisions are made **one at a time by the author**, in order. For each, Claude restates the context and
gives a recommendation; the author decides; the choice and reason are recorded here before any code is written for it.

| # | Decision | Status | Choice |
|---|---|---|---|
| 1 | Where the code lives | **decided** 2026-11-25 | (a) new `core/sanitize.py` |
| 2 | Log-block markers | **decided** 2026-11-25 | (b) random per prompt, `secrets`, 8 bytes, `<<<LOG_DATA_<code> BEGIN/END>>>` |
| 3 | Fake markers inside log lines | open | — |
| 4 | Labelling each line | open | — |
| 5 | Transforming the text itself | open | — |
| 6 | Other hiding tricks (invisible chars, line breaks, colour codes, long lines) | open | — |
| 7 | What the function returns | open | — |
| 8 | Empty chunk | open | — |

---

## Decision 1 — Where the code lives
**Purpose:** the defense must apply to every analyzer and both modes, and be easy to point to in an interview.
- **(a) New file `core/sanitize.py`**, one function called by both prompt builders. One place to read, test and later send upstream; one more file.
- **(b) Inline in `commons.py`** at the two `.format()` sites. Fewer files; the same logic in two places that can drift apart; harder to unit-test.

Recommendation: (a).
**Decision (2026-11-25): (a) new file `src/logsentinelai/core/sanitize.py`.** Reason: one place to read, test and later send upstream; both prompt builders share it, so batch and real-time mode can't drift apart.

## Decision 2 — Log-block markers
**Purpose:** mark exactly where untrusted data starts and ends, in a way an attacker can't fake. S02 and F01 worked by writing `<LOGS END>` into a log line.
- **(a) Fixed markers** like upstream's `<LOGS BEGIN>` — already proven fakeable.
- **(b) Random markers, new for every prompt**, e.g. `<<<LOG_DATA_9f2c41ab07d3e5c1 BEGIN>>>`. The attacker writes the log line before the prompt exists, so can't know the code.
- **(c) Random markers, same code for a whole run.** Simpler, but anyone who sees one output (e.g. Kibana) learns the code.

Sub-choices for (b): randomness source (`secrets` = unguessable, vs `random` = predictable); length (8 bytes / 16 hex chars is plenty); format (triple angle brackets + name, or plain tags like `<data id="…">`).
Recommendation: (b) with `secrets`.
**Decision (2026-11-25, partial): (b) random markers, new for every prompt; randomness from Python's `secrets` module; 8 random bytes (16 hex characters).** Reason: the attacker's log line is written before the prompt exists, so an unpredictable per-prompt code can't be faked — closes the trick behind S02 and F01. `secrets` is designed to be unpredictable; 8 bytes makes guessing practically impossible at a cost of a few tokens.
**Format (2026-11-25): (i) triple brackets + name — `<<<LOG_DATA_<16 hex> BEGIN>>>` … `<<<LOG_DATA_<16 hex> END>>>`.** Reason: very unlikely to collide with real log text (unlike XML-style tags, which HTTP attack payloads contain); the fixed `LOG_DATA` part gives Decision 3 a narrow, exact pattern to defuse; the same code at both ends makes the pair obvious; no curly braces, so it's safe with `.format()`. Rejected: XML tags (collide with real payloads), Markdown fences (closing fence can't carry the code). Banner lines (`===== BEGIN LOG DATA … =====`) kept as a variant to try if S02/F01 still get through.

## Decision 3 — Fake markers inside log lines
**Purpose:** an attacker can still write `<LOGS END>` or an invented `<<<LOG_DATA_… END>>>`; a small model may be fooled by anything that looks like a marker.
- **(a) Leave them**, rely on random markers + prompt rule.
- **(b) Defuse**: change the brackets (`<LOGS END>` → `(LOGS END)`). Text stays visible as evidence.
- **(c) Remove** the text. Cleaner for the model; evidence lost.
- **(d) Replace with a label** like `[removed: fake delimiter]`. Makes the attempt explicit.
- **(e) Escape every `<` and `>`** in every line. Broader, but also changes real attack text like `<script>` (A03).

Sub-choice: what counts as a fake marker — only `LOGS` / `LOG_DATA` patterns (narrow), or anything tag-shaped (broad, risks altering real evidence).
Recommendation: (b), narrow pattern.
**Decision:** _open_

## Decision 4 — Labelling each line
**Purpose:** make entry boundaries obvious, so injected text is clearly inside one attacker-controlled line.
- **(a) No labels.**
- **(b) `[line 1] …`** — clear, but the model may copy labels into `related_logs`.
- **(c) `[untrusted line 1] …`** — stronger wording, more tokens.

Recommendation: (b), and watch `related_logs` in the test runs (least certain of the recommendations).
**Decision:** _open_

## Decision 5 — Transforming the text itself
**Purpose:** research defenses ("datamarking", "encoding") change the text so injected instructions don't read as natural language.
- **(a) No transformation** beyond Decision 3.
- **(b) Datamarking**: spaces → a symbol (`GET^/index.html^HTTP/1.1`). Effective on big models; may confuse a 3B model and hurt clean-log accuracy.
- **(c) Encoding** (e.g. base64). Small models decode badly.

Recommendation: (a) for Defense 1; (b) as a possible later experiment.
**Decision:** _open_

## Decision 6 — Other hiding tricks
**Purpose:** characters a human can't see can hide or disguise instructions. Not covered by the current test cases.
- **Invisible characters** (zero-width spaces): remove / make visible / leave.
- **Hidden line breaks** (`\r`, Unicode line separators): normalize to a visible marker / leave.
- **Terminal colour codes**: remove / leave.
- **Very long lines**: cap per line (noting the cut) / no cap. A cap limits runaway output (S04) but could cut a real payload.

Recommendation: handle invisible characters and line breaks (cheap, don't touch normal text); unsure about a length cap.
**Decision:** _open_

## Decision 7 — What the function returns
**Purpose:** whether Defense 2 (code cross-check) can see what Defense 1 found.
- **(a) Only the wrapped text** — drop-in at both call sites.
- **(b) Also a small report** (fake markers defused, suspicious lines) that Defense 2 can use, e.g. "fake delimiter present → don't allow INFO". A little more plumbing.

Recommendation: (a) now, add the report when building Defense 2.
**Decision:** _open_

## Decision 8 — Empty chunk
**Purpose:** a chunk with no lines must not break the prompt. Rare (batch chunks are never empty).
- **(a) Markers with nothing between.**
- **(b) Markers plus a note** like `[no log lines]`.

Recommendation: (a).
**Decision:** _open_

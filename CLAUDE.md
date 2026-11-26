# CLAUDE.md

Fork of LogSentinelAI (`call518/LogSentinelAI`, MIT) being hardened against prompt/log injection.
**`project-plan.md` is the source of truth** — read it first, especially "Start Here" and "Current status".

## Working rules
- Small, reviewable changes; explain every change — the author must be able to explain each line in an interview.
- Ask before acting on anything beyond what was requested; report findings before changing code.
- Don't change upstream code until the injection point has been reported (second task in the plan).
- Public/synthetic data only (Loghub, `sample-logs/`). No Elasticsearch/Kibana/Telegram yet — printed/saved JSON only.
- Only one Claude session should edit files at a time.

## Logging rules (required)
`run-log.md` and `project-plan.md` are the project's development record — the author uses them for the write-up and interviews.

**Test runs → `run-log.md`**
- Every test run gets an entry, including runs the author does and pastes in. Add it right after the run, before moving on.
- Entry format: `## Run N — YYYY-MM-DD — short title`, then:
  - Goal (one line)
  - Settings table: date/time (UTC), code (commit hash + modified/unmodified), analyzer, input, chunk size, model (+ Ollama version), command
  - Results table per chunk: time, prompt tokens, response tokens, valid JSON / schema, verdict
  - Manual verdict check: was the verdict actually correct?
  - Observations: errors, hallucinations, bugs, anything relevant to the injection work
- Failed or aborted runs are logged too, with the error.

**Project status → `project-plan.md`**
- Any status change — task finished, decision made (with the reason), problem found, plan changed — gets a dated entry in the **Development Log** section, and the **Current status** summary is updated to match.

**For both files**
- Append-only: never rewrite or delete past entries. Corrections go in as a new dated entry that refers to the old one.
- Log updates go in the same commit as the work they describe.
- Redact private details (hostnames, home/LAN IPs, usernames) — the repo is public.
- Before ending a session or a piece of work, check that both files are up to date.

## Privacy rules (required) — the repo is public
- Never commit: `.env`, `runs/`, `*.mmdb`, `logsentinelai.log`, raw tool output, or anything copied from it unredacted.
- Never write into tracked files or commit messages: the author's hostname, LAN/home IP, Windows username or user-folder paths, email addresses, real name beyond the GitHub username, API keys/tokens. The tool's `@host` field holds hostname + LAN IP — always drop it when quoting results.
- Commit author email must be a GitHub noreply address (`<ID>+<username>@users.noreply.github.com`).
- Enforced by `scripts/privacy_check.py`, run by local git hooks (`.git/hooks/pre-commit`, `.git/hooks/commit-msg`). Personal strings live in `.privacy-denylist`. The script, the denylist and the hooks are all **local only** (gitignored / untracked) — never commit them. Never bypass with `--no-verify`; if the check blocks a commit, redact and retry. Use the `privacy-allow` marker only for deliberate safe examples, and tell the author.
- New clone? The script and denylist must be copied over from the old clone, and the hooks reinstalled:
  `.git/hooks/pre-commit` → `exec .venv/Scripts/python.exe scripts/privacy_check.py`
  `.git/hooks/commit-msg` → `exec .venv/Scripts/python.exe scripts/privacy_check.py --msg "$1"`

## Environment (Windows 10, PowerShell)
- Python **3.12** via uv (`.python-version` = 3.12; project requires >=3.11,<3.13). Venv: `.venv`.
- Install/refresh deps: `uv sync --extra dev --locked`
- Run CLI: `uv run logsentinelai --help` (or `.\.venv\Scripts\logsentinelai.exe`)
- Tests: `uv run --extra dev pytest -q --no-cov` (plain `uv run` re-syncs without the dev extra and removes pytest)
- **Set `PYTHONUTF8=1`** — the tool logs emoji, which crash the logger under the default Windows cp1252 console encoding.
- Hardware: i5-1235U, 16 GB RAM, Intel Iris Xe, no NVIDIA GPU → Ollama runs on CPU.

## Config
- Config is loaded from `./.env` (gitignored; created from `.env.template`). Never commit it.
- Local changes from the template: `LLM_PROVIDER=ollama`, `LLM_MODEL_OLLAMA=qwen2.5:3b`,
  `LLM_MAX_TOKENS_OLLAMA=4096`, `TELEGRAM_ENABLED=false`, `GEOIP_ENABLED=false`, `LOG_FILE=logsentinelai.log`.
- Ollama endpoint: `LLM_API_HOST_OLLAMA=http://127.0.0.1:11434/v1` (OpenAI-compatible). Keep Ollama bound to 127.0.0.1.
- Ollama: `OLLAMA_CONTEXT_LENGTH=8192`. Models: `qwen2.5:3b` for development, `qwen2.5:7b` for before/after runs.
  The user is installing Ollama themselves — don't install it.

## Code map
- CLI entry: `src/logsentinelai/cli.py`; analyzers: `src/logsentinelai/analyzers/` (httpd_access, httpd_server, linux_system, general_log).
- Config loading: `src/logsentinelai/core/config.py`; shared logic: `src/logsentinelai/core/commons.py`.
- Sample logs: `sample-logs/` (access-10k.log, apache-10k.log, linux-2k.log).

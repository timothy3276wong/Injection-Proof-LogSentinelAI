# Injection Point Report — LogSentinelAI

_Second task in `project-plan.md`. Read-only trace of unmodified upstream code (`f77fe7c`), 2026-11-24. No code was changed._

## Summary
Every analyzer (HTTP access, Apache error, Linux system, general) in both batch and real-time mode inserts raw log text into the LLM prompt with Python's `str.format()`, with no sanitization, escaping or labelling as untrusted data. Instructions and log data are sent together as a single user message. Structured output (Outlines + Ollama `json_schema`) fixes the *shape* of the answer, but not its *values*, and no code checks the values before they drive alerts.

## Data flow
```
log file
  → read line by line, whitespace stripped only      commons.py:1052-1082
  → chunk_buffer (chunk_size lines)                  commons.py:1086-1092
  → prompt_template.format(logs=...)   ⭐ INJECTION   commons.py:1238-1240  (batch)
                                       ⭐ INJECTION   commons.py:625-633    (real-time)
  → process_log_chunk → generate_with_model           commons.py:178
  → one "user" message + json_schema response_format  llm.py:184 → outlines/models/openai.py:68-76, 200-217
  → JSON parsed + Pydantic-validated                  commons.py:185, 263
  → Elasticsearch + Telegram alert (severity-based)   commons.py:270 → elasticsearch.py:104-116
```

## The injection points
**Batch mode:** `src/logsentinelai/core/commons.py:1238-1240`
```python
logs = "\n".join(chunk_buffer).rstrip("\n")
model_schema = analysis_schema_class.model_json_schema()
prompt = prompt_template.format(logs=logs, model_schema=model_schema, response_language=response_language)
```

**Real-time mode:** `src/logsentinelai/core/commons.py:625-633` (`prepare_chunk_for_analysis`): the same `.format()` pattern.

These are the only two places a prompt is built. Both feed the single model call at `commons.py:178`, so one fix covers all four log types.

**The templates:** `src/logsentinelai/core/prompts.py`. The four templates (lines 2, 65, 120, 176) all end with:
```
<LOGS BEGIN>
{logs}
<LOGS END>
```
No template says the log content is untrusted or should be treated as data only.

## Why it is injectable
1. **Raw insertion.** Log text controlled by an attacker (URL, user-agent, username, message) is pasted into the prompt unchanged. The only processing is `line.strip()` (`commons.py:1078`). A search of `src/` found no sanitizing, escaping, filtering or marker handling.
2. **No separation between instructions and data.** Outlines turns a string prompt into one `user` message (`outlines/models/openai.py:68-76`). The analyst's rules and the attacker's text arrive in the same block.
3. **Fakeable delimiters.** A log line can contain the literal text `<LOGS END>` followed by new "instructions". To the model, the log block appears to end there and the rules appear to continue.
4. **Format enforced, values unchecked.** Ollama enforces the schema (`response_format: json_schema, strict: true`, `openai.py:200-217`), so output is always valid JSON. But the model alone decides `severity`, and no code checks it.

## What an attacker would target
From `src/logsentinelai/core/elasticsearch.py`:
- **Alert decision:** a Telegram alert fires if **any event's `severity`** is at or above `TELEGRAM_ALERT_LEVEL` (default CRITICAL), or if processing fails (lines 104-116). Nothing else decides it.
- **Shown in the alert but not used to decide it:** `highest_severity`, `requires_immediate_attention`, `requires_human_review` (lines 134-139, 217).
- **Copied from model output into the alert text:** `description`, up to 3 `related_logs`, up to 3 `recommended_actions` (lines 203-245). Sent as plain text (`utils/telegram_alert.py:27`), so no formatting injection, but links still display.
- **No cross-check:** nothing compares `highest_severity` with the events, or the statistics with the real chunk.

Resulting attack goals, each one a future test case:
1. **Suppress:** a real attack line gets `severity: INFO` → no alert.
2. **Fake alarm:** a harmless line gets `severity: CRITICAL` → false alert.
3. **Poison text:** misleading `description` / `recommended_actions` copied into alerts and Kibana.

## Where the defense goes
| Location | Defense layer (project-plan.md) |
|---|---|
| `commons.py:1240` and `:629`, the `.format()` calls | Delimiting / spotlighting: mark or encode each log line before insertion |
| `prompts.py` templates | Hardened prompt: say explicitly that logs may contain manipulation attempts |
| `llm.py:184`, pass an Outlines `Chat` (`openai.py:88`) instead of a string | Put rules in a system message and logs in the user message |
| `commons.py:262-266`, after validation, before output | Code cross-check: plain rules can override the model's verdict |

## Side findings
- **`@log_path` metadata bug:** `commons.py:1277` passes `config.get("log_path")`, the `.env` default, not the file actually processed. Explains Run 1 observation 3.
- **Field names:** the plan's `is_attack` doesn't exist. The real fields are `severity`, `attack_patterns` and `highest_severity` (`analyzers/httpd_access.py:33-61`).
- **SSH batch mode** likely doesn't work: `_process_file_streaming_batch` checks `os.path.exists` locally on a remote path (`commons.py:1026`). Out of scope.

## Not yet verified
This is a code reading. No crafted log line has been run yet; that happens in the attack-design task.

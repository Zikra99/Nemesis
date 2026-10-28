# Nemesis

""Nemesis Demo" (https://img.youtube.com/vi/pFUOHMpxctQ/maxresdefault.jpg)" (https://youtu.be/pFUOHMpxctQ)
▶ **Click the image above to go to the video**
---

## What it is

Nemesis is a small CLI tool that runs a security assessment against a web target. You give it a URL and an instruction in plain English, and it comes back with a report.

The instruction is the only thing you type. Something like:

```
Find A05:2025 vulnerabilities on https://vulnbank.org
```

Everything after that is done by a language model running locally through Ollama. The Python code doesn't decide what to test or what payloads to send. It gives the model a target, a set of HTTP actions, and lets the model figure out the rest.

The end result is a report that maps whatever the model found back to OWASP Top 10:2025 categories and MITRE ATT&CK technique IDs.

---

## Why build it this way

Two design decisions that matter for the story:

**One: no payload library.** There is no `sqli_payloads.txt` in the repo. The model writes its own SQL injection strings on every run. That's the whole point of using an LLM instead of a script.

**Two: the code is deliberately dumb.** It only knows how to send HTTP requests and record what happened. It doesn't know what a vulnerability looks like. That judgement is the model's job.

---

## How it runs

Five phases, executed one after another. Each phase is a separate call to the local model.

```
1. Commander    -> turns your sentence into a structured directive
2. Recon        -> model browses the target with GET requests
3. Planning     -> model builds an attack plan (list of HTTP calls with payloads)
4. Execution    -> code fires the requests
5. Analysis     -> model reads the responses and calls record_finding
6. Reporting    -> model writes the summary, code assembles the report
```

Each phase is one Python method in `src/agent.py`. They're called in sequence from `run()`.

The phases exist because a 7B model trying to plan, execute, and analyse in one prompt produces garbage. Splitting it up gives each call a smaller job and a smaller prompt, which matters a lot on CPU.

---

## The files

```
main.py                 CLI entry point
requirements.txt        dependencies
.env.example            template (model name, log level, budget)
Modelfile               Ollama wrapper for DeepHat
src/
  agent.py              the six phases live here
  prompts.py            all prompt text
  tools.py              HTTP actions (get, post, record_finding)
  rag.py                MITRE + OWASP knowledge base, ChromaDB
  scope.py              domain authorization gate
  __init__.py
data/                   generated at runtime, not in git
```

---

## `main.py`

Parses the URL with a regex, shows the OWASP menu, calls the agent, prints the report. Roughly 100 lines.

The one thing worth pointing at: it doesn't contain any attack logic. If you deleted the file, the agent still works if you call `agent.run()` yourself.

---

## `src/agent.py`

The orchestrator. Open this file first during the demo.

`run()` calls the six phases in order. That method is the best summary of the whole project, maybe 40 lines.

`_call_llm()` is the only place that talks to Ollama. It retries on bad JSON, strips markdown fences, and validates the model's output against a Pydantic schema. Everything else in the file depends on this.

`_analyze_responses()` is the phase I want to show. This is where findings actually get created. It builds a transcript of every probe and response, sends it to the model, and asks "which of these prove a vulnerability". Whatever the model returns gets passed to `record_finding`.

Without this phase the model was firing payloads but never seeing the results, so it never recorded anything. That was the main bug I fixed after the first working prototype.

---

## `src/prompts.py`

All the prompt strings live here so you can read them without jumping around the code.

The one to look at is `PLANNING_PROMPT`. This is where the model is told to generate its own payloads. Two blocks inside it are worth discussing openly:

```text
MANDATORY for injection:
- Send at least 4 distinct payloads per parameter
- Do not send benign values like "test"/"admin"

MANDATORY response analysis:
- These strings in the body are STRONG evidence of SQL injection:
  "sql syntax", "unexpected token", "ORA-", "MySQL", "PostgreSQL", ...
```

they're guidance rails. The model still writes the payloads, but I'm telling it what to look for in responses. Without that hint the model was missing obvious SQL errors.

---

## `src/tools.py`

The model can call exactly three actions:

| action | what it does |
|--------|-------------|
| `http_get` | sends a GET, returns the full request and response |
| `http_post` | sends a POST with either form data or JSON body |
| `record_finding` | appends a finding to the list the reporter uses |

No other action exists. That's intentional. Everything the model wants to do has to happen through those three primitives.

Every request goes through `_request()` which checks two things: is this domain authorized (via `scope.py`), and have we hit our request budget. That's the only place safety is enforced. It's not the model's job.

The response formatter returns the raw response body (truncated), status code, headers, cookies, redirect chain. Everything the model needs to reason about what happened.

---

## `src/rag.py`

The knowledge base. Three sources, embedded into ChromaDB on first run, queried during planning:

- **MITRE ATT&CK** techniques, pulled from the official `mitre/cti` repo on GitHub. About 870 entries.
- **Atomic Red Team** YAMLs, currently just `T1059` as a representative sample.
- **OWASP Top 10:2025** categories, stored as a small dict in the file (name and rank only).

When the planner needs context, it queries by `objective_summary + focus_owasp_categories` and gets back the top 8 most similar documents. Those show up in the planning prompt as bullet lists like:

```
Relevant MITRE ATT&CK context:
- T1190: Exploit Public-Facing Application

Relevant OWASP Top 10:2025 context:
- A05:2025: Injection
```

What this does: the model gets authoritative names and IDs to classify findings against, instead of inventing them. It does not give the model payloads — MITRE and OWASP don't contain payloads.

First run builds the index in about 30 seconds. Subsequent runs skip it.

---

## `src/scope.py`

The authorization gate. On first contact with a new domain, it prompts the operator to type the domain name back. If it matches, the domain is saved to `data/authorized_targets.json` and future runs skip the prompt.

This is the one control I'm not handing to the model. Whether a target is allowed to be tested is a human decision. Everything else — what to test, how, what counts as a finding — the model decides.

Mention this explicitly if anyone asks about safety. It's the reason the tool doesn't ship as "point at any URL".

---

## The flow, concretely

For the demo target `vulnbank.org` with A05:2025 selected:

**Commander.** Model reads the goal. Returns:

```json
{
  "objective_summary": "Find injection vulnerabilities in the login flow",
  "scope_mode": "targeted",
  "focus_owasp_categories": ["A05:2025"],
  "focus_paths": ["/login"]
}
```

**Recon.** Model returns up to 8 GET steps. The agent fetches `/`, `/login`, `/api/login`, and a few others. `/api/login` returns 405, `/login` returns 200 with a form.

**Planning.** RAG returns `T1190` and `A05:2025` as relevant context. Model produces the attack plan. This is the JSON array of POST requests with payloads:

```json
[
  {"action_name": "http_post", "parameters": {
    "url": "https://vulnbank.org/login",
    "data": {"username": "' OR '1'='1", "password": "x"}
  }},
  {"action_name": "http_post", "parameters": {
    "url": "https://vulnbank.org/login",
    "data": {"username": "' UNION SELECT NULL--", "password": "x"}
  }}
]
```

**Execution.** Agent fires each request. Responses logged.

**Analysis.** Model sees the response bodies. One of them came back 500 with a Python traceback. Model decides that's a finding and calls `record_finding` with the traceback snippet as evidence.

**Reporting.** Model writes three sentences of executive summary. Python builds the full report with sections and action log.

Total wall time on CPU: roughly 5 to 10 minutes depending on how many payloads the model generates.

---

## What's the model actually doing vs. the code

**The model is doing:**
- Choosing which endpoints to hit
- Writing every payload
- Deciding which responses prove a vulnerability
- Choosing OWASP category and MITRE technique
- Writing the executive summary

**The code is doing:**
- Sending HTTP requests
- Enforcing scope and budget
- Truncating responses to fit in context window
- Assembling the final report structure

**The grey area (prompt hints):**
- Telling the model to send 4 payloads per parameter
- Telling the model which strings suggest SQL injection
- Telling the model to prefer 500 errors over other evidence

"isn't that hardcoded"; the payloads aren't, but the hints about what to look for are. Removing them makes the tool less reliable. I chose reliability over purity for this demo.

---

## Known limitations


**The model doesn't know request format until it tries.** Vulnbank's `/login` endpoint expects `application/json`. On the successful run the model sent form data (`data=`) and the server crashed before running the query. That gave us a traceback as evidence rather than the cleaner SQL error we'd get from a JSON request. The model picks format based on the form it sees in the HTML, and for API endpoints it guesses wrong.

**CPU inference is slow.** 7B model on CPU is roughly 5 to 10 tokens per second. The planning phase takes 2 to 5 minutes on a good day. On a GPU the same run would be 30 seconds.

**Scope authorization is per-domain.** It doesn't do subdomains, ports, or paths. If you authorize `example.com`, `api.example.com` is separately prompted. That's crude but it's the right direction for a demo.

---



















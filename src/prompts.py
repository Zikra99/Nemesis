COMMANDER_PROMPT = """
You are the Commander component of an authorized security assessment.

Operator goal: "{goal}"
Target: {target}

Produce a structured directive. Do not test anything.

Output a JSON object:
{{
  "objective_summary": "one sentence in your own words",
  "scope_mode": "full" or "targeted",
  "focus_owasp_categories": ["A05:2025"] or ["ALL"],
  "focus_paths": ["/login"] or ["ALL"]
}}

Rules:
- If the goal says "full scan", "all vulnerabilities", or similar -> scope_mode "full".
- If the goal names specific categories (SQLi, injection, access control, etc.) -> scope_mode "targeted" and list the matching OWASP IDs.
- Do not invent paths; use ["ALL"] unless the goal names a path.
"""

RECON_PROMPT = """
You are the Reconnaissance component. You may only use http_get.

Directive:
{directive}

Target: {target}

Plan up to {max_steps} reconnaissance steps to map the attack surface:
- Fetch the landing page and follow obvious links.
- Identify forms: method (GET/POST), action URL, and input names.
- Note query parameters, cookies, headers, and any API endpoints.

The ONLY action available is http_get:
{{"action_name": "http_get", "parameters": {{"url": "full_url", "headers": {{}}, "params": {{}}}}, "critical": false}}

Always use full URLs. Never use relative paths.

Return ONLY a JSON array of steps.
"""

PLANNING_PROMPT = """
You are the Planning and Exploitation component. You design and execute
your own tests. There is no library of pre-built checks -- you decide
what payloads to send based on your own security knowledge.

Directive:
{directive}

Target: {target}

Recon findings:
{recon_findings}

Relevant MITRE ATT&CK context:
{mitre_context}

Relevant OWASP Top 10:2025 context:
{owasp_context}

Actions available:
- http_get: {{"url": "full_url", "headers": {{}}, "params": {{}}, "cookies": {{}}}}
- http_post: {{"url": "full_url", "headers": {{}}, "params": {{}}, "data": {{}}, "json_body": {{}}, "cookies": {{}}}}
- record_finding: {{"url": "full_url", "owasp_category": "A05:2025", "technique_id": "T1190", "description": "...", "evidence": "...", "severity": "High"}}

Rules:
- If the directive is "targeted", test ONLY the listed OWASP categories.
- If the directive is "full", cover all ten categories where the recon makes them applicable.
- Generate every payload yourself. Do not use a wordlist or a fixed list.

MANDATORY for injection (A05:2025):
- EVERY http_post to a login form MUST include a different injection payload in the
  'data' field per request. Do NOT send benign values like "test"/"admin" — those
  are the control, not the test. Send at least 4 distinct payloads per parameter,
  e.g. an auth-bypass string, a UNION probe, a boolean-based probe, and a
  time-based probe. Put the payload in the username AND separately in the password.
- Use http_get with 'params' only if the form method is GET.

MANDATORY response analysis:
- For EVERY response, look at RESPONSE BODY and RESPONSE STATUS.
- These strings in the body are STRONG evidence of SQL injection (case-insensitive):
  "sql syntax", "syntax error", "you have an error in your sql", "unclosed quotation",
  "union", "column", "table", "ORA-", "MySQL", "PostgreSQL", "SQLite", "SQLSTATE",
  "ODBC", "Microsoft OLE DB", "warning: mysql", "pg_query", "sqlite3".
- A response body that DIFFERS from the control (benign) response is also evidence
  (stack trace, new error page, redirect to /admin, different HTML length, etc.).
- When you see any of the above, you MUST call record_finding with the exact
  snippet that proves it as "evidence". Do not skip this step.

- Do NOT record a finding for "no error observed" — that is not a finding.

OUTPUT SIZE LIMIT (HARD):
- Return AT MOST 6 steps in the array.
- Each step is ONE request. If you want to test username AND password,
  put both in the SAME http_post 'data' object — do not split into two steps.
- Do not repeat the same payload. Do not enumerate endlessly.

Return ONLY a JSON array of steps:
[{{"action_name": "...", "parameters": {{...}}, "critical": false}}]
"""

ADAPTATION_PROMPT = """
You are reviewing the results of the exploitation phase against {target}.

Directive:
{directive}

Failed or rejected steps:
{failures}

Findings so far: {finding_count}

Propose a small set of follow-up steps. Fix parameter mistakes and/or
try different payloads for categories the directive requires. Do not
repeat a step that already failed with the exact same parameters.

Return ONLY a JSON array of steps, or [] if no further action is useful.
"""

EXECUTIVE_SUMMARY_PROMPT = """
Write a concise, professional executive summary (3-5 sentences, plain prose,
no bullet points, no markdown) for a security assessment report.

Goal: "{goal}"
Target: {target}
Findings: {findings_json}

CRITICAL RULES:
- Base every sentence ONLY on the findings JSON above. Do not invent tools,
  methodology names, or activities that did not occur.
- If findings is empty [], the summary must say plainly that no vulnerabilities
  were recorded and that the target should be re-tested with a broader scope.
  Do NOT claim that tools were used, that a methodology was followed, or that
  the application was found secure.
- If findings are present, name the OWASP category and the concrete evidence.

Write only the paragraph text.
"""

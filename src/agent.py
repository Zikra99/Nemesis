import json
import re
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import ollama
from pydantic import BaseModel, Field

from src import scope
from src.prompts import (
    ADAPTATION_PROMPT, COMMANDER_PROMPT, EXECUTIVE_SUMMARY_PROMPT,
    PLANNING_PROMPT, RECON_PROMPT,
)
from src.rag import OWASP_TOP_10_2025, RAGRetriever
from src.tools import ActionLibrary

import httpx as _httpx

logger = logging.getLogger(__name__)
OLLAMA_TIMEOUT = 600  # 10 min hard ceiling per LLM call

MAX_RECON_STEPS = 8
MAX_ADAPTATION_ROUNDS = 2


class AgentPlanningError(Exception):
    pass


class DirectiveSchema(BaseModel):
    objective_summary: str
    scope_mode: str = Field(description="'full' or 'targeted'")
    focus_owasp_categories: List[str]
    focus_paths: List[str]


class StepSchema(BaseModel):
    action_name: str
    parameters: Dict[str, Any]
    critical: bool = False


class StepListSchema(BaseModel):
    steps: List[StepSchema]


class RedTeamAgent:
    def __init__(self, retriever: RAGRetriever,
                 actions: Optional[ActionLibrary] = None):
        self.retriever = retriever
        self.actions = actions or ActionLibrary()
        self.model = os.getenv("OLLAMA_MODEL", "DeepHat/DeepHat-V1-7B")
        self.execution_history: List[Dict] = []
        self.start_time = time.time()

    def run(self, goal: str, target: str) -> str:
        logger.info(f"Agent received goal: {goal}")
        logger.info(f"Target: {target}")

        directive = self._commander_phase(goal, target)
        logger.info(f"Directive: {directive}")

        recon_findings = self._recon_phase(directive, target)
        logger.info("Reconnaissance complete.")

        plan = self._planning_phase(directive, target, recon_findings)
        results = self._execute(plan)
        self._analyze_responses(directive, target, results)

        for round_num in range(1, MAX_ADAPTATION_ROUNDS + 1):
            if not self._needs_adaptation(directive, results):
                break
            logger.info(f"Adaptation round {round_num}...")
            revised = self._adaptation_phase(directive, target, results)
            if not revised:
                break
            results.extend(self._execute(revised))

        return self._reporting_phase(goal, target, directive, results)

    def _call_llm(self, prompt: str, schema, what: str) -> Any:
        logger.info(f"Calling Ollama ({self.model}) for {what}...")
        last_err = None
        for attempt in range(1, 3):
            start = time.time()
            try:
                response = ollama.Client(timeout=OLLAMA_TIMEOUT).chat(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    options={"temperature": 0.2 if attempt == 1 else 0.0,
                             "num_ctx": 8192,
                             "num_predict": 800},   # hard cap output tokens
                    keep_alive="30m",
                )
                content = response["message"]["content"].strip()
                content = re.sub(r"```(?:json)?\s*", "", content)
                content = re.sub(r"```\s*$", "", content)
                m = re.search(r"(\{.*\}|\[.*\])", content, re.DOTALL)
                if m:
                    content = m.group(0)
                logger.info(f"Ollama responded in {time.time() - start:.1f}s "
                            f"(attempt {attempt})")
                data = json.loads(content)
                # DeepHat returns a raw array; wrap it if the schema expects steps
                if schema is StepListSchema and isinstance(data, list):
                    data = {"steps": data}
                elif schema is DirectiveSchema and isinstance(data, list) and data:
                    data = data[0]
                return schema.model_validate(data)
            except Exception as e:
                last_err = e
                logger.warning(f"LLM attempt {attempt} for {what} failed: {e}")
                prompt += "\n\nYour entire response must be valid JSON only, no prose."
        raise AgentPlanningError(f"Could not get valid {what}: {last_err}")

    def _commander_phase(self, goal: str, target: str) -> Dict:
        prompt = COMMANDER_PROMPT.format(goal=goal, target=target)
        schema = self._call_llm(prompt, DirectiveSchema, "commander directive")
        return {
            "target": target,
            "objective_summary": schema.objective_summary,
            "scope_mode": schema.scope_mode if schema.scope_mode in ("full", "targeted") else "targeted",
            "focus_owasp_categories": schema.focus_owasp_categories or ["ALL"],
            "focus_paths": schema.focus_paths or ["ALL"],
        }

    def _recon_phase(self, directive: Dict, target: str) -> str:
        prompt = RECON_PROMPT.format(
            directive=json.dumps(directive, indent=2),
            target=target, max_steps=MAX_RECON_STEPS,
        )
        try:
            result = self._call_llm(prompt, StepListSchema, "recon plan")
            steps = [s.model_dump() for s in result.steps]
        except AgentPlanningError as e:
            logger.warning(f"Recon failed: {e}; continuing without recon.")
            return "No reconnaissance data gathered."

        results = self._execute(steps)
        lines = ["RECONNAISSANCE FINDINGS:"]
        for r in results:
            step = r.get("step", {})
            lines.append(f"[{step.get('action_name')}] status={r.get('status')}")
            if r.get("status") == "success":
                lines.append(str(r.get("result"))[:500])
        text = "\n".join(lines)
        # Hard cap total recon text so it can't blow the context window
        if len(text) > 3000:
            text = text[:3000] + "\n... [recon truncated]"
        return text

    def _planning_phase(self, directive: Dict, target: str, recon_findings: str) -> List[Dict]:
        query = directive["objective_summary"] + " " + " ".join(directive["focus_owasp_categories"])
        grouped = self.retriever.retrieve_grouped(query, top_k=8)
        mitre_text = "\n".join(f"- {d['ref_id']}: {d['name']}" for d in grouped.get("mitre_attack", [])) or "(none)"
        owasp_text = "\n".join(f"- {d['ref_id']}: {d['name']}" for d in grouped.get("owasp_top10_2025", [])) or "(none)"
        prompt = PLANNING_PROMPT.format(
            directive=json.dumps(directive, indent=2), target=target,
            recon_findings=recon_findings, mitre_context=mitre_text,
            owasp_context=owasp_text,
        )
        result = self._call_llm(prompt, StepListSchema, "exploitation plan")
        return [s.model_dump() for s in result.steps]

    def _execute(self, plan: List[Dict]) -> List[Dict]:
        results = []
        for step in plan:
            action_name = step.get("action_name")
            params = step.get("parameters", {}) or {}
            try:
                result = self.actions.execute(action_name, **params)
                logger.info(f"Executed {action_name} -> {str(result)[:180]}")
                if action_name in ("http_post", "http_get"):
                    req_body = params.get("data") or params.get("json_body") or params.get("params")
                    if req_body:
                        logger.info(f"  >> REQUEST PAYLOAD: {req_body}")
                results.append({"step": step, "status": "success", "result": result})
            except scope.ScopeViolation as e:
                results.append({"step": step, "status": "refused", "error": str(e)})
            except Exception as e:
                logger.error(f"Action {action_name} failed: {e}")
                results.append({"step": step, "status": "failed", "error": str(e)})
        self.execution_history.extend(results)
        return results

    # ------------------------------------------------------------------
    # Phase 4b: Response Analysis — the LLM sees every response and
    # decides which ones prove a vulnerability, then calls record_finding.
    # ------------------------------------------------------------------
    def _analyze_responses(self, directive: Dict, target: str, results: List[Dict]) -> None:
        http_results = [r for r in results if r.get("status") == "success"
                        and r.get("step", {}).get("action_name") in ("http_get", "http_post")]
        if not http_results:
            return

        # Build a compact transcript of each request/response pair
        transcript_parts = []
        for i, r in enumerate(http_results, 1):
            step = r["step"]
            action = step.get("action_name")
            params = step.get("parameters", {}) or {}
            payload = params.get("data") or params.get("json_body") or params.get("params") or {}
            body = str(r.get("result", ""))
            # Trim to keep the prompt manageable
            if len(body) > 2500:
                body = body[:2500] + "\n... [truncated]"
            transcript_parts.append(
                f"--- Probe #{i} ---\n"
                f"Action: {action}\n"
                f"Sent: {payload}\n"
                f"Response:\n{body}\n"
            )
        transcript = "\n".join(transcript_parts)
        if len(transcript) > 8000:
            transcript = transcript[:8000] + "\n... [transcript truncated]"

        prompt = f"""You are the Analysis component. You previously sent the following
HTTP probes to {target} for OWASP category(ies) {directive.get('focus_owasp_categories')}.
Now you must analyse the responses and decide which ones prove a vulnerability.

PROBES AND RESPONSES:
{transcript}

RULES:
- A finding is ONLY justified if the response body or status clearly indicates the
  vulnerability (e.g. SQL syntax error, stack trace with DB driver names, reflected
  payload, different length than control, redirect to /admin, HTTP 500 on injection).
- "No visible change" is NOT a finding.
- Do NOT invent findings to be thorough. If nothing proves a vulnerability, return [].
- For each confirmed finding, produce exactly one object in the output array.
- EVIDENCE RANKING (pick the best available, in order):
  1. SQL/database error strings from the response body (e.g. "syntax error", "SQLSTATE",
     "You have an error in your SQL syntax", "unclosed quotation", "each UNION query").
  2. HTTP 500/502 status with a stack trace or error page that appeared ONLY for the
     injected payload, not for the benign control.
  3. A response body whose length or content differs drastically from the control.
  4. A redirect to /admin or /dashboard that did not happen with the control.
- Do NOT use Python/Node traceback fragments like "NoneType object has no attribute"
  as primary evidence — they indicate a crash but not specifically injection. Quote the
  surrounding line if it contains SQL or query context; otherwise prefer the HTTP status.

OUTPUT: a JSON array of findings, each with:
  {{"url": "...", "owasp_category": "A05:2025", "technique_id": "T1190",
    "description": "...", "evidence": "exact snippet from the response",
    "severity": "High"}}
Return ONLY a JSON array (possibly []). No prose.
"""
        try:
            response = ollama.Client(timeout=OLLAMA_TIMEOUT).chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.1, "num_ctx": 8192},
            )
            content = response["message"]["content"].strip()
            content = re.sub(r"```(?:json)?\s*", "", content)
            content = re.sub(r"```\s*$", "", content)
            m = re.search(r"\[.*\]", content, re.DOTALL)
            if not m:
                logger.info("Analysis phase: no findings array in output; skipping.")
                return
            findings = json.loads(m.group(0))
            if not isinstance(findings, list) or not findings:
                logger.info("Analysis phase: model reported no confirmed findings.")
                return
            for f in findings:
                try:
                    self.actions._record_finding(
                        url=f.get("url", target),
                        owasp_category=f.get("owasp_category", "A05:2025"),
                        technique_id=f.get("technique_id", "T1190"),
                        description=f.get("description", "Unspecified"),
                        evidence=f.get("evidence", ""),
                        severity=f.get("severity", "Medium"),
                    )
                except Exception as e:
                    logger.warning(f"Could not record finding: {e}")
        except Exception as e:
            logger.warning(f"Analysis phase failed: {e}")


    def _needs_adaptation(self, directive: Dict, results: List[Dict]) -> bool:
        failed = [r for r in results if r.get("status") in ("failed", "refused")]
        has_success = any(r.get("status") == "success" for r in results)
        no_findings = len(self.actions.recorded_findings) == 0
        if failed and has_success:
            return True
        if directive.get("scope_mode") == "full" and no_findings and has_success:
            return True
        return False

    def _adaptation_phase(self, directive: Dict, target: str, results: List[Dict]) -> List[Dict]:
        failures = [
            {"action": r["step"].get("action_name"),
             "parameters": r["step"].get("parameters"),
             "error": r.get("error")}
            for r in results if r.get("status") in ("failed", "refused")
        ]
        prompt = ADAPTATION_PROMPT.format(
            target=target, directive=json.dumps(directive, indent=2),
            failures=json.dumps(failures, indent=2) if failures else "(none)",
            finding_count=len(self.actions.recorded_findings),
        )
        try:
            result = self._call_llm(prompt, StepListSchema, "adaptation plan")
            return [s.model_dump() for s in result.steps]
        except AgentPlanningError:
            return []

    def _executive_summary(self, goal: str, target: str, findings: List[Dict]) -> str:
        prompt = EXECUTIVE_SUMMARY_PROMPT.format(
            goal=goal, target=target,
            findings_json=json.dumps(
                [{"category": f.get("owasp_category"), "severity": f.get("severity"),
                  "description": f.get("description")} for f in findings], indent=2),
        )
        try:
            response = ollama.Client(timeout=OLLAMA_TIMEOUT).chat(model=self.model,
                                   messages=[{"role": "user", "content": prompt}],
                                   options={"temperature": 0.3})
            return response["message"]["content"].strip() or "No executive summary generated."
        except Exception:
            return "Executive summary could not be generated."

    def _reporting_phase(self, goal: str, target: str, directive: Dict,
                         results: List[Dict]) -> str:
        duration = time.time() - self.start_time
        mins, secs = divmod(int(duration), 60)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        findings = self.actions.recorded_findings
        normalized = []
        for f in findings:
            cat = f.get("owasp_category") or ""
            if cat not in OWASP_TOP_10_2025:
                cat = "Unclassified"
            normalized.append({**f, "owasp_category": cat})
        severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
        highest = max((severity_rank.get(f.get("severity", "Medium"), 2) for f in normalized), default=-1)
        risk = ["No findings", "Low", "Medium", "High", "Critical"][highest + 1] if highest >= 0 else "No findings"
        executive = self._executive_summary(goal, target, normalized)
        by_cat: Dict[str, List[Dict]] = {}
        for f in normalized:
            by_cat.setdefault(f["owasp_category"], []).append(f)
        lines = [
            "=" * 72, "NEMESIS -- SECURITY ASSESSMENT REPORT", "=" * 72, "",
            f"Target:          {target}",
            f"Date:            {now}",
            f"Duration:        {mins}m {secs}s",
            f"Overall Risk:    {risk}",
            f"Scope:           {directive.get('scope_mode')} "
            f"({', '.join(directive.get('focus_owasp_categories', ['ALL']))})",
            f"Requests sent:   {self.actions.request_count}",
            f"Findings:        {len(normalized)}", "",
            "EXECUTIVE SUMMARY", "-" * 72, executive, "",
        ]
        if not normalized:
            lines.append("No vulnerabilities were recorded during this assessment.")
        else:
            lines.append("DETAILED FINDINGS")
            lines.append("-" * 72)
            for cat_id in sorted(by_cat):
                info = OWASP_TOP_10_2025.get(cat_id)
                heading = f"{cat_id} -- {info['name']}" if info else cat_id
                lines.append("")
                lines.append(heading)
                lines.append("." * len(heading))
                for item in by_cat[cat_id]:
                    lines.append(f"  URL:       {item.get('url')}")
                    lines.append(f"  Severity:  {item.get('severity', 'Medium')}")
                    if item.get("technique_id"):
                        lines.append(f"  ATT&CK:    {item.get('technique_id')}")
                    lines.append(f"  Detail:    {item.get('description')}")
                    lines.append(f"  Evidence:  {item.get('evidence')}")
                    lines.append("")
        lines.append("")
        lines.append("ACTION LOG")
        lines.append("-" * 72)
        for entry in results:
            step = entry.get("step", {})
            action = step.get("action_name", "?")
            status = entry.get("status", "?")
            detail = str(entry.get("result", entry.get("error", "")))[:120].replace("\n", " ")
            lines.append(f"  {action:<18} {status:<10} {detail}")
        lines.append("")
        lines.append("Report generated by Nemesis.")
        return "\n".join(lines)

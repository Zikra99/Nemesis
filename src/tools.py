import logging
import time
from typing import Any, Dict, List, Optional

import requests

from src import scope

logger = logging.getLogger(__name__)

USER_AGENT = "Nemesis-RedTeam-Agent/2.0 (authorized-security-test)"
MAX_BODY_PREVIEW = 4000


class RequestBudgetExceeded(Exception):
    pass


class ActionLibrary:
    def __init__(self, request_delay: float = 0.25, max_requests: int = 800):
        self.actions = {
            "http_get": self._http_get,
            "http_post": self._http_post,
            "record_finding": self._record_finding,
        }
        self.request_delay = request_delay
        self.max_requests = max_requests
        self.request_count = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.recorded_findings: List[Dict] = []

    def list_actions(self):
        return list(self.actions.keys())

    def execute(self, action_name: str, **kwargs):
        if action_name not in self.actions:
            raise ValueError(f"Unknown action: {action_name}")
        return self.actions[action_name](**kwargs)

    def _request(self, method: str, url: str, **kwargs) -> Any:
        if not scope.confirm_authorized(url):
            raise scope.ScopeViolation(
                f"'{url}' is not an authorized target. Refusing to send traffic."
            )
        if self.request_count >= self.max_requests:
            raise RequestBudgetExceeded(
                f"Hit the {self.max_requests}-request budget for this run."
            )
        kwargs.setdefault("timeout", 15)
        try:
            resp = self.session.request(method, url, **kwargs)
            self.request_count += 1
            time.sleep(self.request_delay)
            return resp
        except requests.RequestException as e:
            logger.debug(f"Request failed: {method} {url} -> {e}")
            self.request_count += 1
            time.sleep(self.request_delay)
            return None

    def _format_exchange(self, method: str, url: str,
                         req_headers: Optional[Dict], req_params: Optional[Dict],
                         req_body: Any, resp) -> str:
        if resp is None:
            return (f"METHOD: {method}\nURL: {url}\n"
                    f"RESULT: Request failed (connection error, timeout, or DNS failure).")
        body = resp.text
        truncated = len(body) > MAX_BODY_PREVIEW
        body_preview = body[:MAX_BODY_PREVIEW] if truncated else body
        try:
            cookies = resp.cookies.get_dict()
        except Exception:
            cookies = {}
        redirect_chain = [r.url for r in resp.history] if resp.history else []
        lines = [
            f"METHOD: {method}", f"URL: {url}",
            f"REQUEST HEADERS: {dict(req_headers) if req_headers else '(session defaults only)'}",
            f"REQUEST QUERY PARAMS: {req_params if req_params else '(none)'}",
            f"REQUEST BODY: {req_body if req_body else '(none)'}",
            "---",
            f"RESPONSE STATUS: {resp.status_code} {resp.reason}",
            f"RESPONSE TIME: {resp.elapsed.total_seconds():.3f}s",
            f"REDIRECT CHAIN: {redirect_chain if redirect_chain else '(none)'}",
            f"RESPONSE HEADERS: {dict(resp.headers)}",
            f"RESPONSE COOKIES: {cookies if cookies else '(none)'}",
            f"RESPONSE BODY LENGTH: {len(body)} bytes",
            f"RESPONSE BODY{' (truncated)' if truncated else ''}:",
            body_preview,
        ]
        return "\n".join(lines)

    def _run_http(self, method: str, url: str, headers: Optional[Dict] = None,
                  params: Optional[Dict] = None, data: Optional[Dict] = None,
                  json_body: Optional[Dict] = None, cookies: Optional[Dict] = None) -> str:
        for name, value in [("params", params), ("headers", headers), ("cookies", cookies)]:
            if value is not None and not isinstance(value, dict):
                return f"ERROR: '{name}' must be a dictionary."
        if data is not None and not isinstance(data, (dict, str, bytes)):
            return "ERROR: 'data' must be dict, str, or bytes."
        if json_body is not None and not isinstance(json_body, dict):
            return "ERROR: 'json_body' must be a dictionary."
        try:
            resp = self._request(method, url, headers=headers, params=params,
                                 data=data, json=json_body, cookies=cookies)
        except scope.ScopeViolation as e:
            return f"REFUSED: {e}"
        except RequestBudgetExceeded as e:
            return f"BUDGET EXCEEDED: {e}"
        body_sent = json_body if json_body is not None else data
        return self._format_exchange(method, url, headers, params, body_sent, resp)

    def _http_get(self, url: str, headers: Optional[Dict] = None,
                  params: Optional[Dict] = None, cookies: Optional[Dict] = None) -> str:
        return self._run_http("GET", url, headers=headers, params=params, cookies=cookies)

    def _http_post(self, url: str, headers: Optional[Dict] = None,
                   params: Optional[Dict] = None, data: Optional[Dict] = None,
                   json_body: Optional[Dict] = None, cookies: Optional[Dict] = None) -> str:
        return self._run_http("POST", url, headers=headers, params=params,
                              data=data, json_body=json_body, cookies=cookies)

    def _record_finding(self, url: str, owasp_category: str, technique_id: str,
                        description: str, evidence: str, severity: str = "Medium") -> str:
        finding = {
            "url": url, "owasp_category": owasp_category,
            "technique_id": technique_id, "description": description,
            "evidence": evidence, "severity": severity,
        }
        self.recorded_findings.append(finding)
        logger.info(f"Finding recorded: [{owasp_category}] {description} at {url}")
        return (f"Finding recorded: [{severity}] [{owasp_category}] {description} "
                f"at {url} (technique: {technique_id or 'n/a'})")

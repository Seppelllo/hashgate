# SPDX-License-Identifier: Apache-2.0
"""Self-hosted operator web UI — served by the existing gate server under /ui.

Security model (the load-bearing part):

- The UI is a NEW sanctioned path that the agent could reach via curl — and
  the agent already knows preview id + hash from the deny reason. The hook
  token does NOT protect here: it lives in the environment Claude Code hands
  to the wrapper, i.e. it is potentially readable from the agent's side.
  Therefore ALL /ui routes — read-only ones included, the payloads contain
  commands — require the SEPARATE ``operator_token`` (config.toml /
  HASHGATE_OPERATOR_TOKEN), which is never needed in the agent/hook
  environment. The hook token never authorizes UI routes (pinned by test).
- No configured operator_token => every /ui route answers 403 with setup
  instructions (fail-closed: no open UI because configuration is missing).
- Login exchanges the token ONCE for a random server-side session id in an
  HttpOnly cookie — the token itself never appears in any response, header
  or page (pinned by test). Mutating endpoints additionally require the
  per-session CSRF value as a form field (synchronizer-token pattern: the
  cookie alone never mutates), OR the operator token itself as the
  ``X-Hashgate-Operator-Token`` header (a custom header cannot be set
  cross-site, and it doubles as the tool-friendly API auth).

Rendering truth is shared with the CLI (``render.summary_lines`` etc.) —
the same ⚠ warnings appear on both surfaces.
"""
from __future__ import annotations

import hmac
import json
import re
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select

from hashgate.adapters.sqlalchemy_store import PreviewRow
from hashgate.errors import EvidenceNotFound
from hashgate.evidence import EvidenceExporter, order_chain_events
from hashgate.integrations.claude_code.approvals import (
    DECISION_APPROVED,
    DECISION_DENIED,
    DECISION_DENIED_FINAL,
    denied_head_map,
    is_expired,
    outcome_for_preview,
)
from hashgate.integrations.claude_code.render import (
    age,
    expiry,
    local_time,
    short,
    summary_lines,
)
from hashgate.store import new_id

_WEB_DIR = Path(__file__).parent / "web"
_PREFIX_LEN = 12
_PREFIX_RE = re.compile(r"^[0-9a-f]{12}$")

_NO_TOKEN_HINT = (
    "hashgate operator UI is disabled: no operator_token configured.\n"
    "Set operator_token in ~/.hashgate/config.toml (or the\n"
    "HASHGATE_OPERATOR_TOKEN environment variable) and restart the server.\n"
    "Generate one: openssl rand -hex 16\n"
    "Note: this is a SEPARATE secret from the hook token and must never\n"
    "appear in the agent/hook environment."
)


def register_ui(app: FastAPI, state: Any) -> None:  # noqa: C901
    env = Environment(
        loader=FileSystemLoader(_WEB_DIR),
        autoescape=select_autoescape(["html"]),
    )
    env.globals.update(age=age, expiry=expiry, local_time=local_time, short=short)
    sessions: dict[str, str] = {}  # session id -> csrf token
    state.ui_sessions = sessions

    # --- auth helpers -----------------------------------------------------------
    def _token_configured() -> bool:
        return bool(state.config.operator_token)

    def _header_authorized(request: Request) -> bool:
        supplied = request.headers.get("x-hashgate-operator-token")
        return bool(supplied) and hmac.compare_digest(
            supplied, state.config.operator_token or "")

    def _session_id(request: Request) -> str | None:
        sid = request.cookies.get("hashgate_session")
        return sid if sid and sid in sessions else None

    def _authorized(request: Request) -> bool:
        return _header_authorized(request) or _session_id(request) is not None

    def _deny_page(request: Request) -> Response:
        if not _token_configured():
            return Response(_NO_TOKEN_HINT, status_code=403, media_type="text/plain")
        if request.method == "GET":
            return RedirectResponse("/ui/login", status_code=303)
        return Response("operator authorization required", status_code=403,
                        media_type="text/plain")

    def _mutation_authorized(request: Request, form: dict[str, Any]) -> bool:
        """Cookie alone never mutates: session + matching CSRF form field,
        or the operator token itself as a custom header."""
        if _header_authorized(request):
            return True
        sid = _session_id(request)
        if sid is None:
            return False
        supplied = str(form.get("csrf") or "")
        return bool(supplied) and hmac.compare_digest(supplied, sessions[sid])

    def _csrf_for(request: Request) -> str:
        sid = _session_id(request)
        return sessions.get(sid, "") if sid else ""

    def _render(request: Request, template: str, status_code: int = 200,
                **context: Any) -> HTMLResponse:
        context.setdefault("csrf", _csrf_for(request))
        html = env.get_template(template).render(**context)
        return HTMLResponse(html, status_code=status_code)

    # --- data helpers -------------------------------------------------------------
    async def _pending_rows() -> list[dict[str, Any]]:
        async with state.sessionmaker() as session:
            previews = (await session.execute(
                select(PreviewRow).order_by(PreviewRow.derived_at))
            ).scalars().all()
        rows = []
        for row in previews:
            approval = await state.approvals.latest_for_preview(row.preview_id)
            if approval is not None and (
                approval.decision in (DECISION_DENIED, DECISION_DENIED_FINAL)
                or approval.consumed_at
                or (approval.decision == DECISION_APPROVED
                    and not is_expired(approval))
            ):
                continue
            payload = row.payload or {}
            lines = summary_lines(row.action_type, payload, {})
            rows.append({
                "preview_id": row.preview_id,
                "action_type": row.action_type,
                "age": age(row.derived_at),
                "hash": row.payload_hash,
                "command": payload.get("command", ""),
                "first_warning": next(
                    (line for line in lines if line.lstrip().startswith("⚠")), None),
            })
        return rows

    async def _load_preview(preview_id: str) -> PreviewRow | None:
        async with state.sessionmaker() as session:
            return await session.get(PreviewRow, preview_id)

    # --- static -------------------------------------------------------------------
    @app.get("/ui/static/app.css")
    async def ui_css() -> Response:
        return Response((_WEB_DIR / "app.css").read_text(encoding="utf-8"),
                        media_type="text/css")

    # --- login / logout --------------------------------------------------------------
    @app.get("/ui/login")
    async def ui_login_form(request: Request) -> Response:
        if not _token_configured():
            return Response(_NO_TOKEN_HINT, status_code=403, media_type="text/plain")
        return _render(request, "login.html", error=None)

    @app.post("/ui/login")
    async def ui_login(request: Request) -> Response:
        if not _token_configured():
            return Response(_NO_TOKEN_HINT, status_code=403, media_type="text/plain")
        form = dict(await request.form())
        supplied = str(form.get("token") or "")
        if not supplied or not hmac.compare_digest(
                supplied, state.config.operator_token or ""):
            return _render(request, "login.html", status_code=403,
                           error="wrong operator token")
        sid, csrf = new_id(), new_id()
        sessions[sid] = csrf
        response = RedirectResponse("/ui", status_code=303)
        # http://localhost has no TLS, so no Secure flag — documented; the
        # cookie carries a random session id, never the token itself
        response.set_cookie("hashgate_session", sid, httponly=True,
                            samesite="strict", path="/ui")
        return response

    @app.post("/ui/logout")
    async def ui_logout(request: Request) -> Response:
        sid = _session_id(request)
        if sid:
            sessions.pop(sid, None)
        response = RedirectResponse("/ui/login", status_code=303)
        response.delete_cookie("hashgate_session", path="/ui")
        return response

    # --- views ---------------------------------------------------------------------
    @app.get("/ui")
    async def ui_pending(request: Request) -> Response:
        if not _authorized(request):
            return _deny_page(request)
        await state.ensure_init()
        return _render(request, "pending.html", rows=await _pending_rows())

    @app.get("/ui/partial/pending")
    async def ui_pending_partial(request: Request) -> Response:
        if not _authorized(request):
            return _deny_page(request)
        await state.ensure_init()
        return _render(request, "_pending_list.html", rows=await _pending_rows())

    @app.get("/ui/preview/{preview_id}")
    async def ui_preview(request: Request, preview_id: str,
                         ok: str = "", err: str = "") -> Response:
        if not _authorized(request):
            return _deny_page(request)
        await state.ensure_init()
        row = await _load_preview(preview_id)
        if row is None:
            return Response("unknown preview", status_code=404,
                            media_type="text/plain")
        payload = row.payload or {}
        denied_heads = await denied_head_map(state.sessionmaker) \
            if payload.get("commits") else {}
        approval = await state.approvals.latest_for_preview(row.preview_id)
        outcome, _, _ = await outcome_for_preview(state.store, state.approvals, row)
        return _render(
            request, "detail.html",
            row=row, payload=payload,
            payload_json=json.dumps(payload, indent=2, ensure_ascii=False),
            summary=summary_lines(row.action_type, payload, denied_heads),
            approval=approval, approval_expired=is_expired(approval) if approval else False,
            outcome=outcome, prefix_len=_PREFIX_LEN, ok=ok, err=err,
        )

    @app.get("/ui/history")
    async def ui_history(request: Request) -> Response:
        if not _authorized(request):
            return _deny_page(request)
        await state.ensure_init()
        async with state.sessionmaker() as session:
            previews = (await session.execute(
                select(PreviewRow).order_by(PreviewRow.derived_at.desc()).limit(50))
            ).scalars().all()
        entries = []
        for row in previews:
            outcome, decided_at, deny_reason = await outcome_for_preview(
                state.store, state.approvals, row)
            entries.append({
                "preview_id": row.preview_id, "action_type": row.action_type,
                "outcome": outcome, "decided_at": decided_at,
                "deny_reason": deny_reason,
                "head": str((row.payload or {}).get("head_sha") or "")[:12] or "-",
                "chain_id": row.chain_id,
            })
        return _render(request, "history.html", entries=entries)

    @app.get("/ui/bundle/{ref}")
    async def ui_bundle(request: Request, ref: str, download: int = 0) -> Response:
        if not _authorized(request):
            return _deny_page(request)
        await state.ensure_init()
        chain_id = ref
        row = await _load_preview(ref)
        if row is not None and row.chain_id:
            chain_id = row.chain_id
        try:
            bundle = await EvidenceExporter(store=state.store) \
                .export_oversight_bundle_by_chain(chain_id)
        except EvidenceNotFound:
            return Response("unknown chain", status_code=404, media_type="text/plain")
        if download:
            return Response(
                json.dumps(bundle, indent=2, ensure_ascii=False) + "\n",
                media_type="application/json",
                headers={"Content-Disposition":
                         f'attachment; filename="hashgate-bundle-{chain_id[:12]}.json"'})
        events = order_chain_events(list(bundle["events"]))
        return _render(request, "bundle.html", bundle=bundle, events=events,
                       chain_id=chain_id)

    # --- mutations -----------------------------------------------------------------
    @app.post("/ui/accept")
    async def ui_accept(request: Request) -> Response:
        if not _token_configured():
            return Response(_NO_TOKEN_HINT, status_code=403, media_type="text/plain")
        form = dict(await request.form())
        if not _mutation_authorized(request, form):
            return Response("operator authorization required (session + CSRF, "
                            "or X-Hashgate-Operator-Token header)",
                            status_code=403, media_type="text/plain")
        await state.ensure_init()
        preview_id = str(form.get("preview_id") or "")
        row = await _load_preview(preview_id)
        if row is None:
            return Response("unknown preview", status_code=404,
                            media_type="text/plain")

        def back(ok: str = "", err: str = "") -> Response:
            from urllib.parse import urlencode
            return RedirectResponse(
                f"/ui/preview/{preview_id}?{urlencode({'ok': ok, 'err': err})}",
                status_code=303)

        # the typed 12-hex prefix IS the deliberate echo — checked against
        # the FULL stored hash, wrong/short prefix approves nothing
        prefix = str(form.get("hash_prefix") or "").strip().lower()
        if not _PREFIX_RE.fullmatch(prefix) or not row.payload_hash.startswith(prefix):
            return back(err=f"hash echo mismatch: type the FIRST {_PREFIX_LEN} hex "
                            "characters of the payload hash shown above")
        existing = await state.approvals.latest_for_preview(preview_id)
        if existing is not None and existing.decision == DECISION_DENIED_FINAL:
            return back(err="this exact state was FINALLY denied — a changed "
                            "state is a new decision")
        if existing is not None and existing.decision == DECISION_APPROVED \
                and not existing.consumed_at and not is_expired(existing):
            return back(ok="already has an open approval — the agent can retry now")
        reason = str(form.get("reason") or "").strip() or "approved via hashgate web UI"
        approval = await state.approvals.decide(
            preview_id=row.preview_id, chain_id=row.chain_id,
            action_type=row.action_type, payload_hash=row.payload_hash,
            decision=DECISION_APPROVED, operator_id="operator:web-ui",
            reason=reason, channel="web-ui")
        return back(ok=f"approved as {approval.id} (single-use, "
                       f"expires {expiry(approval.expires_at)}) — "
                       "the agent can retry now")

    @app.post("/ui/deny")
    async def ui_deny(request: Request) -> Response:
        if not _token_configured():
            return Response(_NO_TOKEN_HINT, status_code=403, media_type="text/plain")
        form = dict(await request.form())
        if not _mutation_authorized(request, form):
            return Response("operator authorization required (session + CSRF, "
                            "or X-Hashgate-Operator-Token header)",
                            status_code=403, media_type="text/plain")
        await state.ensure_init()
        preview_id = str(form.get("preview_id") or "")
        row = await _load_preview(preview_id)
        if row is None:
            return Response("unknown preview", status_code=404,
                            media_type="text/plain")

        def back(ok: str = "", err: str = "") -> Response:
            from urllib.parse import urlencode
            return RedirectResponse(
                f"/ui/preview/{preview_id}?{urlencode({'ok': ok, 'err': err})}",
                status_code=303)

        reason = str(form.get("reason") or "").strip()
        if not reason:
            return back(err="a reason is required to deny")
        final = str(form.get("final") or "") in ("on", "true", "1")
        existing = await state.approvals.latest_for_preview(preview_id)
        if existing is not None and existing.decision == DECISION_DENIED_FINAL:
            return back(err="this exact state was already FINALLY denied")
        approval = await state.approvals.decide(
            preview_id=row.preview_id, chain_id=row.chain_id,
            action_type=row.action_type, payload_hash=row.payload_hash,
            decision=DECISION_DENIED, operator_id="operator:web-ui",
            reason=reason, final=final, channel="web-ui")
        if final:
            return back(ok=f"FINALLY denied as {approval.id} — this exact state "
                           "will never be approved; a changed state is a new decision")
        return back(ok=f"denied as {approval.id}")

    @app.get("/ui/api/pending")
    async def ui_api_pending(request: Request) -> Response:
        if not _token_configured():
            return Response(_NO_TOKEN_HINT, status_code=403, media_type="text/plain")
        if not _authorized(request):
            return JSONResponse({"error": "operator authorization required"},
                                status_code=403)
        await state.ensure_init()
        return JSONResponse({"pending": await _pending_rows()})

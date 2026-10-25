#!/usr/bin/env python3
"""Evidence-based deletion audit generator for Ghost Data Still Exists.

Only participant-facing files under dataset/ are used. No model/API calls are made.
Run from any directory: python code/main.py
"""
from __future__ import annotations

import csv
import json
import re
import sqlite3
import subprocess
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
EVIDENCE_DIR = (DATASET / "evidence").resolve()
OUTPUT = ROOT / "output.csv"

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}
SYSTEM_BY_PREFIX = {
    "account": "account_service",
    "search": "search_service",
    "analytics": "analytics_platform",
    "support": "support_platform",
    "export": "export_service",
    "data_flow": "integration_service",
    "backup": "backup_service",
    "audit_record": "security_service",
    "tombstone": "identity_service",
    "email_delivery": "email_delivery_service",
    "marketing": "marketing_platform",
    "cache": "cache_service",
    "attachment": "object_storage",
    "object": "object_storage",
}
CATEGORY_BY_PREFIX = {
    "account": "USER_PROFILE",
    "search": "SEARCH_INDEX_ENTRY",
    "analytics": "ANALYTICS_PROFILE",
    "support": "SUPPORT_MESSAGE",
    "export": "USER_EXPORT",
    "data_flow": "DATA_FLOW",
    "backup": "BACKUP_ARCHIVE",
    "audit_record": "SECURITY_AUDIT_LOG",
    "tombstone": "ACCOUNT_TOMBSTONE",
    "email_delivery": "EMAIL_DELIVERY_LOG",
    "marketing": "MARKETING_PROFILE",
    "cache": "CACHE_ENTRY",
    "attachment": "SUPPORT_ATTACHMENT",
    "object": "SUPPORT_ATTACHMENT",
}
DELETE_CATEGORIES = {
    "USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY", "SUPPORT_ATTACHMENT", "USER_EXPORT", "MARKETING_PROFILE",
}
REDACT_CATEGORIES = {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}
ANONYMIZE_CATEGORIES = {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}
RETAIN_CATEGORIES = {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}
IDENTIFIER_FIELDS = {
    "email", "owner_email", "customer_email", "requester_email", "email_address",
    "phone", "owner_phone", "customer_phone", "requester_phone", "full_name",
    "name", "display_name", "email_hash", "lookup_key", "matched_value",
    "correlation_key", "subject_reference", "customer_reference", "user_id",
    "subject_key", "requester_name",
}
DIRECT_PII_FIELDS = {
    "email", "owner_email", "customer_email", "requester_email", "email_address",
    "phone", "owner_phone", "customer_phone", "requester_phone", "full_name",
    "name", "display_name", "email_hash", "matched_value", "correlation_key",
    "subject_key", "requester_name",
}


def read_csv(filename: str) -> list[dict[str, str]]:
    with (DATASET / filename).open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def parse_time(value) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def norm(value) -> str:
    return str(value or "").strip().casefold()


def is_pii_value(value) -> bool:
    if value is None:
        return False
    return str(value).strip().casefold() not in {
        "", "null", "none", "no direct identifier", "n/a", "unknown",
    }


def resource_prefix(resource_id: str) -> str:
    return str(resource_id or "").split("_", 1)[0].casefold()


def guess_system(resource_id: str, fallback: str = "") -> str:
    rid = str(resource_id or "")
    # longest prefixes first (email_delivery before email-like prefixes)
    for prefix in sorted(SYSTEM_BY_PREFIX, key=len, reverse=True):
        if rid.startswith(prefix + "_"):
            return SYSTEM_BY_PREFIX[prefix]
    return fallback or "unknown_system"


def guess_category(resource_id: str, fallback: str = "") -> str:
    rid = str(resource_id or "")
    for prefix in sorted(CATEGORY_BY_PREFIX, key=len, reverse=True):
        if rid.startswith(prefix + "_"):
            return CATEGORY_BY_PREFIX[prefix]
    return fallback or "UNKNOWN"


def identity_index(identities: list[dict], audits: list[dict]):
    by_user = {}
    value_to_users = defaultdict(set)
    for identity in identities:
        uid = norm(identity.get("user_id"))
        if not uid:
            continue
        vals = {norm(identity.get(k)) for k in ("user_id", "name", "email", "phone", "email_hash")}
        vals.discard("")
        by_user[uid] = vals
        for val in vals:
            value_to_users[val].add(uid)
    for row in audits:
        uid = norm(row.get("user_id"))
        if uid not in by_user:
            continue
        for field in ("old_value", "new_value"):
            val = norm(row.get(field))
            if val:
                by_user[uid].add(val)
                value_to_users[val].add(uid)
    return by_user, value_to_users


def resolve_subject(request, identities, by_user, value_to_users):
    email = norm(request.get("email"))
    matches = set(value_to_users.get(email, set()))
    if len(matches) == 1:
        uid = next(iter(matches))
        return uid, by_user[uid]
    # A current identity may be the only exact email match.
    current = [r for r in identities if norm(r.get("email")) == email]
    if len(current) == 1:
        uid = norm(current[0].get("user_id"))
        return uid, by_user.get(uid, {email, uid})
    return "", {email} if email else set()


def flatten_scalars(value, prefix=""):
    out = []
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                out.append((str(k).casefold(), v))
            elif isinstance(v, (dict, list)):
                out.extend(flatten_scalars(v, prefix + str(k) + "."))
    elif isinstance(value, list):
        for v in value:
            out.extend(flatten_scalars(v, prefix))
    return out


def category_from_context(resource_id, context="", table=""):
    c = str(context or "").casefold()
    t = str(table or "").casefold()
    rid_cat = guess_category(resource_id)
    if rid_cat != "UNKNOWN":
        return rid_cat
    for needle, cat in (
        ("customer_profiles", "USER_PROFILE"),
        ("profile_lookup", "USER_PROFILE"),
        ("search", "SEARCH_INDEX_ENTRY"),
        ("analytics", "ANALYTICS_PROFILE"),
        ("telemetry", "PRODUCT_TELEMETRY"),
        ("support", "SUPPORT_MESSAGE"),
        ("attachment", "SUPPORT_ATTACHMENT"),
        ("export", "USER_EXPORT"),
        ("connector", "DATA_FLOW"),
        ("data_flow", "DATA_FLOW"),
        ("restore", "BACKUP_ARCHIVE"),
        ("backup", "BACKUP_ARCHIVE"),
        ("security_audit", "SECURITY_AUDIT_LOG"),
        ("audit_record", "SECURITY_AUDIT_LOG"),
        ("tombstone", "ACCOUNT_TOMBSTONE"),
        ("marketing", "MARKETING_PROFILE"),
        ("delivery", "EMAIL_DELIVERY_LOG"),
        ("cache", "CACHE_ENTRY"),
        ("legal_hold", "LEGAL_HOLD_RECORD"),
    ):
        if needle in c or needle in t:
            return cat
    return "UNKNOWN"


def make_observation(evidence_id, captured_at, observed_at, system, resource_id,
                     category, state, pairs, source_kind, full_scope=False):
    vals = {str(k).casefold(): v for k, v in pairs}
    return {
        "evidence_id": evidence_id,
        "captured_at": captured_at,
        "observed_at": observed_at or captured_at,
        "system_id": system or guess_system(resource_id),
        "resource_id": str(resource_id or ""),
        "category": category or guess_category(resource_id),
        "state": state,
        "values": vals,
        "source_kind": source_kind,
        "full_scope": full_scope,
    }


def state_from_record(category, values, raw=None):
    low = {str(k).casefold(): v for k, v in values.items()}
    raw = raw if isinstance(raw, dict) else {}
    # Tombstones intentionally persist; their presence is valid only when direct identifiers are removed.
    if category == "ACCOUNT_TOMBSTONE":
        direct_pii = any(is_pii_value(low.get(k)) for k in DIRECT_PII_FIELDS)
        return "PRESENT" if direct_pii else "REDACTED"
    result = norm(low.get("result") or low.get("status"))
    # Explicit lookup result takes precedence over generic row presence.
    if str(low.get("status_code", "")).strip() in {"404", "410"}:
        return "ABSENT"
    if str(low.get("rows", "")).strip() == "0":
        return "ABSENT"
    if result in {"not_found", "not found", "absent", "missing", "no_hit", "miss"}:
        return "ABSENT"
    if result in {"anonymized", "anonymised"}:
        return "ANONYMIZED"
    if result in {"redacted", "sanitized", "sanitised"}:
        return "REDACTED"
    if result in {"blocked", "false", "0", "disabled", "stopped", "inactive"}:
        if category == "BACKUP_ARCHIVE":
            return "BLOCKED"
        if category == "DATA_FLOW":
            return "DISABLED"
    if result in {"active", "enabled", "true", "1", "delivered"}:
        if category == "BACKUP_ARCHIVE":
            return "ACTIVE"
        if category == "DATA_FLOW":
            return "ACTIVE"
    if category == "DATA_FLOW":
        enabled = low.get("enabled")
        if enabled is False or norm(enabled) in {"false", "0", "disabled"}:
            return "DISABLED"
        if enabled is True or norm(enabled) in {"true", "1", "enabled"}:
            return "ACTIVE"
    if category == "BACKUP_ARCHIVE":
        allowed = low.get("restore_allowed")
        if allowed is False or norm(allowed) in {"false", "0", "blocked"}:
            return "BLOCKED"
        if allowed is True or norm(allowed) in {"true", "1", "active", "allowed"}:
            return "ACTIVE"
    direct_pii = any(is_pii_value(low.get(k)) for k in DIRECT_PII_FIELDS)
    reference = any(is_pii_value(low.get(k)) for k in ("user_id", "customer_reference", "subject_reference"))
    if category == "ACCOUNT_TOMBSTONE":
        return "PRESENT" if direct_pii else "REDACTED"
    if category in ANONYMIZE_CATEGORIES:
        return "PRESENT" if direct_pii or reference else "ANONYMIZED"
    if category == "SUPPORT_MESSAGE":
        return "PRESENT" if direct_pii else "REDACTED"
    if category == "EMAIL_DELIVERY_LOG":
        return "PRESENT" if direct_pii else "REDACTED"
    if category == "SECURITY_AUDIT_LOG" or category == "LEGAL_HOLD_RECORD":
        return "PRESENT"
    if category == "UNKNOWN":
        return "PRESENT"
    return "PRESENT"


def parse_json_file(row, path):
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return [], []
    captured = parse_time(row.get("captured_at"))
    observations, scopes = [], []

    def walk(node, system="", collection="", scope_time=None):
        if isinstance(node, dict):
            system_here = str(node.get("data_store") or node.get("system") or system)
            collection_here = str(node.get("collection") or node.get("record_type") or collection)
            time_here = parse_time(node.get("observed_at") or node.get("recorded_at") or node.get("captured_at")) or scope_time or captured

            # Mark complete snapshot collection scopes, including empty arrays.
            if isinstance(node.get("records"), list) and (node.get("collection") or node.get("data_store")):
                scopes.append({
                    "evidence_id": row["file_id"], "captured_at": captured,
                    "observed_at": time_here, "system_id": system_here,
                    "category": category_from_context("", collection_here),
                    "resource_ids": set(),
                    "full_scope": True,
                })

            if node.get("resource_id"):
                rid = str(node.get("resource_id"))
                pairs = flatten_scalars(node)
                category = category_from_context(rid, collection_here)
                state = state_from_record(category, dict(pairs), node)
                # A 0-hit query is an absence observation for its resource.
                if isinstance(node.get("hits"), dict) and int(node["hits"].get("total", 0) or 0) == 0:
                    state = "ABSENT"
                obs = make_observation(
                    row["file_id"], captured, time_here, system_here, rid,
                    category, state, pairs, "json", False
                )
                observations.append(obs)

            for key, child in node.items():
                if isinstance(child, (dict, list)):
                    next_system = key if key in {
                        "account_service", "analytics_platform", "backup_service",
                        "export_service", "integration_service", "search_service",
                        "support_platform", "security_service", "identity_service",
                        "marketing_platform", "email_delivery_service", "object_storage",
                    } else system_here
                    walk(child, next_system, collection_here, time_here)
        elif isinstance(node, list):
            for child in node:
                walk(child, system, collection, scope_time)

    walk(data, scope_time=captured)
    # populate scope resource ids from parsed observations that belong to same evidence/system/category
    for scope in scopes:
        scope["resource_ids"] = {
            o["resource_id"] for o in observations
            if o["evidence_id"] == scope["evidence_id"]
            and o["system_id"] == scope["system_id"]
            and (scope["category"] == "UNKNOWN" or o["category"] == scope["category"])
        }
    return observations, scopes


def expand_record_fields(record: dict) -> dict:
    """Expand JSON-encoded payload columns in SQL snapshots into record fields."""
    expanded = dict(record)
    for payload_key in ("payload", "record_json", "document", "data", "record"):
        payload = record.get(payload_key)
        if isinstance(payload, str) and payload.strip().startswith(("{", "[")):
            try:
                decoded = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if isinstance(decoded, dict):
                expanded.update(decoded)
    return expanded


def parse_sql_file(row, path):
    captured = parse_time(row.get("captured_at"))
    observations, scopes = [], []
    try:
        sql = path.read_text(encoding="utf-8-sig", errors="replace")
        conn = sqlite3.connect(":memory:")
        conn.executescript(sql)
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        for (table,) in tables:
            cols = [x[1] for x in conn.execute(f'PRAGMA table_info("{table}")').fetchall()]
            rows = conn.execute(f'SELECT * FROM "{table}"').fetchall()
            table_l = table.casefold()
            category = category_from_context("", table_l, table_l)
            if table_l == "snapshot_scope":
                continue
            if category == "UNKNOWN":
                # Older schemas use generic primary/replica table names.
                category = "USER_PROFILE" if "customer_data" in table_l or "customer_profiles" in table_l else "UNKNOWN"
            system = ""
            if "search" in table_l:
                system = "search_service"
            elif "analytics" in table_l:
                system = "analytics_platform"
            elif "support" in table_l:
                system = "support_platform"
            elif "export" in table_l:
                system = "export_service"
            elif "connector" in table_l:
                system = "integration_service"
            elif "backup" in table_l or "restore" in table_l:
                system = "backup_service"
            elif "audit" in table_l:
                system = "security_service"
            elif "tombstone" in table_l or "deleted_customer" in table_l:
                system = "identity_service"
            elif "marketing" in table_l:
                system = "marketing_platform"
            elif "delivery" in table_l:
                system = "email_delivery_service"
            else:
                system = "account_service"
            resource_col = next((c for c in cols if c.casefold() in {"resource_id", "id"}), None)
            resource_ids = set()
            for tup in rows:
                d = dict(zip(cols, tup))
                rid = str(d.get(resource_col) or "") if resource_col else ""
                if rid:
                    resource_ids.add(rid)
                    # Some snapshots store the actual record as JSON in a payload/data column.
                    # Decode it before classification so nested identifiers and privacy state
                    # are evaluated rather than treating the JSON blob as opaque text.
                    expanded = expand_record_fields(d)
                    explicit_system = str(d.get("system_id") or d.get("system") or "")
                    canonical_systems = {
                        "account_service", "analytics_platform", "backup_service",
                        "export_service", "integration_service", "search_service",
                        "support_platform", "security_service", "identity_service",
                        "marketing_platform", "email_delivery_service", "object_storage",
                        "cache_service",
                    }
                    if explicit_system in canonical_systems:
                        row_system = explicit_system
                    else:
                        row_system = system
                    explicit_category = str(d.get("category") or d.get("data_category") or "")
                    row_category = explicit_category or category_from_context(rid, table_l, table_l)
                    if row_category == "UNKNOWN":
                        row_category = category
                    state = state_from_record(row_category, expanded, expanded)
                    observations.append(make_observation(
                        row["file_id"], captured, captured, row_system, rid,
                        row_category, state, list(expanded.items()), "sql", False
                    ))
            # SQL tables in these evidence files are complete point-in-time snapshots.
            scopes.append({
                "evidence_id": row["file_id"], "captured_at": captured,
                "observed_at": captured, "system_id": system, "category": category,
                "resource_ids": resource_ids, "table": table_l, "full_scope": True,
            })
        conn.close()
    except Exception:
        return [], []
    return observations, scopes


KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|([^ ]+))')
RID_RE = re.compile(r'\b(?:account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|email_delivery|marketing|cache|attachment|object)_\d+[A-Za-z0-9-]*\b')


def parse_text_lines(row, path, text, source_kind):
    captured = parse_time(row.get("captured_at"))
    observations = []
    lines = text.splitlines()
    # Group structured log lines by trace id so lookup keys and completion states can be joined.
    groups = defaultdict(list)
    for line in lines:
        kv = {m.group(1).casefold(): (m.group(2) if m.group(2) is not None else m.group(3)) for m in KV_RE.finditer(line)}
        trace = kv.get("trace_id") or kv.get("trace") or ""
        groups[trace or f"line:{len(groups)}"].append((line, kv))
    for group in groups.values():
        joined = " ".join(line for line, _ in group)
        joined_norm = norm(joined)
        kv_all = {}
        for _, kv in group:
            kv_all.update(kv)
        event_time = None
        for line, _ in group:
            m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)", line)
            if m:
                event_time = parse_time(m.group(1))
                break
        when = event_time or captured
        rids = set(RID_RE.findall(joined))
        # Each record is associated only when its own evidence text contains a known identifier.
        for rid in rids:
            system = kv_all.get("service") or kv_all.get("target_system") or guess_system(rid)
            system = {
                "account_replica": "account_service", "support_replica": "support_platform",
                "search_replica": "search_service", "analytics_replica": "analytics_platform",
                "export_replica": "export_service", "backup_replica": "backup_service",
                "security_replica": "security_service", "identity_replica": "identity_service",
                "object_storage_replica": "object_storage",
            }.get(system, system)
            category = category_from_context(rid, joined)
            state = "PRESENT"
            if re.search(r"\b(rows=0|http_status=404|status_code=404|NOT_FOUND|not found)\b", joined, re.I):
                state = "ABSENT"
            elif category == "DATA_FLOW":
                if re.search(r"\b(enabled=false|DISABLED|stopped|inactive)\b", joined, re.I):
                    state = "DISABLED"
                elif re.search(r"\b(enabled=true|ACTIVE|delivered)\b", joined, re.I):
                    state = "ACTIVE"
            elif category == "BACKUP_ARCHIVE":
                if re.search(r"\b(BLOCKED|restore_allowed=false)\b", joined, re.I):
                    state = "BLOCKED"
                elif re.search(r"\b(ACTIVE|restore_allowed=true|allowed|eligible=true)\b", joined, re.I) and not re.search(r"deletion_block=true|restore_allowed=false", joined, re.I):
                    state = "ACTIVE"
            elif category == "ANALYTICS_PROFILE":
                if re.search(r"\bANONYMIZED\b", joined, re.I):
                    state = "ANONYMIZED"
                elif re.search(r"\b(IDENTIFIABLE|email=|phone=|email_hash=)\b", joined, re.I):
                    state = "PRESENT"
            elif category in {"ACCOUNT_TOMBSTONE", "SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"}:
                if re.search(r"\b(REDACTED|REDACT)\b", joined, re.I) and not re.search(r"\b(email|phone|name)=\S+", joined, re.I):
                    state = "REDACTED"
            if source_kind == "txt":
                # Handover lines are structured with explicit record category/state.
                m = re.search(r"\|\s*([A-Z_]+)\s*\|\s*([A-Z_]+)\s*\|", joined)
                if m:
                    category = m.group(1)
                    explicit = m.group(2)
                    state = {
                        "NOT_FOUND": "ABSENT", "FOUND": "PRESENT", "IDENTIFIABLE": "PRESENT",
                        "ANONYMIZED": "ANONYMIZED", "REDACTED": "REDACTED",
                        "ACTIVE": "ACTIVE", "DISABLED": "DISABLED", "BLOCKED": "BLOCKED",
                    }.get(explicit, state)
            pairs = list(kv_all.items())
            # Add line text to allow matching against identity history.
            pairs.append(("raw_text", joined))
            observations.append(make_observation(
                row["file_id"], captured, when, system, rid, category, state,
                pairs, source_kind, False
            ))
    # Structured handover rows may have no key-value syntax.
    if source_kind == "txt":
        for line in lines:
            m = re.match(r"\s*-\s*(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*(.*)", line)
            if not m:
                continue
            ts, system, rid, cat, state_text, subject = m.groups()
            state = {
                "NOT_FOUND": "ABSENT", "FOUND": "PRESENT", "IDENTIFIABLE": "PRESENT",
                "ANONYMIZED": "ANONYMIZED", "REDACTED": "REDACTED",
                "ACTIVE": "ACTIVE", "DISABLED": "DISABLED", "BLOCKED": "BLOCKED",
            }.get(state_text.strip().upper(), "PRESENT")
            observations.append(make_observation(
                row["file_id"], captured, parse_time(ts), system.strip(), rid.strip(),
                cat.strip(), state, [("subject_reference", subject.strip()), ("raw_text", line)],
                source_kind, False
            ))
    return observations


def extract_evidence(manifest):
    observations, scopes = [], []
    for row in manifest:
        path = (DATASET / row["file_path"]).resolve()
        if not path.is_relative_to(EVIDENCE_DIR) or not path.is_file():
            continue
        ext = path.suffix.casefold()
        if ext == ".json":
            obs, sc = parse_json_file(row, path)
            observations.extend(obs)
            scopes.extend(sc)
        elif ext == ".sql":
            obs, sc = parse_sql_file(row, path)
            observations.extend(obs)
            scopes.extend(sc)
        elif ext in {".log", ".txt"}:
            try:
                text = path.read_text(encoding="utf-8-sig", errors="replace")
            except OSError:
                continue
            observations.extend(parse_text_lines(row, path, text, ext[1:]))
        elif ext == ".pdf":
            try:
                result = subprocess.run(
                    ["pdftotext", "-layout", str(path), "-"],
                    capture_output=True, text=True, timeout=20, check=False,
                )
                text = result.stdout or ""
            except (OSError, subprocess.TimeoutExpired):
                text = ""
            observations.extend(parse_text_lines(row, path, text, "pdf"))
        elif ext == ".png":
            try:
                from PIL import Image
                import pytesseract
                text = pytesseract.image_to_string(Image.open(path))
            except Exception:
                text = ""
            observations.extend(parse_text_lines(row, path, text, "png"))
    return observations, scopes


def obs_matches_identity(obs, identifiers):
    def clean(value):
        return str(value or "").strip().casefold().strip("\"'")

    ids = {clean(v) for v in identifiers if is_pii_value(v)}
    if not ids:
        return False

    values = obs.get("values", {})
    if any(clean(v) in ids for v in values.values()):
        return True

    raw = clean(values.get("raw_text", ""))
    for value in ids:
        if not value:
            continue
        if "@" in value:
            pattern = (
                r"(?<![a-z0-9._%+\-])" + re.escape(value)
                + r"(?![a-z0-9._%+\-])"
            )
        else:
            pattern = (
                r"(?<![a-z0-9_])" + re.escape(value)
                + r"(?![a-z0-9_])"
            )
        if re.search(pattern, raw):
            return True
    return False


def relevant_obs_for_case(
    request, uid, identifiers, observations, cutoff, activity=None
):
    selected = []
    linked_resources = set()
    uid_norm = norm(uid) if uid else ""
    ids = sorted({norm(v) for v in identifiers if is_pii_value(v)})

    # Keep each identifier paired with its own compiled regex.
    id_patterns = []
    for value in ids:
        if not value:
            continue
        if "@" in value:
            pattern = (
                r"(?<![a-z0-9._%+\-])" + re.escape(value)
                + r"(?![a-z0-9._%+\-])"
            )
        else:
            pattern = (
                r"(?<![a-z0-9_])" + re.escape(value)
                + r"(?![a-z0-9_])"
            )
        id_patterns.append((value, re.compile(pattern)))

    uid_pattern = (
        re.compile(
            r"(?<![a-z0-9_])" + re.escape(uid_norm) + r"(?![a-z0-9_])"
        )
        if uid_norm else None
    )

    for event in activity or []:
        event_time = parse_time(event.get("event_time"))
        if cutoff is None or event_time is None or event_time > cutoff:
            continue
        if event.get("event_type") != "LINK_RESOURCE_IDENTITY":
            continue

        details = norm(event.get("details", ""))
        has_uid = bool(uid_pattern and uid_pattern.search(details))
        has_identifier = any(
            pattern.search(details) for _, pattern in id_patterns
        )
        if (has_uid or has_identifier) and event.get("resource_id"):
            linked_resources.add(str(event["resource_id"]))

            # Capture resource IDs mentioned in subject-linked catalog events.
            details_text = str(event.get("details", ""))
            for rid in RID_RE.findall(details_text):
                linked_resources.add(rid)

    for obs in observations:
        captured = obs.get("captured_at")
        observed = obs.get("observed_at") or captured
        if (
            cutoff is None or captured is None or observed is None
            or captured > cutoff or observed > cutoff
        ):
            continue

        values = obs.get("values", {})
        normalized_values = {norm(v) for v in values.values()}
        exact_match = bool(set(ids).intersection(normalized_values))
        raw = norm(values.get("raw_text", ""))
        text_match = bool(
            raw and any(
                value in raw and pattern.search(raw)
                for value, pattern in id_patterns
            )
        )
        stable_uid_match = bool(
            uid_norm and uid_norm in normalized_values
        )
        linked = (
            obs.get("resource_id")
            and str(obs["resource_id"]) in linked_resources
        )

        if exact_match or text_match or stable_uid_match or linked:
            selected.append(obs)

    return selected

def latest_by_resource(observations):
    grouped = defaultdict(list)
    for o in observations:
        if o["resource_id"]:
            grouped[(o["system_id"], o["resource_id"])].append(o)
    out = {}
    for key, rows in grouped.items():
        rows.sort(key=lambda o: (o.get("observed_at") or o.get("captured_at") or datetime.min.replace(tzinfo=timezone.utc), o.get("captured_at") or datetime.min.replace(tzinfo=timezone.utc)))
        out[key] = rows[-1]
    return out


def add_step(steps, phase, system, resource, operation, state, evidence_id):
    steps.append({
        "step_no": 0, "phase": phase, "system_id": system or guess_system(resource),
        "resource_id": resource, "operation": operation, "state": state,
        "evidence_id": evidence_id or "",
    })


def is_non_deletion_request(request_text: str) -> bool:
    """Return True only for clear account-support requests that do not authorize erasure."""
    text = norm(request_text)
    explicit_non_deletion = bool(
        re.search(
            r"not asking for deletion|not a request to erase|do not close the account|don't delete|"
            r"do not delete|without removing any of my records|still need the account|"
            r"still want receipts|information request, not|not asking you to erase|"
            r"do not remove|keep my account|please leave my profile|only.*marketing|"
            r"stop the promotional emails|correct it without removing",
            text,
        )
    )
    if explicit_non_deletion:
        return True
    non_deletion_action = bool(
        re.search(
            r"\b(update|replace|correct|reset|download|change|stop|remove me from|"
            r"need a copy|send me a copy|could you send me a copy)\b",
            text,
        )
    )
    deletion_intent = bool(
        re.search(
            r"\b(delete|deletion|erase|erased|erasure|deleted|permanent account-deletion|"
            r"permanently delete|remove my account|close this account|close my account|"
            r"remove records|remove any records|remove the profile|remove the personal details|"
            r"erase the account)\b",
            text,
        )
    )
    return non_deletion_action and not deletion_intent


def create_case_output(request, uid, identifiers, all_observations, all_scopes, activity=None):
    cutoff = parse_time(request.get("audit_at"))
    # A non-deletion request is not authorized for deletion.
    non_deletion = is_non_deletion_request(request.get("request_text", ""))
    if non_deletion:
        return request["case_id"], "NOT_APPLICABLE", []

    subject_obs = relevant_obs_for_case(request, uid, identifiers, all_observations, cutoff, activity)
    latest = latest_by_resource(subject_obs)
    # Resource-specific compliant state and outstanding action maps.
    enabled_flow_ids = {
        str(event.get("resource_id"))
        for event in (activity or [])
        if event.get("event_type") == "CHECK_DATA_FLOW"
        and event.get("resource_id")
        and cutoff is not None
        and parse_time(event.get("event_time")) is not None
        and parse_time(event.get("event_time")) <= cutoff
        and "enabled" in norm(event.get("details", ""))
    }
    findings, remediations, verifications = [], [], []
    noncompliant = False
    known_resources = set(latest)

    for (system, rid), obs in latest.items():
        cat = obs["category"] or guess_category(rid)
        state = obs["state"]
        evid = obs["evidence_id"]
        if cat in DELETE_CATEGORIES:
            if state != "ABSENT":
                noncompliant = True
                add_step(findings, "FINDING", system, rid, "REPORT_REMAINING_RECORD", "PRESENT", evid)
                add_step(remediations, "REMEDIATION", system, rid, "DELETE_RECORD", "ABSENT", "")
                add_step(verifications, "VERIFICATION", system, rid, "VERIFY_RECORD_ABSENT", "ABSENT", "")
        elif cat in REDACT_CATEGORIES:
            if state == "PRESENT":
                noncompliant = True
                add_step(findings, "FINDING", system, rid, "REPORT_EXPOSED_PII", "PRESENT", evid)
                add_step(remediations, "REMEDIATION", system, rid, "REDACT_RECORD", "REDACTED", "")
                add_step(verifications, "VERIFICATION", system, rid, "VERIFY_RECORD_REDACTED", "REDACTED", "")
            elif state == "REDACTED":
                add_step(verifications, "VERIFICATION", system, rid, "VERIFY_RECORD_REDACTED", "REDACTED", evid)
        elif cat in ANONYMIZE_CATEGORIES:
            if state == "PRESENT":
                noncompliant = True
                add_step(findings, "FINDING", system, rid, "REPORT_EXPOSED_PII", "PRESENT", evid)
                add_step(remediations, "REMEDIATION", system, rid, "ANONYMIZE_RECORD", "ANONYMIZED", "")
                add_step(verifications, "VERIFICATION", system, rid, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", "")
            elif state == "ANONYMIZED":
                add_step(verifications, "VERIFICATION", system, rid, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", evid)
        elif cat == "DATA_FLOW":
            if state == "ACTIVE" or (state == "PRESENT" and rid in enabled_flow_ids):
                noncompliant = True
                add_step(findings, "FINDING", system, rid, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", evid)
                add_step(remediations, "REMEDIATION", system, rid, "DISABLE_DATA_FLOW", "DISABLED", "")
                add_step(verifications, "VERIFICATION", system, rid, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", "")
            elif state == "DISABLED":
                add_step(verifications, "VERIFICATION", system, rid, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", evid)
        elif cat == "BACKUP_ARCHIVE":
            if state == "ACTIVE":
                noncompliant = True
                add_step(findings, "FINDING", system, rid, "REPORT_RESTORE_RISK", "ACTIVE", evid)
                add_step(remediations, "REMEDIATION", system, rid, "BLOCK_RESTORE", "BLOCKED", "")
                add_step(verifications, "VERIFICATION", system, rid, "VERIFY_RESTORE_BLOCKED", "BLOCKED", "")
            elif state == "BLOCKED":
                add_step(verifications, "VERIFICATION", system, rid, "VERIFY_RESTORE_BLOCKED", "BLOCKED", evid)
        elif cat in RETAIN_CATEGORIES:
            add_step(verifications, "VERIFICATION", system, rid, "VERIFY_RECORD_PRESENT", "PRESENT", evid)

    # A complete case requires positive proof for a primary account lookup. If a known account
    # resource has no current matching observation but a full snapshot covers account_service,
    # mark it absent only when the snapshot predates/equal the audit cutoff.
    # Only use the latest observation for each account resource.
    # Historical ABSENT evidence must not override a newer PRESENT record.
    account_profiles = [
        obs for obs in latest.values()
        if obs["category"] == "USER_PROFILE"
    ]

    account_absence = None
    if account_profiles and not any(
        obs["state"] == "PRESENT" for obs in account_profiles
    ):
        absent_profiles = [
            obs for obs in account_profiles
            if obs["state"] == "ABSENT"
        ]
        if absent_profiles:
            account_absence = max(
                absent_profiles,
                key=lambda obs: (
                    obs.get("observed_at")
                    or obs.get("captured_at")
                    or datetime.min.replace(tzinfo=timezone.utc)
                ),
            )

    if account_absence:
        if not any(
            step["operation"] == "VERIFY_RECORD_ABSENT"
            and step["system_id"] == "account_service"
            for step in verifications
        ):
            add_step(
                verifications,
                "VERIFICATION",
                "account_service",
                account_absence["resource_id"],
                "VERIFY_RECORD_ABSENT",
                "ABSENT",
                account_absence["evidence_id"],
            )
    else:
        # Do not claim completion without reliable account-absence evidence.
        noncompliant = True

        # Report only positively observed, identity-linked resources.
        # Never manufacture resource IDs or use post-cutoff evidence.
        if not findings:
            for (system, rid), obs in latest.items():
                cat = obs.get("category", "")
                state = obs.get("state", "")
                evid = obs.get("evidence_id", "")

                if not evid:
                    continue

                if cat in DELETE_CATEGORIES and state != "ABSENT":
                    add_step(
                        findings, "FINDING", system, rid,
                        "REPORT_REMAINING_RECORD", "PRESENT", evid
                    )
                elif cat in REDACT_CATEGORIES and state == "PRESENT":
                    add_step(
                        findings, "FINDING", system, rid,
                        "REPORT_EXPOSED_PII", "PRESENT", evid
                    )
                elif cat in ANONYMIZE_CATEGORIES and state == "PRESENT":
                    add_step(
                        findings, "FINDING", system, rid,
                        "REPORT_EXPOSED_PII", "PRESENT", evid
                    )
                elif cat == "DATA_FLOW" and state == "ACTIVE":
                    add_step(
                        findings, "FINDING", system, rid,
                        "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", evid
                    )
                elif cat == "BACKUP_ARCHIVE" and state == "ACTIVE":
                    add_step(
                        findings, "FINDING", system, rid,
                        "REPORT_RESTORE_RISK", "ACTIVE", evid
                    )
    # For incomplete cases all verification is prospective and must have empty evidence IDs.
    if noncompliant:
        for step in verifications:
            step["evidence_id"] = ""
    # Complete cases include only evidence-backed verification steps.
    else:
        verifications = [s for s in verifications if s["evidence_id"]]
        # A case with no verifications cannot be called complete.
        if not verifications:
            noncompliant = True

    steps = findings + remediations + verifications
    steps.sort(key=lambda s: (
        PHASE_ORDER[s["phase"]], OP_ORDER[s["operation"]],
        s["system_id"], s["resource_id"]
    ))
    # Deduplicate exact duplicate steps generated from nested JSON records/log lines.
    deduped = []
    seen = set()
    for s in steps:
        key = (s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"], s["evidence_id"])
        if key not in seen:
            seen.add(key)
            deduped.append(s)
    for i, s in enumerate(deduped, 1):
        s["step_no"] = i
    status = "INCOMPLETE" if noncompliant else "COMPLETE"
    return request["case_id"], status, deduped


def main():
    requests = read_csv("deletion_requests.csv")
    identities = read_csv("user_identities.csv")
    audits = read_csv("user_audit_log.csv")
    activity = read_csv("system_activity.csv")
    manifest = read_csv("evidence_files.csv")
    observations, scopes = extract_evidence(manifest)

    output_rows = []
    for request in requests:
        cutoff = parse_time(request.get("audit_at"))
        eligible_audits = [
            row for row in audits
            if parse_time(row.get("event_time")) is not None
            and cutoff is not None
            and parse_time(row.get("event_time")) <= cutoff
        ]
        by_user, value_to_users = identity_index(identities, eligible_audits)
        uid, identifiers = resolve_subject(request, identities, by_user, value_to_users)
        # The request email is itself an identifier and may be an older address.
        if request.get("email"):
            identifiers = set(identifiers) | {norm(request["email"])}
        case_id, status, steps = create_case_output(
            request, uid, identifiers, observations, scopes, activity
        )
        output_rows.append({
            "case_id": case_id, "deletion_status": status,
            "steps_json": json.dumps(steps, separators=(",", ":"), ensure_ascii=False),
        })

    output_rows.sort(key=lambda r: r["case_id"])
    with OUTPUT.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")
        writer.writeheader()
        writer.writerows(output_rows)

    counts = defaultdict(int)
    for row in output_rows:
        counts[row["deletion_status"]] += 1
    print(f"Generated: {OUTPUT}")
    print(f"Rows: {len(output_rows)}")
    print(f"Statuses: {dict(sorted(counts.items()))}")
    print(f"Evidence observations parsed: {len(observations)}")
    print(f"Snapshot scopes parsed: {len(scopes)}")
    print("Model/API calls: 0")


if __name__ == "__main__":
    main()



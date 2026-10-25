
import re
import csv
import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
EVIDENCE_DIR = (DATASET / "evidence").resolve()


def read_csv(filename):
    with (DATASET / filename).open(
        "r", encoding="utf-8-sig", newline=""
    ) as file:
        return list(csv.DictReader(file))


def parse_time(value):
    if not value:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            return None
        return result
    except (ValueError, TypeError):
        return None


def normalize(value):
    return str(value or "").strip().casefold()


def load_evidence():
    evidence = []

    for row in read_csv("evidence_files.csv"):
        path = (DATASET / row["file_path"]).resolve()

        if not path.is_relative_to(EVIDENCE_DIR):
            continue
        if not path.is_file():
            continue

        try:
            content = path.read_text(
                encoding="utf-8-sig", errors="replace"
            )
        except OSError:
            continue

        evidence.append({
            "file_id": row["file_id"],
            "file_path": row["file_path"],
            "captured_at": parse_time(row["captured_at"]),
            "content": content,
        })

    return evidence


def resolve_identity(request, identities):
    email = normalize(request.get("email"))
    matches = [
        item for item in identities
        if normalize(item.get("email")) == email
    ]
    return matches[0] if len(matches) == 1 else None


def evidence_at_cutoff(evidence, audit_at):
    cutoff = parse_time(audit_at)
    if cutoff is None:
        return []

    return [
        item for item in evidence
        if item["captured_at"] is not None
        and item["captured_at"] <= cutoff
    ]


def inspect_json_evidence(item, identity, audit_at):
    """Find matching JSON records observed by the audit cutoff."""
    path = DATASET / item["file_path"]

    if path.suffix.lower() != ".json":
        return []

    cutoff = parse_time(audit_at)
    captured_at = item["captured_at"]

    if cutoff is None or captured_at is None or captured_at > cutoff:
        return []

    try:
        with path.open("r", encoding="utf-8-sig") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError):
        return []

    identifiers = {
        normalize(identity.get("user_id")),
        normalize(identity.get("email")),
        normalize(identity.get("email_hash")),
        normalize(identity.get("phone")),
    }
    identifiers.discard("")

    matches = []

    def walk(value, system=""):
        if isinstance(value, dict):
            observed_at = parse_time(value.get("observed_at", ""))
            if observed_at and observed_at > cutoff:
                return

            values = {
                normalize(v) for v in value.values()
                if isinstance(v, (str, int, float))
            }

            if identifiers.intersection(values):
                matches.append({
                    "file_id": item["file_id"],
                    "file_path": item["file_path"],
                    "system": system,
                    "resource_id": value.get("resource_id", ""),
                    "observed_at": value.get("observed_at", ""),
                    "record": value,
                })

            for key, child in value.items():
                walk(
                    child,
                    key if key.endswith("_service") else system,
                )

        elif isinstance(value, list):
            for child in value:
                walk(child, system)

    walk(data)
    return matches


def build_resource_links(activity, request, identity):
    """Find identity-to-resource links available at audit time."""
    cutoff = parse_time(request.get("audit_at"))
    if cutoff is None or identity is None:
        return []

    user_id = normalize(identity.get("user_id"))
    email = normalize(identity.get("email"))
    links = []

    for event in activity:
        if event.get("event_type") != "LINK_RESOURCE_IDENTITY":
            continue

        event_time = parse_time(event.get("event_time"))
        if event_time is None or event_time > cutoff:
            continue

        details = normalize(event.get("details", ""))
        resource_id = event.get("resource_id", "")

        mentions_user = bool(
            user_id and re.search(
                rf"(?<![a-z0-9_]){re.escape(user_id)}(?![a-z0-9_])",
                details,
            )
        )
        mentions_email = bool(email and email in details)

        if mentions_user and mentions_email and resource_id:
            links.append({
                "activity_id": event["activity_id"],
                "event_time": event["event_time"],
                "system_id": event["target_system"],
                "resource_id": resource_id,
            })

    return links


def main():
    requests = read_csv("deletion_requests.csv")
    identities = read_csv("user_identities.csv")
    activity = read_csv("system_activity.csv")
    evidence = load_evidence()

    total_links = 0
    total_json_matches = 0

    for request in requests:
        identity = resolve_identity(request, identities)
        if identity is None:
            continue

        eligible = evidence_at_cutoff(
            evidence, request["audit_at"]
        )

        links = build_resource_links(
            activity, request, identity
        )
        total_links += len(links)

        for item in eligible:
            if item["file_path"].lower().endswith(".json"):
                matches = inspect_json_evidence(
                    item, identity, request["audit_at"]
                )
                total_json_matches += len(matches)

    print(f"Requests: {len(requests)}")
    print(f"Identities: {len(identities)}")
    print(f"Activity records: {len(activity)}")
    print(f"Readable evidence files: {len(evidence)}")
    print(f"Resource links found: {total_links}")
    print(f"Matching JSON records found: {total_json_matches}")
    print("Diagnostic completed; final output is not generated yet.")


if __name__ == "__main__":
    main()

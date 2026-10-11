"""
Cowrie log parser

Converts raw cowrie.json events into one row per attacker session.

Usage:
    python parse_cowrie.py

Expects cowrie.json to be in the same folder as this script.
Produces sessions.csv as output.
"""

import json
from collections import defaultdict
from datetime import datetime

import pandas as pd


def parse_timestamp(ts_str):
    """Parse a Cowrie timestamp."""
    if not ts_str:
        return None

    try:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        try:
            return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return None


def parse_cowrie_log(log_path):
    sessions = defaultdict(lambda: {
        "source_ip": None,
        "start_time": None,
        "end_time": None,
        "duration_seconds": None,
        "login_attempts": 0,
        "successful_logins": 0,
        "usernames": set(),
        "passwords": set(),
        "commands": [],
        "download_attempts": 0,
    })

    skipped_lines = 0

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                skipped_lines += 1
                continue

            session_id = event.get("session")

            if not session_id:
                continue

            s = sessions[session_id]
            eventid = event.get("eventid", "")
            ts = parse_timestamp(event.get("timestamp"))

            if s["source_ip"] is None and "src_ip" in event:
                s["source_ip"] = event["src_ip"]

            if ts:
                if s["start_time"] is None or ts < s["start_time"]:
                    s["start_time"] = ts

                if s["end_time"] is None or ts > s["end_time"]:
                    s["end_time"] = ts

            if eventid == "cowrie.login.failed":
                s["login_attempts"] += 1

                if "username" in event:
                    s["usernames"].add(event["username"])

                if "password" in event:
                    s["passwords"].add(event["password"])

            elif eventid == "cowrie.login.success":
                s["login_attempts"] += 1
                s["successful_logins"] += 1

                if "username" in event:
                    s["usernames"].add(event["username"])

                if "password" in event:
                    s["passwords"].add(event["password"])

            elif eventid == "cowrie.command.input":
                if "input" in event:
                    s["commands"].append(event["input"])

            elif eventid in (
                "cowrie.session.file_download",
                "cowrie.session.file_upload"
            ):
                s["download_attempts"] += 1

            elif eventid == "cowrie.session.closed":
                if "duration" in event:
                    s["duration_seconds"] = event["duration"]

    rows = []

    for session_id, s in sessions.items():
        duration = s["duration_seconds"]

        if duration is None and s["start_time"] and s["end_time"]:
            duration = (
                s["end_time"] - s["start_time"]
            ).total_seconds()

        rows.append({
            "session_id": session_id,
            "source_ip": s["source_ip"],
            "start_time": s["start_time"],
            "end_time": s["end_time"],
            "duration_seconds": duration,
            "login_attempts": s["login_attempts"],
            "successful_logins": s["successful_logins"],
            "unique_usernames": len(s["usernames"]),
            "unique_passwords": len(s["passwords"]),
            "command_count": len(s["commands"]),
            "unique_command_count": len(set(s["commands"])),
            "commands": "; ".join(s["commands"]),
            "download_attempts": s["download_attempts"],
        })

    df = pd.DataFrame(rows)

    if not df.empty:
        df = df.sort_values("start_time").reset_index(drop=True)

    if skipped_lines:
        print(
            f"Note: skipped {skipped_lines} malformed/unreadable log lines."
        )

    return df


if __name__ == "__main__":
    df = parse_cowrie_log("cowrie.json")

    print(df)

    df.to_csv("sessions.csv", index=False)

    print(f"\nSaved {len(df)} session(s) to sessions.csv")
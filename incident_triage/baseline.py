import json
import os
import sys

import httpx

SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:7860")

SYSTEM_PROMPT = """\
You are an expert incident response engineer performing triage on server alerts.

For each alert, determine:
1. Severity (P1-P4): P1=Critical/outage, P2=Major degradation, P3=Minor issue, P4=Info
2. Owning team: infra, network, app, database, or security
3. Related alerts: list IDs if part of a cascading failure
4. Root cause: identify the root cause alert ID for chain alerts

Respond with a JSON array of triage actions:
{
  "alert_id": "ALERT-XXXX",
  "assigned_severity": "P1",
  "assigned_team": "infra",
  "related_alert_ids": ["ALERT-YYYY"],
  "root_cause_alert_id": "ALERT-ZZZZ"
}

Use timestamps, services, hosts, and metrics to spot cascading patterns.
Earlier alerts with lower severity affecting dependent services are likely root causes.
"""


def run_baseline():
    try:
        from openai import OpenAI
    except ImportError:
        print("Error: openai package required. Install with: pip install openai")
        sys.exit(1)

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY env var required")
        sys.exit(1)

    client = OpenAI(api_key=api_key)
    http = httpx.Client(base_url=SERVER_URL, timeout=30)

    tasks = http.get("/tasks").json()
    print(f"{'Task':<12} {'Score':>8} {'Details'}")
    print("-" * 60)

    for task_info in tasks:
        task_id = task_info["task_id"]

        from incident_triage.server.tasks import get_task
        from incident_triage.server.alert_generator import generate_task_alerts

        task = get_task(task_id)
        alerts = generate_task_alerts(task_id, task.seed)
        obs_alerts = [a.to_observation_dict() for a in alerts]

        alert_text = json.dumps(obs_alerts, indent=2)
        user_prompt = (
            f"Task: {task_info['description']}\n\n"
            f"Alerts ({len(obs_alerts)} total):\n{alert_text}\n\n"
            "Respond with ONLY a JSON array of triage actions."
        )

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
            max_tokens=4096,
        )

        content = response.choices[0].message.content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[1]
            if content.endswith("```"):
                content = content[: content.rfind("```")]
        try:
            actions = json.loads(content)
        except json.JSONDecodeError:
            print(f"{task_id:<12} {'FAIL':>8} Could not parse LLM response")
            continue

        grade_resp = http.post(
            "/grader",
            json={"task_id": task_id, "actions": actions},
        ).json()

        breakdown = ", ".join(
            f"{k}={v:.2f}" for k, v in grade_resp["breakdown"].items()
        )
        print(f"{task_id:<12} {grade_resp['score']:>8.4f} {breakdown}")

    http.close()


if __name__ == "__main__":
    run_baseline()

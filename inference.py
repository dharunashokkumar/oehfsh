"""Hackathon inference script for Incident Response Triage environment.

Uses the OpenAI-compatible client with HF router as the LLM backend.
Runs all tasks against the environment, gets LLM triage actions, and grades them.

Required env vars:
  API_BASE_URL  — LLM endpoint (default: https://router.huggingface.co/v1)
  MODEL_NAME    — model identifier
  HF_TOKEN or API_KEY — auth key
  SERVER_URL    — environment URL (default: http://localhost:7860)
"""

import json
import os
import sys

import httpx

API_BASE_URL = os.environ.get("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.environ.get("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
API_KEY = os.environ.get("HF_TOKEN") or os.environ.get("API_KEY", "")
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


def main():
    try:
        from openai import OpenAI
    except ImportError:
        print("Error: openai package required. Install with: pip install openai")
        sys.exit(1)

    if not API_KEY:
        print("Error: HF_TOKEN or API_KEY env var required")
        sys.exit(1)

    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
    http = httpx.Client(base_url=SERVER_URL, timeout=60)

    tasks = http.get("/tasks").json()
    print(f"Model: {MODEL_NAME}")
    print(f"Server: {SERVER_URL}")
    print(f"{'Task':<12} {'Score':>8} {'Details'}")
    print("-" * 70)

    for task_info in tasks:
        task_id = task_info["task_id"]
        rewards = []
        steps_taken = 0
        score = 0.0
        success = False

        print(f"[START] task={task_id} env=incident-triage-env model={MODEL_NAME}", flush=True)

        try:
            # Reset the environment for this task
            reset_resp = http.post("/reset", json={"task_id": task_id}).json()
            obs = reset_resp["observation"]
            obs_alerts = obs["alerts"]

            alert_text = json.dumps(obs_alerts, indent=2)
            user_prompt = (
                f"Task: {task_info['description']}\n\n"
                f"Alerts ({len(obs_alerts)} total):\n{alert_text}\n\n"
                "Respond with ONLY a JSON array of triage actions."
            )

            try:
                response = client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=0,
                    max_tokens=4096,
                )
            except Exception as e:
                steps_taken = 1
                rewards.append(0.0)
                print(f"[STEP] step=1 action=llm_call reward=0.00 done=true error={e}", flush=True)
                continue

            content = response.choices[0].message.content.strip()
            # Strip markdown code fences if present
            if content.startswith("```"):
                content = content.split("\n", 1)[1]
                if content.endswith("```"):
                    content = content[: content.rfind("```")]
            try:
                actions = json.loads(content)
            except json.JSONDecodeError:
                steps_taken = 1
                rewards.append(0.0)
                print(f"[STEP] step=1 action=parse_response reward=0.00 done=true error=JSONDecodeError", flush=True)
                continue

            grade_resp = http.post(
                "/grader",
                json={"task_id": task_id, "actions": actions},
            ).json()

            score = grade_resp["score"]
            score = min(max(score, 0.0), 1.0)
            success = score > 0.0
            steps_taken = 1
            rewards.append(score)

            print(f"[STEP] step=1 action=triage reward={score:.2f} done=true error=null", flush=True)

        finally:
            rewards_str = ",".join(f"{r:.2f}" for r in rewards) if rewards else "0.00"
            if steps_taken == 0:
                steps_taken = 1
            print(f"[END] success={str(success).lower()} steps={steps_taken} score={score:.2f} rewards={rewards_str}", flush=True)

    http.close()


if __name__ == "__main__":
    main()

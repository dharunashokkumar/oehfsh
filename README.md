---
title: Incident Triage Environment
emoji: 🚨
colorFrom: red
colorTo: yellow
sdk: docker
app_port: 7860
tags:
  - openenv
---

# Incident Response Triage

I built this for the OpenEnv Hackathon. It's an RL environment where an agent triages production alerts -- classifying severity, routing to the right team, grouping cascading failures, and finding root causes.

The alerts are modeled after what you'd actually see in a Grafana/PagerDuty feed: structured log lines from postgres, k8s, nginx, etc. Each task ramps up complexity from basic classification to full incident commander scenarios with noise filtering.

## Action space

Each step the agent submits a `TriageAction`:

| Field | Type | Description |
|-------|------|-------------|
| `alert_id` | `str` | alert being triaged |
| `assigned_severity` | `str` | P1 (critical) through P4 (info) |
| `assigned_team` | `str` | infra / network / app / database / security |
| `related_alert_ids` | `list[str] \| None` | IDs of related cascading alerts |
| `root_cause_alert_id` | `str \| None` | root cause alert ID |
| `root_cause_description` | `str \| None` | free-text root cause |
| `action_type` | `str` | "triage" (default) or "acknowledge" |

## Tasks

| Task | Difficulty | Alerts | What's tested | Grading |
|------|-----------|--------|---------------|---------|
| task_1 | Easy | 3-5 | independent alerts only | severity 50%, team 50% |
| task_2 | Medium | 8-10 | 2-3 cascading chains | severity 30%, team 30%, grouping 40% |
| task_3 | Hard | 15-20 | chains + red herrings | severity 20%, team 20%, grouping 25%, root cause 35% |
| task_4 | Expert | 30+ | 5+ chains, noise, ambiguous ownership | severity 15%, team 15%, grouping 25%, root cause 30%, noise 15% |

## Reward shaping

- Base step cost: **-0.02** (time pressure)
- Invalid alert ID: **-0.10**
- Correct severity: **+0.10**, dangerous downgrade (P1/P2 -> P3/P4): **-0.05**
- Correct team: **+0.10**, wrong team: **-0.05**
- Good grouping (Jaccard >= 0.5): **+0.15**
- Correct root cause: **+0.20**
- Triaging a noise alert: **-0.05**
- Acknowledging an alert: **+0.01**
- SLA penalty (task_4 only): **-0.03** per step late past SLA threshold

## Design decisions

**Cascading chains** are the core mechanic. A database lock contention alert spawns downstream app timeouts, which spawn network-layer 5xx spikes. The agent needs to trace the cascade backwards through timestamps and service dependencies to find the root cause. Chain rules enforce realistic propagation paths (db -> app -> network, not the reverse).

**Noise alerts** in task_4 (health checks passing, deploys succeeding, scheduled maintenance) test whether the agent can distinguish signal from noise. Triaging noise is penalized; ignoring it is rewarded.

**Red herrings** share hosts/services with real chains but are independent. They test whether the agent over-groups alerts based on superficial similarity.

## Setup

```bash
pip install -e "."
uvicorn incident_triage.server.app:app --host 0.0.0.0 --port 7860
```

Docker:
```bash
docker build -t incident-triage .
docker run -p 7860:7860 incident-triage
```

## API

WebSocket at `/ws` for reset/step/state (standard OpenEnv protocol).

REST:
- `GET /tasks` -- list tasks
- `POST /grader` -- grade actions: `{"task_id": "task_1", "actions": [...]}`
- `POST /baseline` -- heuristic baseline (all P3/infra) across all tasks

## Baseline scores

Heuristic baseline (assign all alerts P3/infra, no grouping):

| Task | Score | Severity | Team | Grouping | Root Cause | Noise |
|------|-------|----------|------|----------|------------|-------|
| task_1 | 0.40 | 0.00 | 0.80 | — | — | — |
| task_2 | 0.30 | 0.22 | 0.33 | 0.33 | — | — |
| task_3 | 0.34 | 0.21 | 0.21 | 0.33 | 0.50 | — |
| task_4 | 0.38 | 0.15 | 0.21 | 0.24 | 0.39 | 1.00 |

## LLM inference

```bash
export HF_TOKEN=hf_...
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
python inference.py
```

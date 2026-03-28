from __future__ import annotations

from pydantic import BaseModel
from fastapi import Body, HTTPException
from openenv.core.env_server.http_server import (
    create_app,
    serialize_observation,
    deserialize_action,
)

from incident_triage.models import TriageAction, TriageObservation
from incident_triage.server.incident_triage_environment import (
    IncidentTriageEnvironment,
)
from incident_triage.server.tasks import list_tasks, get_task
from incident_triage.server.alert_generator import generate_task_alerts
from incident_triage.server.graders import grade


app = create_app(
    IncidentTriageEnvironment,
    TriageAction,
    TriageObservation,
    env_name="incident-triage-env",
    max_concurrent_envs=10,
)

# ---------------------------------------------------------------------------
# Replace the framework's stateless REST /reset, /step, /state with stateful
# versions that share a server-side environment instance.
# The framework creates+destroys a fresh env per REST call, so sequential
# reset -> step flows lose state.  We fix that here.
# ---------------------------------------------------------------------------

# Remove the framework-registered REST routes we are replacing
_OVERRIDE_PATHS = {"/reset", "/step", "/state"}
app.router.routes[:] = [
    r for r in app.router.routes if getattr(r, "path", None) not in _OVERRIDE_PATHS
]

# Server-side environment instance (single-session; sufficient for judge eval)
_active_env: IncidentTriageEnvironment | None = None


class ResetRequest(BaseModel):
    task_id: str = "task_1"
    seed: int | None = None
    episode_id: str | None = None


class StepRequest(BaseModel):
    action: dict


@app.post("/reset")
def reset_env(req: ResetRequest = Body(default_factory=ResetRequest)):
    global _active_env
    _active_env = IncidentTriageEnvironment()
    obs = _active_env.reset(
        seed=req.seed,
        episode_id=req.episode_id,
        task_id=req.task_id,
    )
    return serialize_observation(obs)


@app.post("/step")
def step_env(req: StepRequest = Body(...)):
    if _active_env is None:
        raise HTTPException(status_code=400, detail="No active session. Call /reset first.")
    action = deserialize_action(req.action, TriageAction)
    obs = _active_env.step(action)
    return serialize_observation(obs)


@app.get("/state")
def get_state():
    if _active_env is None:
        raise HTTPException(status_code=400, detail="No active session. Call /reset first.")
    state = _active_env.state
    return state.model_dump()


# ---------------------------------------------------------------------------
# Custom endpoints
# ---------------------------------------------------------------------------

@app.get("/tasks")
def get_tasks() -> list[dict]:
    return list_tasks()


class GraderRequest(BaseModel):
    task_id: str
    actions: list[dict]


class GraderResponse(BaseModel):
    score: float
    breakdown: dict[str, float]
    details: dict[str, float]
    per_alert: list[dict] = []


@app.post("/grader", response_model=GraderResponse)
def run_grader(req: GraderRequest) -> dict:
    task = get_task(req.task_id)
    alerts = generate_task_alerts(req.task_id, task.seed)
    ground_truth = [a.to_dict() for a in alerts]
    return grade(req.task_id, req.actions, ground_truth)


class BaselineResponse(BaseModel):
    task_id: str
    score: float
    breakdown: dict[str, float]


@app.post("/baseline")
def run_heuristic_baseline() -> list[dict]:
    results = []
    for task_id in ["task_1", "task_2", "task_3", "task_4"]:
        task = get_task(task_id)
        alerts = generate_task_alerts(task_id, task.seed)
        ground_truth = [a.to_dict() for a in alerts]

        actions = [
            {
                "alert_id": a.alert_id,
                "assigned_severity": "P3",
                "assigned_team": "infra",
                "related_alert_ids": [],
                "root_cause_alert_id": None,
            }
            for a in alerts
            if not a.is_noise
        ]
        result = grade(task_id, actions, ground_truth)
        results.append(
            {
                "task_id": task_id,
                "score": result["score"],
                "breakdown": result["breakdown"],
            }
        )
    return results


@app.get("/")
def root():
    return {
        "name": "incident-triage-env",
        "status": "running",
        "tasks": 4,
        "endpoints": ["/tasks", "/reset", "/step", "/state", "/grader", "/baseline"],
    }

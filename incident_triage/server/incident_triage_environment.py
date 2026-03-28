import time
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment

from incident_triage.models import (
    Alert,
    TriageAction,
    TriageObservation,
    TriageState,
)
from incident_triage.server.alert_generator import generate_task_alerts
from incident_triage.server.tasks import get_task

SLA_STEPS = {"P1": 5, "P2": 10}


class IncidentTriageEnvironment(
    Environment[TriageAction, TriageObservation, TriageState]
):
    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self) -> None:
        super().__init__()
        self._alerts: list[Alert] = []
        self._processed: dict[str, dict] = {}
        self._acknowledged: set[str] = set()
        self._alert_first_step: dict[str, int] = {}
        self._current_step = 0
        self._cumulative_reward = 0.0
        self._start_time = 0.0
        self._task_id = ""
        self._task_description = ""
        self._max_steps = 10
        self._done = False
        self._episode_id = str(uuid4())

    def reset(
        self,
        seed: int | None = None,
        episode_id: str | None = None,
        **kwargs,
    ) -> TriageObservation:
        task_id = kwargs.get("task_id", "task_1")
        task = get_task(task_id)

        self._task_id = task_id
        self._task_description = task.description
        self._max_steps = task.max_steps
        self._episode_id = episode_id or str(uuid4())
        self._alerts = generate_task_alerts(task_id, task.seed)
        self._processed = {}
        self._acknowledged = set()
        self._alert_first_step = {}
        self._current_step = 0
        self._cumulative_reward = 0.0
        self._start_time = time.time()
        self._done = False

        return self._build_observation()

    def step(
        self,
        action: TriageAction,
        timeout_s: float | None = None,
        **kwargs,
    ) -> TriageObservation:
        if self._done:
            return self._build_observation()

        self._current_step += 1
        reward = -0.02

        alert_map = {a.alert_id: a for a in self._alerts}
        alert_id = action.alert_id

        if alert_id not in alert_map:
            reward = -0.1
        elif action.action_type == "acknowledge":
            if alert_id not in self._acknowledged:
                self._acknowledged.add(alert_id)
                reward += 0.01
        elif alert_id in self._processed:
            pass
        else:
            alert = alert_map[alert_id]

            if alert.is_noise:
                reward = -0.05
                self._processed[alert_id] = {
                    "alert_id": alert_id,
                    "assigned_severity": action.assigned_severity,
                    "assigned_team": action.assigned_team,
                    "related_alert_ids": action.related_alert_ids or [],
                    "root_cause_alert_id": action.root_cause_alert_id,
                    "root_cause_description": action.root_cause_description,
                }
            else:
                if action.assigned_severity == alert.expected_severity:
                    reward += 0.1
                elif (
                    alert.expected_severity in ("P1", "P2")
                    and action.assigned_severity in ("P3", "P4")
                ):
                    reward -= 0.05

                if action.assigned_team == alert.expected_team:
                    reward += 0.1
                else:
                    reward -= 0.05

                if action.related_alert_ids is not None:
                    gt_related = set(alert.related_alert_ids)
                    pred_related = set(action.related_alert_ids)
                    if gt_related or pred_related:
                        jaccard = (
                            len(gt_related & pred_related)
                            / len(gt_related | pred_related)
                            if (gt_related | pred_related)
                            else 1.0
                        )
                        if jaccard >= 0.5:
                            reward += 0.15

                if action.root_cause_alert_id is not None:
                    if action.root_cause_alert_id == alert.root_cause_id:
                        reward += 0.2

                # SLA penalty for task_4
                if self._task_id == "task_4" and alert_id in self._alert_first_step:
                    sla_limit = SLA_STEPS.get(alert.expected_severity)
                    if sla_limit is not None:
                        steps_since_seen = self._current_step - self._alert_first_step[alert_id]
                        if steps_since_seen > sla_limit:
                            reward -= 0.03 * (steps_since_seen - sla_limit)

                self._processed[alert_id] = {
                    "alert_id": alert_id,
                    "assigned_severity": action.assigned_severity,
                    "assigned_team": action.assigned_team,
                    "related_alert_ids": action.related_alert_ids or [],
                    "root_cause_alert_id": action.root_cause_alert_id,
                    "root_cause_description": action.root_cause_description,
                }

        self._cumulative_reward += reward

        # track when alerts are first seen (for SLA)
        for a in self._alerts:
            if a.alert_id not in self._alert_first_step:
                self._alert_first_step[a.alert_id] = self._current_step

        # termination: only count non-noise alerts toward completion
        triageable = sum(1 for a in self._alerts if not a.is_noise)
        non_noise_processed = sum(
            1 for aid in self._processed
            if aid in alert_map and not alert_map[aid].is_noise
        )

        if non_noise_processed >= triageable or self._current_step >= self._max_steps:
            self._done = True

        obs = self._build_observation()
        obs.reward = reward
        return obs

    @property
    def state(self) -> TriageState:
        return TriageState(
            episode_id=self._episode_id,
            step_count=self._current_step,
            alerts=[a.to_observation_dict() for a in self._alerts],
            processed_alerts=list(self._processed.values()),
            cumulative_reward=self._cumulative_reward,
            ground_truth=[a.to_dict() for a in self._alerts],
            total_alerts=len(self._alerts),
            current_step_num=self._current_step,
            max_steps=self._max_steps,
            task_id=self._task_id,
        )

    def _build_observation(self) -> TriageObservation:
        elapsed = time.time() - self._start_time if self._start_time else 0.0
        return TriageObservation(
            alerts=[a.to_observation_dict() for a in self._alerts],
            processed_count=len(self._processed),
            total_alerts=len(self._alerts),
            current_step=self._current_step,
            max_steps=self._max_steps,
            time_elapsed_seconds=round(elapsed, 2),
            task_id=self._task_id,
            task_description=self._task_description,
            done=self._done,
            reward=0.0,
        )

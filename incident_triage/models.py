from dataclasses import dataclass, field

from pydantic import Field as PydanticField
from openenv.core.env_server.types import Action, Observation, State


@dataclass
class Alert:
    alert_id: str
    timestamp: str
    service_name: str
    expected_severity: str  # P1-P4
    source_host: str
    alert_type: str
    message: str
    metrics: dict = field(default_factory=dict)
    expected_team: str = "infra"
    related_alert_ids: list[str] = field(default_factory=list)
    root_cause_id: str = ""
    category: str = ""
    is_noise: bool = False

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "service_name": self.service_name,
            "expected_severity": self.expected_severity,
            "source_host": self.source_host,
            "alert_type": self.alert_type,
            "message": self.message,
            "metrics": self.metrics,
            "expected_team": self.expected_team,
            "related_alert_ids": list(self.related_alert_ids),
            "root_cause_id": self.root_cause_id,
            "is_noise": self.is_noise,
        }

    def to_observation_dict(self) -> dict:
        """Strip ground-truth fields for agent-facing observation."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "service_name": self.service_name,
            "source_host": self.source_host,
            "alert_type": self.alert_type,
            "message": self.message,
            "metrics": dict(self.metrics),
            "category": self.category,
        }


class TriageAction(Action):
    alert_id: str = PydanticField(...)
    assigned_severity: str = PydanticField(...)
    assigned_team: str = PydanticField(...)
    related_alert_ids: list[str] | None = PydanticField(default=None)
    root_cause_description: str | None = PydanticField(default=None)
    root_cause_alert_id: str | None = PydanticField(default=None)
    action_type: str = PydanticField(default="triage")


class TriageObservation(Observation):
    alerts: list[dict] = PydanticField(default_factory=list)
    processed_count: int = PydanticField(default=0)
    total_alerts: int = PydanticField(default=0)
    current_step: int = PydanticField(default=0)
    max_steps: int = PydanticField(default=10)
    time_elapsed_seconds: float = PydanticField(default=0.0)
    task_id: str = PydanticField(default="")
    task_description: str = PydanticField(default="")


class TriageState(State):
    alerts: list[dict] = PydanticField(default_factory=list)
    processed_alerts: list[dict] = PydanticField(default_factory=list)
    cumulative_reward: float = PydanticField(default=0.0)
    ground_truth: list[dict] = PydanticField(default_factory=list)
    total_alerts: int = PydanticField(default=0)
    current_step_num: int = PydanticField(default=0)
    max_steps: int = PydanticField(default=10)
    task_id: str = PydanticField(default="")

from dataclasses import dataclass, field


@dataclass
class TaskDefinition:
    task_id: str
    name: str
    description: str
    seed: int
    max_steps: int
    grading_weights: dict[str, float] = field(default_factory=dict)


TASKS: dict[str, TaskDefinition] = {
    "task_1": TaskDefinition(
        task_id="task_1",
        name="Basic Triage",
        description=(
            "Easy: 3-5 independent alerts. Classify severity (P1-P4) and assign "
            "the correct team. No cascading failures."
        ),
        seed=42,
        max_steps=10,
        grading_weights={"severity": 0.5, "team": 0.5},
    ),
    "task_2": TaskDefinition(
        task_id="task_2",
        name="Cascading Failures",
        description=(
            "Medium: 8-10 alerts including 2-3 cascading chains. Classify severity, "
            "assign teams, and group related alerts."
        ),
        seed=137,
        max_steps=20,
        grading_weights={"severity": 0.3, "team": 0.3, "grouping": 0.4},
    ),
    "task_3": TaskDefinition(
        task_id="task_3",
        name="Full Investigation",
        description=(
            "Hard: 15-20 alerts with 3-4 cascading chains plus red herrings. "
            "Classify, assign, group, and identify root causes."
        ),
        seed=256,
        max_steps=40,
        grading_weights={
            "severity": 0.2,
            "team": 0.2,
            "grouping": 0.25,
            "root_cause": 0.35,
        },
    ),
    "task_4": TaskDefinition(
        task_id="task_4",
        name="Incident Commander",
        description=(
            "Expert: 30+ alerts across 5+ cascading chains, noise alerts that should "
            "be ignored, and ambiguous team ownership. Acknowledge or triage."
        ),
        seed=512,
        max_steps=50,
        grading_weights={
            "severity": 0.15,
            "team": 0.15,
            "grouping": 0.25,
            "root_cause": 0.30,
            "noise": 0.15,
        },
    ),
}


def get_task(task_id: str) -> TaskDefinition:
    if task_id not in TASKS:
        raise ValueError(
            f"Unknown task_id: {task_id}. Available: {list(TASKS.keys())}"
        )
    return TASKS[task_id]


def list_tasks() -> list[dict]:
    return [
        {
            "task_id": t.task_id,
            "name": t.name,
            "description": t.description,
            "max_steps": t.max_steps,
            "grading_weights": t.grading_weights,
        }
        for t in TASKS.values()
    ]

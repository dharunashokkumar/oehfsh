from incident_triage.server.tasks import get_task


def grade_severity(actions: list[dict], ground_truth: list[dict]) -> float:
    gt_map = {a["alert_id"]: a for a in ground_truth}
    if not gt_map:
        return 0.0

    scores: list[float] = []
    seen: set[str] = set()
    for act in actions:
        aid = act.get("alert_id", "")
        if aid in seen or aid not in gt_map:
            continue
        seen.add(aid)
        expected = gt_map[aid]["expected_severity"]
        scores.append(1.0 if act.get("assigned_severity") == expected else 0.0)

    for aid in gt_map:
        if aid not in seen:
            scores.append(0.0)

    return sum(scores) / len(scores) if scores else 0.0


def grade_team(actions: list[dict], ground_truth: list[dict]) -> float:
    gt_map = {a["alert_id"]: a for a in ground_truth}
    if not gt_map:
        return 0.0

    scores: list[float] = []
    seen: set[str] = set()
    for act in actions:
        aid = act.get("alert_id", "")
        if aid in seen or aid not in gt_map:
            continue
        seen.add(aid)
        expected = gt_map[aid]["expected_team"]
        scores.append(1.0 if act.get("assigned_team") == expected else 0.0)

    for aid in gt_map:
        if aid not in seen:
            scores.append(0.0)

    return sum(scores) / len(scores) if scores else 0.0


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def grade_grouping(actions: list[dict], ground_truth: list[dict]) -> float:
    gt_map = {a["alert_id"]: a for a in ground_truth}
    if not gt_map:
        return 0.0

    scores: list[float] = []
    seen: set[str] = set()
    for act in actions:
        aid = act.get("alert_id", "")
        if aid in seen or aid not in gt_map:
            continue
        seen.add(aid)
        expected = set(gt_map[aid].get("related_alert_ids", []))
        predicted = set(act.get("related_alert_ids") or [])
        scores.append(_jaccard(predicted, expected))

    for aid in gt_map:
        if aid not in seen:
            gt_related = set(gt_map[aid].get("related_alert_ids", []))
            scores.append(1.0 if not gt_related else 0.0)

    return sum(scores) / len(scores) if scores else 0.0


def grade_root_cause(actions: list[dict], ground_truth: list[dict]) -> float:
    gt_map = {a["alert_id"]: a for a in ground_truth}
    if not gt_map:
        return 0.0

    scores: list[float] = []
    seen: set[str] = set()
    for act in actions:
        aid = act.get("alert_id", "")
        if aid in seen or aid not in gt_map:
            continue
        seen.add(aid)
        gt_root = gt_map[aid].get("root_cause_id", "")
        is_independent = gt_root == aid

        predicted_root = act.get("root_cause_alert_id")
        if is_independent:
            scores.append(
                1.0 if (predicted_root is None or predicted_root == aid) else 0.0
            )
        else:
            scores.append(1.0 if predicted_root == gt_root else 0.0)

    for aid in gt_map:
        if aid not in seen:
            gt_root = gt_map[aid].get("root_cause_id", "")
            is_independent = gt_root == aid
            scores.append(1.0 if is_independent else 0.0)

    return sum(scores) / len(scores) if scores else 0.0


def grade_noise(actions: list[dict], ground_truth: list[dict]) -> float:
    noise_ids = {a["alert_id"] for a in ground_truth if a.get("is_noise")}
    if not noise_ids:
        return 1.0

    triaged_ids = {act.get("alert_id", "") for act in actions}
    scores: list[float] = []
    for nid in noise_ids:
        scores.append(0.0 if nid in triaged_ids else 1.0)

    return sum(scores) / len(scores) if scores else 1.0


def grade(task_id: str, actions: list[dict], ground_truth: list[dict]) -> dict:
    task = get_task(task_id)
    weights = task.grading_weights

    # filter out noise alerts from ground truth for non-noise graders
    non_noise_gt = [a for a in ground_truth if not a.get("is_noise")]

    breakdown: dict[str, float] = {}
    details: dict[str, float] = {}
    per_alert: list[dict] = []

    if "severity" in weights:
        s = grade_severity(actions, non_noise_gt)
        breakdown["severity"] = s
        details["severity_weighted"] = s * weights["severity"]

    if "team" in weights:
        s = grade_team(actions, non_noise_gt)
        breakdown["team"] = s
        details["team_weighted"] = s * weights["team"]

    if "grouping" in weights:
        s = grade_grouping(actions, non_noise_gt)
        breakdown["grouping"] = s
        details["grouping_weighted"] = s * weights["grouping"]

    if "root_cause" in weights:
        s = grade_root_cause(actions, non_noise_gt)
        breakdown["root_cause"] = s
        details["root_cause_weighted"] = s * weights["root_cause"]

    if "noise" in weights:
        s = grade_noise(actions, ground_truth)
        breakdown["noise"] = s
        details["noise_weighted"] = s * weights["noise"]

    # build per-alert detail
    gt_map = {a["alert_id"]: a for a in non_noise_gt}
    action_map = {act.get("alert_id", ""): act for act in actions}
    for aid, gt in gt_map.items():
        act = action_map.get(aid, {})
        per_alert.append({
            "alert_id": aid,
            "severity_correct": act.get("assigned_severity") == gt["expected_severity"],
            "team_correct": act.get("assigned_team") == gt["expected_team"],
            "expected_severity": gt["expected_severity"],
            "got_severity": act.get("assigned_severity"),
            "expected_team": gt["expected_team"],
            "got_team": act.get("assigned_team"),
        })

    total = sum(details.values())
    return {
        "score": round(total, 4),
        "breakdown": {k: round(v, 4) for k, v in breakdown.items()},
        "details": {k: round(v, 4) for k, v in details.items()},
        "per_alert": per_alert,
    }

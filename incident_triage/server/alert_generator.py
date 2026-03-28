import random
from datetime import datetime, timedelta, timezone

from incident_triage.models import Alert

TEMPLATES: list[dict] = [
    # infrastructure
    {
        "category": "infrastructure",
        "alert_type": "cpu_spike",
        "service_name": "k8s-node-pool",
        "base_severity": "P2",
        "owning_team": "infra",
        "message_template": "[WARN] cpu.usage_percent={cpu_pct} host={host} threshold=85 | node health degraded",
        "metric_ranges": {"cpu_pct": (85, 100), "memory_pct": (40, 70)},
    },
    {
        "category": "infrastructure",
        "alert_type": "disk_full",
        "service_name": "ebs-vol-manager",
        "base_severity": "P1",
        "owning_team": "infra",
        "message_template": "[CRIT] df /var/lib: {disk_pct}% used on {host} -- /var/log consuming 38G",
        "metric_ranges": {"disk_pct": (90, 99), "cpu_pct": (20, 50)},
    },
    {
        "category": "infrastructure",
        "alert_type": "oom_kill",
        "service_name": "k8s-node-pool",
        "base_severity": "P1",
        "owning_team": "infra",
        "message_template": "[CRIT] kernel: oom-kill:constraint=CONSTRAINT_MEMCG on {host} pid=4821 killed",
        "metric_ranges": {"memory_pct": (95, 100), "cpu_pct": (60, 90)},
    },
    {
        "category": "infrastructure",
        "alert_type": "high_memory",
        "service_name": "celery-worker",
        "base_severity": "P3",
        "owning_team": "infra",
        "message_template": "[WARN] mem.usage_percent={memory_pct} host={host} | resident set growing",
        "metric_ranges": {"memory_pct": (80, 94), "cpu_pct": (30, 60)},
    },
    {
        "category": "infrastructure",
        "alert_type": "swap_thrashing",
        "service_name": "k8s-node-pool",
        "base_severity": "P2",
        "owning_team": "infra",
        "message_template": "[WARN] vmstat: si/so > 500 pages/s on {host} for 5m | swap thrashing",
        "metric_ranges": {"memory_pct": (88, 98), "cpu_pct": (70, 95)},
    },
    {
        "category": "infrastructure",
        "alert_type": "inode_exhaustion",
        "service_name": "ebs-vol-manager",
        "base_severity": "P2",
        "owning_team": "infra",
        "message_template": "[WARN] inode usage 98% on {host}:/data -- cannot create new files",
        "metric_ranges": {"disk_pct": (70, 85)},
    },
    {
        "category": "infrastructure",
        "alert_type": "disk_io_saturation",
        "service_name": "ebs-vol-manager",
        "base_severity": "P2",
        "owning_team": "infra",
        "message_template": "[WARN] iostat: await={latency_ms}ms util=99% on {host}:/dev/xvda",
        "metric_ranges": {"disk_pct": (60, 80), "latency_ms": (200, 800)},
    },
    {
        "category": "infrastructure",
        "alert_type": "zombie_processes",
        "service_name": "k8s-node-pool",
        "base_severity": "P4",
        "owning_team": "infra",
        "message_template": "[INFO] ps: 14 zombie processes on {host} -- parent pid=1 not reaping",
        "metric_ranges": {"cpu_pct": (10, 30), "memory_pct": (20, 40)},
    },
    # network
    {
        "category": "network",
        "alert_type": "connection_timeout",
        "service_name": "nginx-ingress",
        "base_severity": "P2",
        "owning_team": "network",
        "message_template": "[ERR] upstream timeout host={host} after 30s -- 504 returned to client",
        "metric_ranges": {"latency_ms": (30000, 60000), "error_rate": (5, 20)},
    },
    {
        "category": "network",
        "alert_type": "dns_failure",
        "service_name": "coredns",
        "base_severity": "P1",
        "owning_team": "network",
        "message_template": "[CRIT] SERVFAIL for {host} -- all upstream resolvers unreachable",
        "metric_ranges": {"error_rate": (50, 100)},
    },
    {
        "category": "network",
        "alert_type": "ssl_cert_expiry",
        "service_name": "nginx-lb-01",
        "base_severity": "P3",
        "owning_team": "network",
        "message_template": "[WARN] x509: cert for {host} expires in 72h -- auto-renew failed",
        "metric_ranges": {},
    },
    {
        "category": "network",
        "alert_type": "high_latency",
        "service_name": "nginx-ingress",
        "base_severity": "P2",
        "owning_team": "network",
        "message_template": "[WARN] p99_latency={latency_ms}ms host={host} | SLO breach >500ms",
        "metric_ranges": {"latency_ms": (500, 5000), "error_rate": (1, 10)},
    },
    {
        "category": "network",
        "alert_type": "packet_loss",
        "service_name": "arista-core-sw",
        "base_severity": "P2",
        "owning_team": "network",
        "message_template": "[WARN] mtr {host}->upstream: 12% packet loss over 5m window",
        "metric_ranges": {"error_rate": (10, 25)},
    },
    {
        "category": "network",
        "alert_type": "port_unreachable",
        "service_name": "nginx-ingress",
        "base_severity": "P1",
        "owning_team": "network",
        "message_template": "[CRIT] healthcheck: {host}:443 connection refused -- service down",
        "metric_ranges": {"error_rate": (80, 100)},
    },
    {
        "category": "network",
        "alert_type": "bgp_flap",
        "service_name": "vyos-edge-01",
        "base_severity": "P1",
        "owning_team": "network",
        "message_template": "[CRIT] bgpd: neighbor {host} state Established->Active 4x in 60s",
        "metric_ranges": {"error_rate": (30, 60)},
    },
    # application
    {
        "category": "application",
        "alert_type": "http_5xx",
        "service_name": "react-ssr",
        "base_severity": "P1",
        "owning_team": "app",
        "message_template": "[CRIT] 5xx_rate={error_rate}% host={host} | users seeing error pages",
        "metric_ranges": {"error_rate": (10, 50), "latency_ms": (200, 2000)},
    },
    {
        "category": "application",
        "alert_type": "slow_response",
        "service_name": "order-api",
        "base_severity": "P2",
        "owning_team": "app",
        "message_template": "[WARN] p95={latency_ms}ms host={host} endpoint=/api/v2/orders",
        "metric_ranges": {"latency_ms": (1000, 10000), "cpu_pct": (50, 80)},
    },
    {
        "category": "application",
        "alert_type": "queue_backlog",
        "service_name": "rabbitmq-prod",
        "base_severity": "P2",
        "owning_team": "app",
        "message_template": "[WARN] queue.depth > 10k on {host} | consumers lagging",
        "metric_ranges": {"latency_ms": (500, 3000)},
    },
    {
        "category": "application",
        "alert_type": "deadlock",
        "service_name": "order-api",
        "base_severity": "P1",
        "owning_team": "app",
        "message_template": "[CRIT] ThreadDump: 3 threads BLOCKED on {host} -- deadlock detected",
        "metric_ranges": {"cpu_pct": (5, 20), "latency_ms": (30000, 60000)},
    },
    {
        "category": "application",
        "alert_type": "memory_leak",
        "service_name": "order-api",
        "base_severity": "P2",
        "owning_team": "app",
        "message_template": "[WARN] heap.used growing linearly on {host} -- 12% increase/hr",
        "metric_ranges": {"memory_pct": (70, 95), "cpu_pct": (40, 70)},
    },
    {
        "category": "application",
        "alert_type": "crash_loop",
        "service_name": "payment-processor",
        "base_severity": "P1",
        "owning_team": "app",
        "message_template": "[CRIT] k8s: pod CrashLoopBackOff on {host} -- 5 restarts in 10m",
        "metric_ranges": {"error_rate": (80, 100), "cpu_pct": (10, 30)},
    },
    {
        "category": "application",
        "alert_type": "thread_pool_exhausted",
        "service_name": "order-api",
        "base_severity": "P1",
        "owning_team": "app",
        "message_template": "[CRIT] tomcat: active_threads=200/200 on {host} -- requests queuing",
        "metric_ranges": {"latency_ms": (5000, 30000), "cpu_pct": (80, 100)},
    },
    {
        "category": "application",
        "alert_type": "gc_pause",
        "service_name": "order-api",
        "base_severity": "P3",
        "owning_team": "app",
        "message_template": "[WARN] jvm.gc.pause=2.3s on {host} -- stop-the-world Full GC",
        "metric_ranges": {"latency_ms": (2000, 8000), "memory_pct": (60, 85)},
    },
    # database
    {
        "category": "database",
        "alert_type": "replication_lag",
        "service_name": "postgres-primary",
        "base_severity": "P2",
        "owning_team": "database",
        "message_template": "[WARN] pg_stat_replication: replay_lag=45s on {host}",
        "metric_ranges": {"latency_ms": (5000, 45000)},
    },
    {
        "category": "database",
        "alert_type": "connection_pool_exhausted",
        "service_name": "postgres-primary",
        "base_severity": "P1",
        "owning_team": "database",
        "message_template": "[CRIT] pgbouncer: cl_active=250/250 on {host} -- new conns rejected",
        "metric_ranges": {"error_rate": (20, 50)},
    },
    {
        "category": "database",
        "alert_type": "slow_query",
        "service_name": "postgres-replica",
        "base_severity": "P3",
        "owning_team": "database",
        "message_template": "[WARN] pg_stat_statements: query on {host} running >10s, seq scan on orders",
        "metric_ranges": {"latency_ms": (10000, 60000), "cpu_pct": (50, 80)},
    },
    {
        "category": "database",
        "alert_type": "lock_contention",
        "service_name": "postgres-primary",
        "base_severity": "P2",
        "owning_team": "database",
        "message_template": "[WARN] pg_locks: 47 blocked queries on {host} -- AccessExclusiveLock held",
        "metric_ranges": {"latency_ms": (3000, 15000)},
    },
    {
        "category": "database",
        "alert_type": "tablespace_full",
        "service_name": "postgres-primary",
        "base_severity": "P1",
        "owning_team": "database",
        "message_template": "[CRIT] pg_tablespace: {disk_pct}% full on {host} -- writes will fail",
        "metric_ranges": {"disk_pct": (92, 99)},
    },
    {
        "category": "database",
        "alert_type": "checkpoint_lag",
        "service_name": "postgres-primary",
        "base_severity": "P3",
        "owning_team": "database",
        "message_template": "[WARN] pg_stat_bgwriter: checkpoint_write_time spiking on {host}",
        "metric_ranges": {"disk_pct": (60, 80)},
    },
    {
        "category": "database",
        "alert_type": "vacuum_delay",
        "service_name": "postgres-primary",
        "base_severity": "P4",
        "owning_team": "database",
        "message_template": "[INFO] autovacuum: table bloat on {host} -- dead tuples > 1M rows",
        "metric_ranges": {"disk_pct": (50, 70)},
    },
    # security
    {
        "category": "security",
        "alert_type": "brute_force",
        "service_name": "auth-api",
        "base_severity": "P1",
        "owning_team": "security",
        "message_template": "[CRIT] fail2ban: 847 failed logins from {host} in 5m -- IP banned",
        "metric_ranges": {"error_rate": (60, 95)},
    },
    {
        "category": "security",
        "alert_type": "unauthorized_access",
        "service_name": "auth-api",
        "base_severity": "P1",
        "owning_team": "security",
        "message_template": "[CRIT] audit: unauthorized admin API call from {host} -- token invalid",
        "metric_ranges": {"error_rate": (1, 10)},
    },
    {
        "category": "security",
        "alert_type": "anomalous_traffic",
        "service_name": "cloudflare-waf",
        "base_severity": "P2",
        "owning_team": "security",
        "message_template": "[WARN] waf: anomalous request pattern from {host} -- rule 942100 triggered",
        "metric_ranges": {"error_rate": (5, 30)},
    },
    {
        "category": "security",
        "alert_type": "firewall_violation",
        "service_name": "iptables-mgr",
        "base_severity": "P2",
        "owning_team": "security",
        "message_template": "[WARN] iptables: DROP in=eth0 src={host} dst=10.0.0.0/8 proto=TCP",
        "metric_ranges": {"error_rate": (10, 40)},
    },
    {
        "category": "security",
        "alert_type": "cert_expiry_warning",
        "service_name": "cert-manager",
        "base_severity": "P3",
        "owning_team": "security",
        "message_template": "[WARN] cert-manager: internal cert for {host} expires in 7d -- renewal pending",
        "metric_ranges": {},
    },
]

NOISE_TEMPLATES: list[dict] = [
    {
        "category": "noise",
        "alert_type": "health_check_ok",
        "service_name": "k8s-node-pool",
        "base_severity": "P4",
        "owning_team": "infra",
        "message_template": "[OK] healthcheck: {host} responding 200 in 12ms -- all probes passing",
        "metric_ranges": {"latency_ms": (5, 50)},
    },
    {
        "category": "noise",
        "alert_type": "cron_complete",
        "service_name": "celery-worker",
        "base_severity": "P4",
        "owning_team": "infra",
        "message_template": "[INFO] cron: daily-cleanup finished on {host} in 34s -- 0 errors",
        "metric_ranges": {"cpu_pct": (5, 20)},
    },
    {
        "category": "noise",
        "alert_type": "deploy_success",
        "service_name": "order-api",
        "base_severity": "P4",
        "owning_team": "app",
        "message_template": "[INFO] deploy: v2.14.3 rolled out to {host} -- 0 failed pods",
        "metric_ranges": {},
    },
    {
        "category": "noise",
        "alert_type": "scheduled_maintenance",
        "service_name": "postgres-primary",
        "base_severity": "P4",
        "owning_team": "database",
        "message_template": "[INFO] maintenance: planned vacuum on {host} started -- ETA 15m",
        "metric_ranges": {"disk_pct": (30, 50)},
    },
]

CHAIN_RULES: dict[str, list[str]] = {
    "database": ["application", "network", "infrastructure"],
    "infrastructure": ["application", "network"],
    "security": ["application", "network", "infrastructure"],
    "network": ["application"],
    "application": ["network"],
}

SEVERITY_ESCALATION = {"P4": "P3", "P3": "P2", "P2": "P1", "P1": "P1"}

HOSTS = [
    "prod-web-01",
    "prod-web-02",
    "prod-api-01",
    "prod-api-02",
    "prod-db-01",
    "prod-db-02",
    "prod-cache-01",
    "prod-worker-01",
    "prod-worker-02",
    "prod-lb-01",
    "prod-queue-01",
    "prod-monitor-01",
]


def _templates_by_category(category: str) -> list[dict]:
    return [t for t in TEMPLATES if t["category"] == category]


def _generate_metrics(template: dict, rng: random.Random) -> dict:
    metrics: dict[str, float] = {}
    for key, (lo, hi) in template.get("metric_ranges", {}).items():
        metrics[key] = round(rng.uniform(lo, hi), 1)
    return metrics


def generate_alert_from_template(
    template: dict,
    rng: random.Random,
    alert_id: str,
    timestamp: str,
    host_override: str | None = None,
    severity_override: str | None = None,
) -> Alert:
    host = host_override or rng.choice(HOSTS)
    metrics = _generate_metrics(template, rng)
    severity = severity_override or template["base_severity"]

    message = template["message_template"].format(
        host=host,
        **{k: v for k, v in metrics.items()},
    )

    return Alert(
        alert_id=alert_id,
        timestamp=timestamp,
        service_name=template["service_name"],
        expected_severity=severity,
        source_host=host,
        alert_type=template["alert_type"],
        message=message,
        metrics=metrics,
        expected_team=template["owning_team"],
        related_alert_ids=[],
        root_cause_id="",
        category=template["category"],
    )


def generate_independent_alerts(
    rng: random.Random,
    count: int,
    start_id: int,
    base_time: datetime,
) -> list[Alert]:
    alerts: list[Alert] = []
    for i in range(count):
        template = rng.choice(TEMPLATES)
        ts = base_time + timedelta(seconds=rng.randint(0, 300))
        alert = generate_alert_from_template(
            template,
            rng,
            alert_id=f"ALERT-{start_id + i:04d}",
            timestamp=ts.isoformat(),
        )
        alert.root_cause_id = alert.alert_id
        alerts.append(alert)
    return alerts


def generate_cascading_chain(
    rng: random.Random,
    chain_length: int,
    start_id: int,
    base_time: datetime,
) -> list[Alert]:
    root_categories = ["database", "infrastructure", "security"]
    root_category = rng.choice(root_categories)
    root_templates = _templates_by_category(root_category)
    if not root_templates:
        root_templates = _templates_by_category("infrastructure")

    root_template = rng.choice(root_templates)
    root_id = f"ALERT-{start_id:04d}"
    root_ts = base_time

    root_host = rng.choice(HOSTS)
    root_alert = generate_alert_from_template(
        root_template,
        rng,
        alert_id=root_id,
        timestamp=root_ts.isoformat(),
        host_override=root_host,
        severity_override="P3",
    )
    root_alert.root_cause_id = root_id

    chain = [root_alert]
    current_category = root_category
    current_severity = "P3"
    current_ts = root_ts

    for i in range(1, chain_length):
        downstream_options = CHAIN_RULES.get(current_category, ["application"])
        next_category = rng.choice(downstream_options)
        next_templates = _templates_by_category(next_category)
        if not next_templates:
            next_templates = _templates_by_category("application")

        next_template = rng.choice(next_templates)
        current_severity = SEVERITY_ESCALATION.get(current_severity, "P1")
        current_ts = current_ts + timedelta(seconds=rng.randint(30, 180))

        alert = generate_alert_from_template(
            next_template,
            rng,
            alert_id=f"ALERT-{start_id + i:04d}",
            timestamp=current_ts.isoformat(),
            severity_override=current_severity,
        )
        alert.root_cause_id = root_id
        alert.related_alert_ids = [a.alert_id for a in chain]
        chain.append(alert)
        current_category = next_category

    all_chain_ids = [a.alert_id for a in chain]
    for alert in chain:
        alert.related_alert_ids = [
            aid for aid in all_chain_ids if aid != alert.alert_id
        ]

    return chain


def generate_red_herrings(
    rng: random.Random,
    count: int,
    chain_alerts: list[Alert],
    start_id: int,
    base_time: datetime,
) -> list[Alert]:
    alerts: list[Alert] = []
    chain_hosts = list({a.source_host for a in chain_alerts})
    chain_services = list({a.service_name for a in chain_alerts})

    for i in range(count):
        template = rng.choice(TEMPLATES)
        ts = base_time + timedelta(seconds=rng.randint(0, 600))

        host = rng.choice(chain_hosts) if chain_hosts and rng.random() < 0.6 else None

        alert = generate_alert_from_template(
            template,
            rng,
            alert_id=f"ALERT-{start_id + i:04d}",
            timestamp=ts.isoformat(),
            host_override=host,
        )
        if chain_services and rng.random() < 0.4:
            alert.service_name = rng.choice(chain_services)

        alert.root_cause_id = alert.alert_id
        alerts.append(alert)

    return alerts


def generate_noise_alerts(
    rng: random.Random,
    count: int,
    start_id: int,
    base_time: datetime,
) -> list[Alert]:
    alerts: list[Alert] = []
    for i in range(count):
        template = rng.choice(NOISE_TEMPLATES)
        ts = base_time + timedelta(seconds=rng.randint(0, 600))
        alert = generate_alert_from_template(
            template,
            rng,
            alert_id=f"ALERT-{start_id + i:04d}",
            timestamp=ts.isoformat(),
        )
        alert.is_noise = True
        alert.root_cause_id = alert.alert_id
        alerts.append(alert)
    return alerts


def generate_task_alerts(task_id: str, seed: int, config: dict | None = None) -> list[Alert]:
    """Generate all alerts for a given task using a fixed seed."""
    rng = random.Random(seed)
    base_time = datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
    all_alerts: list[Alert] = []
    next_id = 1

    if config is None:
        config = {}

    if task_id == "task_1":
        count = config.get("alert_count", rng.randint(3, 5))
        all_alerts = generate_independent_alerts(rng, count, next_id, base_time)

    elif task_id == "task_2":
        chain_count = config.get("chain_count", rng.randint(2, 3))
        chain_length = config.get("chain_length", rng.randint(3, 4))
        independent_count = config.get("alert_count", rng.randint(2, 4))

        for _ in range(chain_count):
            chain = generate_cascading_chain(rng, chain_length, next_id, base_time)
            all_alerts.extend(chain)
            next_id += len(chain)
            base_time = base_time + timedelta(minutes=rng.randint(5, 15))

        all_alerts.extend(
            generate_independent_alerts(rng, independent_count, next_id, base_time)
        )

    elif task_id == "task_3":
        chain_count = config.get("chain_count", rng.randint(3, 4))
        chain_length = config.get("chain_length", rng.randint(3, 5))
        red_herring_count = config.get("red_herring_count", rng.randint(3, 5))
        independent_count = config.get("alert_count", rng.randint(3, 5))

        chain_alerts: list[Alert] = []
        for _ in range(chain_count):
            chain = generate_cascading_chain(rng, chain_length, next_id, base_time)
            chain_alerts.extend(chain)
            all_alerts.extend(chain)
            next_id += len(chain)
            base_time = base_time + timedelta(minutes=rng.randint(5, 15))

        herrings = generate_red_herrings(
            rng, red_herring_count, chain_alerts, next_id, base_time
        )
        all_alerts.extend(herrings)
        next_id += len(herrings)

        all_alerts.extend(
            generate_independent_alerts(rng, independent_count, next_id, base_time)
        )

    elif task_id == "task_4":
        rng4 = random.Random(512)
        base_time4 = datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
        next_id4 = 1

        chain_count = config.get("chain_count", rng4.randint(5, 6))
        chain_length = config.get("chain_length", rng4.randint(4, 6))
        noise_count = config.get("noise_count", rng4.randint(4, 6))
        independent_count = config.get("alert_count", rng4.randint(3, 5))
        red_herring_count = config.get("red_herring_count", rng4.randint(3, 5))

        chain_alerts4: list[Alert] = []
        for _ in range(chain_count):
            chain = generate_cascading_chain(rng4, chain_length, next_id4, base_time4)
            chain_alerts4.extend(chain)
            all_alerts.extend(chain)
            next_id4 += len(chain)
            base_time4 = base_time4 + timedelta(minutes=rng4.randint(5, 15))

        herrings = generate_red_herrings(
            rng4, red_herring_count, chain_alerts4, next_id4, base_time4
        )
        all_alerts.extend(herrings)
        next_id4 += len(herrings)

        noise = generate_noise_alerts(rng4, noise_count, next_id4, base_time4)
        all_alerts.extend(noise)
        next_id4 += len(noise)

        all_alerts.extend(
            generate_independent_alerts(rng4, independent_count, next_id4, base_time4)
        )

        rng4.shuffle(all_alerts)
        return all_alerts

    else:
        raise ValueError(f"Unknown task_id: {task_id}")

    rng.shuffle(all_alerts)
    return all_alerts

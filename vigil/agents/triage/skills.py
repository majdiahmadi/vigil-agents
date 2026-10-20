from vigil.core.skills import Skill


def load_skills() -> list[Skill]:
    return [
        Skill("ssh-sequence-analysis", "Separate authentication observations from authorization conclusions", ("Collect failures and successes in a bounded window", "Correlate exact users, hosts, IPs, times, and event IDs", "Mark authorization and causation unknown unless directly evidenced")),
        Skill("evidence-gap-triage", "Report incomplete telemetry honestly", ("Record searched scope", "Treat missing or failed searches as gaps", "Recommend a human-verifiable next search")),
    ]


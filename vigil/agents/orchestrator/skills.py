from vigil.core.skills import Skill


def load_skills() -> list[Skill]:
    return [
        Skill("selective-routing", "Choose only relevant specialists", ("Classify the submitted alert", "Delegate with the same case and bounded scope", "Do not run irrelevant specialists by default")),
        Skill("grounded-case-synthesis", "Preserve provenance and uncertainty", ("Merge only typed specialist facts", "Keep hypotheses separate from observations", "Mark gaps, conflicts, analyst review, and no remediation")),
    ]


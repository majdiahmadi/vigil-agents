from vigil.core.skills import Skill


def load_skills() -> list[Skill]:
    return [
        Skill("hypothesis-led-hunt", "Test an explicit bounded hypothesis", ("Declare observable, assets, data source, and window", "Collect supporting and contradictory events", "Classify supported, unsupported, or inconclusive")),
        Skill("alternate-explanation-check", "Avoid overclaiming correlated activity", ("Group events by observable and host", "Record plausible administrative or shared-service explanations", "Recommend a discriminating follow-up search")),
    ]


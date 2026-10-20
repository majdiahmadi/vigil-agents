from vigil.core.database import VigilStore


class CaseMemory:
    def __init__(self, store: VigilStore) -> None:
        self.store = store

    def load(self, case_id: str, agent_id: str):
        return self.store.load_memory(case_id, agent_id)

    def remember(self, case_id: str, agent_id: str, kind: str, content: dict):
        self.store.append_memory(case_id, agent_id, kind, content)


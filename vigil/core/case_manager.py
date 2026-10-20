from vigil.core.database import VigilStore
from vigil.core.models import AlertEnvelope


class CaseManager:
    def __init__(self, store: VigilStore) -> None:
        self.store = store

    def create(self, alert: AlertEnvelope, reuse_alert: bool = False) -> str:
        return self.store.create_case(alert, reuse_alert=reuse_alert)

    def get(self, case_id: str):
        return self.store.get_case(case_id)

    def list(self, limit: int = 50):
        return self.store.list_cases(limit)


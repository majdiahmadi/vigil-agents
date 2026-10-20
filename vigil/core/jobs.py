from vigil.core.database import VigilStore


class JobQueue:
    def __init__(self, store: VigilStore) -> None:
        self.store = store

    def enqueue(self, case_id: str, payload: dict, idempotency_key: str | None = None):
        return self.store.enqueue_job(case_id, payload, idempotency_key)

    def claim(self):
        return self.store.claim_job()

    def finish(self, job_id: str, status: str, error: str | None = None):
        self.store.update_job(job_id, status, error)


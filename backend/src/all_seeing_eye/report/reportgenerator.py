import json
from all_seeing_eye.database import repository
from ollama import Client
from collections import Counter

MODEL = "llama3.1:8b"
OLLAMA_HOST = "http://10.40.1.205:11434"

class ReportGenerator:
    def __init__(self):
        self.client = Client(
            host=OLLAMA_HOST,
            timeout=600.0,
        )
        self.model = MODEL

    def generate(self, job_id: int) -> int:
        job = repository.get_job(job_id)
        if repository.get_report(job_id) is not None:
            raise ValueError(f"Job {job_id} hab schon einen Bericht")
        data = self.load_data(job_id)
        statistic = self.calculate_statistic(data)

        summary = self.generate_summary(data, statistic)
        content = self.build_content(data, statistic, summary)
        report_id = self.save(job_id, content)
        return report_id

    def load_data(self, job_id: int) -> dict:
        job = repository.get_job(job_id)
        collections = repository.get_collections_of_job(job_id)
        anayses = repository.get
# Collections und Analysen laden
# Findings laden
# Ein Dictionary mit allen Berichtsdaten zurückgeben

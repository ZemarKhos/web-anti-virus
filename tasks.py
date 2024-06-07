from celery import Celery
from scan import scan_file

app = Celery('tasks', broker='redis://localhost:6379/0')

@app.task
def scan_file_task(filepath):
    return scan_file(filepath)

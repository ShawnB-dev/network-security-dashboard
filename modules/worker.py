from celery import Celery

# Configure Celery to use Redis as the broker
celery_app = Celery(
    'security_tasks',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0'
)

@celery_app.task
def process_heavy_logs(log_data):
    # logic for intensive log analysis
    return "Analysis Complete"
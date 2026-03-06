"""Celery application factory and configuration."""

from celery import Celery

# Use Redis if available, otherwise fall back to an in-memory broker (for testing)
BROKER_URL = "redis://localhost:6379/0"
RESULT_BACKEND = "redis://localhost:6379/0"

celery_app = Celery(
    "securescan",
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
    include=["app.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=86400,  # 24 h
)

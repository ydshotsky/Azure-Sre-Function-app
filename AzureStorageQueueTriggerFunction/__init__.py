import logging
import json
import azure.functions as func
from .fingerprint_generator import generate_error_fingerprint
from .log_filter import sanitize_logs
from .ai_execution_service import execute_intelligent_triage
from datetime import datetime
from pydantic import BaseModel, Field




queue_trigger_bp = func.Blueprint()
test_bp = func.Blueprint()



@test_bp.function_name(name="test_queue")
@test_bp.queue_trigger(
    arg_name="msg",
    queue_name="testqueue",
    connection="AzureWebJobsStorage"
)
def test_queue(msg: func.QueueMessage):
    logging.warning("TEST QUEUE FIRED")

# Setup Logging
logger = logging.getLogger("SRE-AI-Engine.Queue")
# Grab Environment Configuration


class GrafanaAlertPayload(BaseModel):
    service: str = Field(default="unknown")
    status: str = Field("...", examples=["firing"])
    title: str = Field(..., examples=["HTTP 5xx Error Spike Detected"])
    message: str = Field(..., examples=["SecureVault instance replica-a throwing NullPointerException at core login filter."])
    logs: str = Field(default="No additional traceback available.", examples=["Caused by: java.lang.NullPointerException at SecurityFilter.java:42"])

def ai_payload_logs_validation(logs: str) -> bool:
    if not logs or logs.strip() == "":
        return False
    return True

    
@queue_trigger_bp.function_name(name="process_triage_queue")
@queue_trigger_bp.queue_trigger(arg_name="azqueue", queue_name="grafana-alerts", connection="AzureWebJobsStorage")
def process_triage_queue(azqueue: func.QueueMessage):
    logger.info("Background queue worker activated by incoming telemetry item.")
    
    # 1. Extract the string payload back out of the queue message object
    
    raw_body = azqueue.get_body().decode('utf-8')
    logger.error(f"RAW BODY = {repr(raw_body)}")
    
    try:
        payload_dict = json.loads(raw_body)
        logger.error(f"PAYLOAD DICT = {payload_dict}")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON: {str(e)}")
        return

    try:
        alert = payload_dict["alerts"][0]

        ai_payload = {
            "service": alert["labels"].get("service_name", "unknown"),
            "status": alert.get("status", "unknown"),
            "title": alert["annotations"].get("title", "No Title"),
            "message": alert["annotations"].get("message", "No Message"),
            "logs": alert["annotations"].get("logs", "No additional traceback available.")
        }
        if not ai_payload_logs_validation(ai_payload["logs"]):
            logger.error("No logs in payload. Aborting processing.")
            return
        
        payload = GrafanaAlertPayload(**ai_payload)
        logger.error("PYDANTIC VALIDATION PASSED")
    except Exception as e:
        logger.error(f"PYDANTIC VALIDATION FAILED: {str(e)}")
        return   

    try:
        execute_intelligent_triage(ai_payload)
        logger.error("AI EXECUTION PASSED")
    except Exception as e:
        logger.exception("AI EXECUTION FAILED")
        return
    
    logger.info("GitHub issue creation pipeline completed successfully.")

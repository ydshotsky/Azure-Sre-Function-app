import logging
import json
from urllib import response 
import azure.functions as func
import os
import google.generativeai as genai
import redis
import requests
import re
import hashlib
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

redis_url = os.getenv("REDIS_URL")
if redis_url:
    cache = redis.from_url(redis_url, decode_responses=True)
else:
    cache = redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", 6379)),
        decode_responses=True
    )

class GrafanaAlertPayload(BaseModel):
    status: str = Field("...", examples=["firing"])
    title: str = Field(..., examples=["HTTP 5xx Error Spike Detected"])
    message: str = Field(..., examples=["SecureVault instance replica-a throwing NullPointerException at core login filter."])
    logs: str = Field(default="No additional traceback available.", examples=["Caused by: java.lang.NullPointerException at SecurityFilter.java:42"])



def generate_error_fingerprint(title: str, logs: str) -> str:
    """
    Scrubs dynamic runtime noise (timestamps, memory addresses) from 
    the raw error logs to generate a deterministic system signature.
    """
    # Regex out standard timestamps (e.g., 2026-05-25 13:58:21)
    scrubbed_logs = re.sub(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}', '[TIMESTAMP]', logs)
    # Regex out hex memory pointer reference hashes (e.g., 0x7f98ab32)
    scrubbed_logs = re.sub(r'0x[0-9a-fA-F]+', '[MEM_ADDR]', scrubbed_logs)
    
    # Hash the normalized string signature
    raw_signature = f"{title}|||{scrubbed_logs}"
    return hashlib.sha256(raw_signature.encode('utf-8')).hexdigest()

def execute_intelligent_triage(alert: GrafanaAlertPayload):
    # 1. Compute the structural signature fingerprint
    AI_API_KEY = os.getenv("AI_API_KEY", os.getenv("AI_API_KEY"))
    AI_MODEL_NAME = os.getenv("AI_MODEL_NAME", "gemma-4-26b")
    QUEUE_SERVICE_URI = os.getenv("AzureWebJobsStorage__queueServiceUri")
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    GITHUB_REPO = os.getenv("GITHUB_REPO")

    error_hash = generate_error_fingerprint(alert.title, alert.logs)
    cache_key = f"incident:active:{error_hash}"
    existing_issue_id = cache.get(cache_key)
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    logger.warning(f"Generated error fingerprint: {error_hash} for alert titled '{alert.title}'")
    if existing_issue_id:
        try:
            comment_cache_key = f"incident:comment:{error_hash}"
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            existing_comment_meta = cache.get(comment_cache_key)
            logger.warning(f"Existing active issue #{existing_issue_id} found for this fingerprint. Updating deduplication metrics.")
            
            if not existing_comment_meta:
                # First time seeing a duplicate! Create the single tracking comment.
                comment_url = f"https://api.github.com/repos/{GITHUB_REPO}/issues/{existing_issue_id}/comments"
                body_data = {
                    "body": f"🔄 **Deduplication Metrics**\n- **Total Occurrences:** `2`\n- **Last Detected Active:** `{current_time}`"
                }
                
                res = requests.post(comment_url, json=body_data, headers=headers)
                if res.status_code == 201:
                    comment_id = res.json().get("id")
                    # Save comment metadata: ID and set initial counter to 2
                    meta_payload = {"comment_id": comment_id, "count": 2}
                    cache.setex(comment_cache_key, 600, json.dumps(meta_payload))
                    logger.info("Initialized unified deduplication comment thread.")
                else:
                    logger.error(f"Failed to create deduplication comment: {res}")
            else:
                # Subsequent duplicates! Parse metadata, increment counter, and EDIT the comment.
                meta = json.loads(existing_comment_meta)
                target_comment_id = meta["comment_id"]
                new_count = meta["count"] + 1
            
                # Update GitHub in-place via PATCH request
                edit_url = f"https://api.github.com/repos/{GITHUB_REPO}/issues/comments/{target_comment_id}"
                updated_body = {
                    "body": f"🔄 **Deduplication Metrics**\n- **Total Occurrences:** `{new_count}`\n- **Last Detected Active:** `{current_time}`"
                
                }
            
                response = requests.patch(edit_url, json=updated_body, headers=headers)
                if(response.status_code == 200):
                    logger.info(f"Successfully updated deduplication comment for issue #{existing_issue_id} with new count {new_count}.")
                else:                    logger.error(f"Failed to update deduplication comment: {response}")
                # requests.patch(edit_url, json=updated_body, headers=headers)

            
                # Update local cache values with incremented metrics
                meta["count"] = new_count
                cache.setex(comment_cache_key, 600, json.dumps(meta))
                logger.info(f"In-place incremented duplicate metrics for comment #{target_comment_id}")
        except Exception as e:
            logger.error(f"Failed to update deduplication metrics: {str(e)}")
            
        return

    system_instruction = "You are an Elite Principal SRE." \
                        " Generate an Incident Triage Docket with Breakdown, Root Cause, and Runbook steps."\
                        " Strictly adhere to the provided alert details and logs. Do not hallucinate or fabricate information."\
                        " Your response should be in markdown format, suitable for direct posting to GitHub Issues."\
                        " Focus on technical precision and actionable insights for the engineering team."



    user_prompt = f"Title: {alert.title}\nMessage: {alert.message}\nLogs:\n{alert.logs}"
    
    try:
        
        genai.configure(api_key=AI_API_KEY) # type: ignore
        model = genai.GenerativeModel(model_name=AI_MODEL_NAME if AI_MODEL_NAME else 'gemma-4-26b')
        prompt = f"{system_instruction}\n\n{user_prompt}"
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(temperature=0.1)
        )
        ai_diagnostic_markdown = response.text
        logger.warning(f"ai diagnostic markdown = {ai_diagnostic_markdown}")
        
        # Build payload and ship to GitHub Issues API
        url = f"https://api.github.com/repos/{GITHUB_REPO}/issues"
        issue_data = {
            "title": f"🚨 [INCIDENT] {alert.title}",
            "body": f"### Fingerprint: `{error_hash}`\n\n{ai_diagnostic_markdown}",
            "labels": ["bug", "automated-triage"]
        }
        
        response = requests.post(url, json=issue_data, headers=headers)
        
        if response.status_code == 201:
            new_issue_id = response.json().get("number")
            # Cache the GitHub Issue ID with a 10-minute (600 seconds) cooling window
            cache.setex(cache_key, 600, str(new_issue_id))
            logger.info(f"New tracking issue #{new_issue_id} established and cached successfully.")
        else:
            logger.error(f"GitHub Status Code: {response.status_code}")
            logger.error(f"GitHub Response Body: {response.text}")
            logger.error(f"GitHub Response Headers: {response.headers}")
            logger.error(f"GITHUB_REPO={GITHUB_REPO}")
            logger.error(f"Token present={bool(GITHUB_TOKEN)}")
            logger.error(f"Token length={len(GITHUB_TOKEN) if GITHUB_TOKEN else 0}")
    except Exception as e:
        logger.error(f"SRE execution workflow failed: {str(e)}")


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
        payload = GrafanaAlertPayload(**payload_dict)
        logger.error("PYDANTIC VALIDATION PASSED")
    except Exception as e:
        logger.error(f"PYDANTIC VALIDATION FAILED: {str(e)}")
        return   

    try:
        execute_intelligent_triage(payload)
        logger.error("AI EXECUTION PASSED")
    except Exception as e:
        logger.exception("AI EXECUTION FAILED")
        return
    
    logger.info("GitHub issue creation pipeline completed successfully.")

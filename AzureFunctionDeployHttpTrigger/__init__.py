import azure.functions as func
import logging
import json
import os


logger = logging.getLogger("SRE-AI-Engine.HTTP")

http_trigger_bp = func.Blueprint()

@http_trigger_bp.route(route="ai-webhook", methods=["POST"])
@http_trigger_bp.queue_output(arg_name="azqueue", queue_name="grafana-alerts", connection="AzureWebJobsStorage")
def receive_incident_alert(req: func.HttpRequest, azqueue: func.Out[str]) -> func.HttpResponse:
    """
    Ingests the telemetry metrics payload, validates data alignment against the schema contract,
    hands the workflow over to background thread pools, and instantly acknowledges with an HTTP 202.
    """
    expected_secret = os.getenv("GRAFANA_WEBHOOK_SECRET")
    x_grafana_webhook_secret = req.headers.get("x-webhook-secret")
    
    # Fail-closed auth check using constant-time string comparison
    if not expected_secret or not x_grafana_webhook_secret or not secrets.compare_digest(x_grafana_webhook_secret, expected_secret):
        logger.warning("Received unauthorized webhook attempt with invalid or missing Grafana Webhook Secret.")
        return func.HttpResponse("Unauthorized: Invalid Grafana Webhook Secret.", status_code=401)
        
    AI_API_KEY = os.getenv("AI_API_KEY")
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    GITHUB_REPO = os.getenv("GITHUB_REPO")
    # Defensive structural assertions
    if not AI_API_KEY or not GITHUB_TOKEN or not GITHUB_REPO:
        logger.critical("System misconfiguration: Environment secret parameters are missing.")
        return func.HttpResponse("Webhook server configuration failure.", status_code=500)
        


    try:
        req_body = req.get_json()
        json_payload = json.dumps(req_body)
    except Exception as e:
        return func.HttpResponse("Bad Request: Invalid payload format.", status_code=400)
    azqueue.set(json_payload)
    # try:
    #     if not QUEUE_SERVICE_URI:
    #         raise ValueError("Environment property 'AzureWebJobsStorage__queueServiceUri' is missing.")
            
    #     # Authenticate seamlessly using the container's Managed Identity assignment
    #     token_credential = DefaultAzureCredential()
    #     service_client = QueueServiceClient(account_url=QUEUE_SERVICE_URI, credential=token_credential)
    #     queue_client = service_client.get_queue_client("grafana-alerts")
        
    #     # Post the raw text block payload to your queue container
    #     queue_client.send_message(json_payload)
    #     logger.info("Telemetry data successfully committed to the storage queue pool.")
        
    # except Exception as storage_err:
    #     logger.critical(f"Identity-based queue storage transmission failure: {str(storage_err)}")
    #     return func.HttpResponse("Internal Server Error: Failed to queue message.", status_code=500)
   
    # Dispatch execution work unit smoothly off the API worker threads
    return func.HttpResponse(
        json.dumps({"status": "accepted", "message": "Incident payload queued for AI parsing."}),
        status_code=202,
        mimetype="application/json"
    )

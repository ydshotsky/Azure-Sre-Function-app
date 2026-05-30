import logging
import azure.functions as func
from AzureFunctionDeployHttpTrigger.__init__ import http_trigger_bp
from AzureStorageQueueTriggerFunction.__init__ import queue_trigger_bp
from AzureStorageQueueTriggerFunction.__init__ import test_bp

# Global Host Engine Logging Adjustments
logging.basicConfig(level=logging.INFO)

# Instantiating the Central App Controller
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# Clean, Explicit Subfolder Blueprint Registrations
app.register_blueprint(http_trigger_bp)
app.register_blueprint(queue_trigger_bp)
app.register_blueprint(test_bp)


@app.route(route="test")
def test(req: func.HttpRequest):
    return func.HttpResponse("OK")

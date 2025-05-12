from boto3 import client
import json
from datetime import datetime

# Initialize AWS clients
s3 = client("s3")
detective = client("detective")

# Configuration
BUCKET_NAME = "step-functions-version"

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def process_findings(graph_arn, investigation_result, finding, investigation_id):
    #Get indicators for a completed investigation
    indicators_response = detective.list_indicators(
        GraphArn=graph_arn,
        InvestigationId=investigation_id
    )
    investigation_result["Indicators"] = indicators_response.get("Indicators", [])

    # Combine Security Hub finding and Detective investigation data
    combined_result = {
        'SecurityHubFinding': finding,
        'DetectiveData': investigation_result
    }
    
    json_content = json.dumps(combined_result, cls=DateTimeEncoder)
    
    # Generate a unique key using timestamp and finding ID
    timestamp = datetime.now().strftime('%Y-%m-%dT%H-%M-%S-%fZ')
    folder_timestamp = datetime.now().strftime('%Y-%m-%d')
    key = f"{folder_timestamp}/securityhub_event_{timestamp}.json"
    
    # Upload to S3
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=key,
        Body=json_content,
        ContentType='application/json'
    )

def lambda_handler(event, context):
    # Main handler to check investigation status and process results
    graph_arn = event["GraphArn"]
    investigation_id = event["InvestigationId"]
    finding = event["Finding"]

    # Check the status of the investigation
    investigation_result = detective.get_investigation(
        GraphArn=graph_arn,
        InvestigationId=investigation_id
    )

    if investigation_result.get("Status") == "SUCCESSFUL":
        process_findings(graph_arn, investigation_result, finding, investigation_id)
        return {"status": "complete"}

    elif investigation_result.get("Status") == "FAILED":
        raise Exception("Investigation failed!")

    else:
        return {"status": "running"}

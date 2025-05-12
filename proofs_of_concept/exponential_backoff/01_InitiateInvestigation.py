from boto3 import client
import json
from datetime import datetime, timedelta

# Initialize AWS service clients
s3 = client("s3")
detective = client("detective")
stepfunctions = client("stepfunctions")

#Configuration
stepfunction_arn = "arn:aws:states:region:account-id:stateMachine:s1_MainStepFunction"
BUCKET_NAME = "step-functions-version"
wait_time = 60

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def get_iam_arn(resource, resource_type, finding):
    # Extract the ARN for an IAM access key, handling root user cases.
    details = resource.get("Details", {})
    iam_access = details.get(resource_type, {})
    principal_name = iam_access.get("PrincipalName")
    principal_type = iam_access.get("PrincipalType")
    account_id = finding.get("AwsAccountId")
    
    if principal_type == "Root":
        return f"arn:aws:iam::{account_id}:root"
    elif principal_type == "IAMUser":
        return f"arn:aws:iam::{account_id}:user/{principal_name}"
    else:
        return f"arn:aws:iam::{account_id}:role/{principal_name}"
    
def investigate_resource(graph_arn, iam_resource, created_at):
    # Start and monitor a Detective investigation for an IAM resource
    finding_time = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%fZ")
    scope_start = (finding_time - timedelta(days=1)).isoformat() + "Z"
    scope_end = (finding_time + timedelta(days=1)).isoformat() + "Z"

    try:
        # Start an investigation in Detective
        inv_response = detective.start_investigation(
            GraphArn=graph_arn,
            EntityArn=iam_resource,
            ScopeStartTime=scope_start,
            ScopeEndTime=scope_end,
        )

        investigation_id = inv_response.get("InvestigationId")
        if not investigation_id:
            raise Exception("Failed to start investigation!")

        return investigation_id

    except Exception as e:
        return {"error": str(e)}

def process_findings(findings, graph_arn):
    for finding in findings:
        # Identify a relevant resource from the finding
        iam_resource = None
        resources = finding.get('Resources', [])
        for resource in resources:
            resource_type = resource.get('Type')
            if resource_type in ["AwsIamAccessKey", "AwsIamRole", "AwsIamUser"]:
                iam_resource = get_iam_arn(resource, resource_type, finding)
                break
        
        if iam_resource:
            # Start an investigation for this finding's IAM resource
            investigation_id = investigate_resource(
                graph_arn, iam_resource, finding["CreatedAt"]
            )

            # Prepare input for the Step Function
            step_function_input = {
                "GraphArn": graph_arn,
                "InvestigationId": investigation_id,
                "Finding": finding,
                "waitTime": wait_time,
            }

            # Trigger a Step Function execution for this investigation
            stepfunctions.start_execution(
                stateMachineArn=stepfunction_arn, input=json.dumps(step_function_input)
            )

        else:
            # Combine Security Hub finding and Detective investigation data
            combined_result = {
                'SecurityHubFinding': finding,
                'DetectiveData': {'message': "No IAM resource found in the Security Hub finding."}
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
    # Get the findings list, defaulting to an empty list if not present
    findings = event["detail"].get("findings", [])
    
    if not findings:
        raise ValueError("No findings in the event")
    
    # Check if there are any Detective behavior graphs
    graphs_response = detective.list_graphs()
    if not graphs_response.get('GraphList'):
        raise ValueError("No Detective behavior graphs found")
    graph_arn = graphs_response['GraphList'][0]['Arn']
    
    # Process the findings
    process_findings(findings, graph_arn)

    return {
        "statusCode": 200,
        "body": "Investigations started and Step Functions triggered for all findings",
    }

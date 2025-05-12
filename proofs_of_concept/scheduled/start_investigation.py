from boto3 import client
from datetime import datetime, timedelta
import json
import logging
import os
import uuid

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = client("s3")
detective = client("detective")


def get_iam_arn(resource, resource_type, finding):
    """Construct IAM ARN from resource details."""
    try:
        details = resource.get("Details", {})
        iam_access = details.get(resource_type, {})
        principal_name = iam_access.get("PrincipalName") or iam_access.get(
            "PrincipalId"
        )
        principal_type = iam_access.get("PrincipalType")
        account_id = finding.get("AwsAccountId")

        if principal_type == "Root":
            return f"arn:aws:iam::{account_id}:root"
        elif principal_type == "IAMUser":
            return f"arn:aws:iam::{account_id}:user/{principal_name}"
        else:
            return f"arn:aws:iam::{account_id}:role/{principal_name}"
    except Exception as e:
        logger.error(f"Error constructing IAM ARN: {e}")
        return None


def process_finding(security_hub_finding, bucket, ongoing_prefix, invalid_prefix):
    """Extract IAM resources from a finding and start investigations or flag as invalid."""
    try:
        iam_resource = None
        resources = security_hub_finding.get("Resources", [])

        for resource in resources:
            resource_type = resource.get("Type")
            if resource_type in ["AwsIamAccessKey", "AwsIamRole", "AwsIamUser"]:
                iam_resource = get_iam_arn(
                    resource, resource_type, security_hub_finding
                )
                if iam_resource:
                    investigate_resource(
                        iam_resource, security_hub_finding, bucket, ongoing_prefix
                    )
                    break

        # If no IAM resource was found, save to invalid-investigations folder
        if not iam_resource:
            hash = uuid.uuid4().hex.upper()[0:6]
            timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S.%fZ")
            object_key = f"security_hub_finding_{timestamp}_hash_{hash}.json"
            folder_timestamp = datetime.now().strftime("%Y-%m-%d")
            finding_id = security_hub_finding.get("Id", "unknown-finding")

            # Create content with original finding and message
            combined_result = {
                "SecurityHubFinding": security_hub_finding,
                "DetectiveData": "No IAM resource found in the Security Hub finding.",
            }

            json_content = json.dumps(combined_result)

            # Store in S3 with invalid prefix
            s3.put_object(
                Bucket=bucket,
                Key=f"{invalid_prefix}{folder_timestamp}-Test3/{object_key}",
                Body=json_content,
                ContentType="application/json",
            )
            logger.info(
                f"Saved invalid finding {finding_id} (hash {hash}) to {invalid_prefix} (no IAM resource)"
            )

    except Exception as e:
        logger.error(f"Error processing finding: {e}")


def investigate_resource(iam_resource, security_hub_finding, bucket, ongoing_prefix):
    """Start a Detective investigation for an IAM resource."""
    try:
        # Get Detective graph ARN
        graphs_response = detective.list_graphs()
        graph_list = graphs_response.get("GraphList", [])
        if not graph_list:
            logger.error("No Detective behavior graphs found")
            return

        graph_arn = graph_list[0]["Arn"]

        # Extract finding time and create scope
        finding_time = datetime.strptime(
            security_hub_finding.get("CreatedAt", datetime.now().isoformat()),
            "%Y-%m-%dT%H:%M:%S.%fZ",
        )
        scope_start = (finding_time - timedelta(days=1)).isoformat() + "Z"
        scope_end = (finding_time + timedelta(days=1)).isoformat() + "Z"

        # Start investigation
        inv_response = detective.start_investigation(
            GraphArn=graph_arn,
            EntityArn=iam_resource,
            ScopeStartTime=scope_start,
            ScopeEndTime=scope_end,
        )

        # Store investigation details in S3
        investigation_id = inv_response.get("InvestigationId")
        if not investigation_id:
            logger.error("Failed to get investigation ID")
            return

        # Create object key and content
        timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S.%fZ")
        object_key = (
            f"security_hub_finding_{timestamp}_investigation_{investigation_id}.json"
        )
        finding_id = security_hub_finding.get("Id", "unknown-finding")

        json_content = json.dumps(
            {
                "security_hub_finding": security_hub_finding,
                "investigation_id": investigation_id,
            }
        )

        # Store in S3
        s3.put_object(
            Bucket=bucket,
            Key=f"{ongoing_prefix}{object_key}",
            Body=json_content,
            ContentType="application/json",
        )
        logger.info(
            f"Started investigation {investigation_id} for finding {finding_id}"
        )

    except Exception as e:
        logger.error(f"Error during investigation: {e}")


def lambda_handler(event, context):
    """AWS Lambda entry point."""
    logger.info(f"EventBridge timestamp {event['time']}")
    try:
        # Extract environment variables once
        bucket = os.environ.get("BUCKET_NAME")
        ongoing_prefix = os.environ.get("ONGOING_PREFIX")
        invalid_prefix = os.environ.get("INVALID_PREFIX")

        # Handle either direct finding or event from Security Hub
        if event.get("detail", {}).get("findings"):
            findings = event["detail"]["findings"]
            if not isinstance(findings, list):
                findings = [findings]

            for finding in findings:
                process_finding(finding, bucket, ongoing_prefix, invalid_prefix)
        else:
            # Direct finding or different format
            process_finding(event, bucket, ongoing_prefix, invalid_prefix)

        return {"statusCode": 200}
    except Exception as e:
        logger.error(f"Lambda handler error: {e}")
        return {"statusCode": 500, "error": str(e)}

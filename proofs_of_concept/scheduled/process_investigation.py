from boto3 import client
from datetime import datetime
import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = client("s3")
detective = client("detective")


def process_object(bucket, object_key, graph_arn, completed_prefix):
    """Process a single investigation object."""
    try:
        # Get object content and extract data
        response = s3.get_object(Bucket=bucket, Key=object_key)
        object_content = json.loads(response["Body"].read().decode("utf-8"))

        # Extract the investigation ID and the complete security finding
        investigation_id = object_content.get("investigation_id")
        security_hub_finding = object_content.get("security_hub_finding")

        # Log the finding ID for tracking
        finding_id = "unknown-finding"
        if security_hub_finding and isinstance(security_hub_finding, dict):
            finding_id = security_hub_finding.get("Id", "unknown-finding")

        if not investigation_id or not security_hub_finding:
            logger.warning(f"Missing data in object {object_key}")
            return {
                "status": "failed",
                "error": "Missing investigation_id or security_hub_finding",
                "object_key": object_key,
            }

        # Get investigation details from Detective API
        try:
            investigation_data = detective.get_investigation(
                GraphArn=graph_arn, InvestigationId=investigation_id
            )

            # Get indicators for the investigation
            indicators_response = detective.list_indicators(
                GraphArn=graph_arn, InvestigationId=investigation_id
            )

            # Merge the results
            investigation_data["Indicators"] = indicators_response.get("Indicators", [])

        except Exception as e:
            logger.error(f"Error fetching investigation {investigation_id}: {e}")
            investigation_data = {"error": str(e)}

        # Combine and save data
        timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S.%fZ")
        folder_timestamp = datetime.now().strftime("%Y-%m-%d")

        completed_key = f"{completed_prefix}{folder_timestamp}-Test3/security_hub_finding_{timestamp}_investigation_{investigation_id}.json"

        combined_result = {
            "SecurityHubFinding": security_hub_finding,
            "DetectiveData": investigation_data,
        }

        # Save to S3
        s3.put_object(
            Bucket=bucket,
            Key=completed_key,
            Body=json.dumps(
                combined_result,
                default=lambda o: o.isoformat() if isinstance(o, datetime) else None,
            ),
            ContentType="application/json",
        )

        # Archive investigation
        archived = False
        try:
            detective.update_investigation_state(
                GraphArn=graph_arn, InvestigationId=investigation_id, State="ARCHIVED"
            )
            archived = True
        except Exception as e:
            logger.error(f"Error archiving investigation {investigation_id}: {e}")

        # Delete the original object
        s3.delete_object(Bucket=bucket, Key=object_key)

        logger.info(
            f"Processed investigation {investigation_id} for finding {finding_id}"
        )

        return {
            "status": "completed",
            "investigation_id": investigation_id,
            "finding_id": finding_id,
            "completed_object": completed_key,
            "archived": archived,
        }
    except Exception as e:
        logger.error(f"Error processing {object_key}: {e}")
        return {"status": "failed", "error": str(e), "object_key": object_key}


def lambda_handler(event, context):
    """Main Lambda handler function."""
    try:
        # Extract environment variables
        completed_prefix = os.environ.get("COMPLETED_PREFIX")

        # Get Detective graph ARN directly
        graphs = detective.list_graphs().get("GraphList", [])
        if not graphs:
            raise ValueError("No Detective behavior graphs found")
        graph_arn = graphs[0]["Arn"]

        start_time = datetime.now()

        # Extract records to process
        records = [
            r for r in event.get("Records", []) if r.get("eventSource") == "aws:s3"
        ]
        if not records:
            logger.info("No S3 records to process")
            return {"processed_objects": 0}

        logger.info(f"Processing {len(records)} S3 records")
        results = []

        # Process all records
        for record in records:
            record_bucket = record["s3"]["bucket"]["name"]
            key = record["s3"]["object"]["key"]
            result = process_object(record_bucket, key, graph_arn, completed_prefix)
            results.append(result)

        # Summarize results
        completed_count = sum(1 for r in results if r.get("status") == "completed")
        failed_count = sum(1 for r in results if r.get("status") == "failed")
        execution_time = (datetime.now() - start_time).total_seconds()

        logger.info(
            f"Processing complete: {completed_count} completed, {failed_count} failed in {execution_time}s"
        )

        return {
            "statusCode": 200,
            "processed_objects": len(results),
            "completed_objects": completed_count,
            "failed_objects": failed_count,
            "execution_time_seconds": execution_time,
        }
    except Exception as e:
        logger.error(f"Lambda execution error: {e}")
        return {"statusCode": 500, "error": str(e)}

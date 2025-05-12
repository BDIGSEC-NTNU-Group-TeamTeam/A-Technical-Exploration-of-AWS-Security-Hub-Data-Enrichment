from boto3 import client
from datetime import datetime
import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = client("s3")
detective = client("detective")


def move_object(object_key, status, bucket, successful_prefix, failed_prefix):
    """Move object to appropriate directory based on status."""
    try:
        destination_prefix = (
            successful_prefix if status == "SUCCESSFUL" else failed_prefix
        )

        filename = object_key.split("/")[-1]
        destination_key = f"{destination_prefix}{filename}"

        # Copy and delete (move operation)
        s3.copy_object(
            Bucket=bucket, CopySource=f"{bucket}/{object_key}", Key=destination_key
        )
        s3.delete_object(Bucket=bucket, Key=object_key)

        logger.info(f"Moved S3 object: {object_key} -> {destination_key}")
        return status
    except Exception as e:
        logger.error(f"Error moving S3 object {object_key}: {e}")
        return None


def get_all_investigations(status, graph_arn):
    """Get all investigations with specified status."""
    investigations = []
    next_token = None

    while True:
        params = {
            "GraphArn": graph_arn,
            "FilterCriteria": {
                "Status": {"Value": status},
                "State": {"Value": "ACTIVE"},
            },
        }
        if next_token:
            params["NextToken"] = next_token

        response = detective.list_investigations(**params)
        investigations.extend(response.get("InvestigationDetails", []))

        next_token = response.get("NextToken")
        if not next_token:
            break

    logger.info(f"Found {len(investigations)} {status} investigations")
    return investigations


def lambda_handler(event, context):
    """AWS Lambda entry point for polling and updating investigation status."""
    start_time = datetime.now()

    # Extract environment variables once
    bucket = os.environ.get("BUCKET_NAME")
    ongoing_prefix = os.environ.get("ONGOING_PREFIX")
    successful_prefix = os.environ.get("SUCCESSFUL_PREFIX")
    failed_prefix = os.environ.get("FAILED_PREFIX")

    # Setup - Get Detective graph ARN
    graphs_response = detective.list_graphs()
    if not graphs_response.get("GraphList"):
        logger.error("No Detective behavior graphs found")
        return {"statusCode": 500, "error": "No Detective behavior graphs found"}
    graph_arn = graphs_response["GraphList"][0]["Arn"]

    # List all ongoing investigation objects in S3 with pagination
    try:
        all_objects = []
        paginator = s3.get_paginator("list_objects_v2")

        for page in paginator.paginate(Bucket=bucket, Prefix=ongoing_prefix):
            if "Contents" in page:
                filtered_objects = [
                    obj for obj in page["Contents"] if not obj["Key"].endswith("/")
                ]
                all_objects.extend(filtered_objects)

        logger.info(f"Found {len(all_objects)} ongoing investigations in S3")
    except Exception as e:
        logger.error(f"Error listing ongoing investigations: {e}")
        return {
            "statusCode": 500,
            "error": f"Failed to list ongoing investigations: {str(e)}",
        }

    # Early return if no ongoing investigations
    if not all_objects:
        logger.info("No ongoing investigations found. Exiting early.")
        return {
            "statusCode": 200,
            "message": "No ongoing investigations to process",
            "execution_time_seconds": (datetime.now() - start_time).total_seconds(),
        }

    # Get investigations by status
    successful_investigations = get_all_investigations("SUCCESSFUL", graph_arn)
    failed_investigations = get_all_investigations("FAILED", graph_arn)

    # Create a simplified map with just the status for O(1) lookups
    investigation_status_map = {}

    for inv in successful_investigations:
        inv_id = inv.get("InvestigationId")
        if inv_id:
            investigation_status_map[inv_id] = "SUCCESSFUL"

    for inv in failed_investigations:
        inv_id = inv.get("InvestigationId")
        if inv_id:
            investigation_status_map[inv_id] = "FAILED"

    successful_count = 0
    failed_count = 0

    # Process objects
    for obj in all_objects:
        object_key = obj["Key"]
        try:
            response = s3.get_object(Bucket=bucket, Key=object_key)
            object_content = json.loads(response["Body"].read().decode("utf-8"))
            investigation_id = object_content.get("investigation_id")

            if not investigation_id:
                logger.warning(f"No investigation_id found in object {object_key}")
                continue

            if investigation_id not in investigation_status_map:
                logger.info(
                    f"Investigation {investigation_id} not found in status map (not completed yet)"
                )
                continue

            status = investigation_status_map[investigation_id]
            logger.info(f"Moving investigation {investigation_id} with status {status}")

            result = move_object(
                object_key, status, bucket, successful_prefix, failed_prefix
            )

            if result == "SUCCESSFUL":
                successful_count += 1
            elif result == "FAILED":
                failed_count += 1

        except Exception as e:
            logger.error(f"Error processing object {object_key}: {e}")

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        "statusCode": 200,
        "successful_investigations_count": len(successful_investigations),
        "failed_investigations_count": len(failed_investigations),
        "moved_successful_objects": successful_count,
        "moved_failed_objects": failed_count,
        "execution_time_seconds": execution_time,
    }

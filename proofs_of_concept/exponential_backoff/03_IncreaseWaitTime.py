def lambda_handler(event, context):
    current_wait = event["waitTime"]
    new_wait = current_wait * 2  # Double the wait time
    return new_wait

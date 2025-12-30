# © 2023 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
# This AWS Content is provided subject to the terms of the AWS Customer Agreement available at
# http: // aws.amazon.com/agreement or other written agreement between Customer and either
# Amazon Web Services, Inc. or Amazon Web Services EMEA SARL or both.

"""
Lambda function to check if there are other active ("in progress") sessions
for the same user, account, and permission set combination.

This prevents premature revocation of access when overlapping sessions exist.
See: https://github.com/aws-samples/iam-identity-center-team/issues/279
"""

import boto3
from botocore.exceptions import ClientError


def lambda_handler(event: dict, context):
    """
    Check if there are other active sessions that would be affected by revoking access.

    Args:
        event: The event object from Step Functions containing:
            - requests_table: DynamoDB table name for requests
            - id: Current request ID (to exclude from search)
            - email: User's email address (unique identifier stored in DynamoDB)
            - accountId: AWS account ID
            - roleId: Permission set ARN

    Returns:
        dict: Contains hasOverlappingSessions boolean and count
    """
    print(f"EVENT: {event}")

    table_name = event.get("requests_table")
    current_request_id = event.get("id")
    # Use email as the user identifier since it's stored in DynamoDB
    # (userId is computed at runtime and not persisted)
    email = event.get("email")
    account_id = event.get("accountId")
    role_id = event.get("roleId")

    if not all([table_name, current_request_id, email, account_id, role_id]):
        print("Missing required parameters")
        return {
            "hasOverlappingSessions": False,
            "error": "Missing required parameters"
        }

    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(table_name)

        # Scan for other "in progress" requests with the same user/account/role
        # Note: Using Scan because we don't have a composite GSI for these fields.
        # The number of "in progress" requests should be small, making this acceptable.
        response = table.scan(
            FilterExpression=(
                "#status = :status_val AND "
                "email = :email_val AND "
                "accountId = :account_id_val AND "
                "roleId = :role_id_val AND "
                "id <> :current_id"
            ),
            ExpressionAttributeNames={
                "#status": "status"  # 'status' is a reserved word in DynamoDB
            },
            ExpressionAttributeValues={
                ":status_val": "in progress",
                ":email_val": email,
                ":account_id_val": account_id,
                ":role_id_val": role_id,
                ":current_id": current_request_id
            },
            ProjectionExpression="id"  # We only need to know if any exist
        )

        items = response.get("Items", [])
        overlapping_count = len(items)

        print(f"Found {overlapping_count} overlapping session(s) for user {email}, "
              f"account {account_id}, role {role_id}")

        if overlapping_count > 0:
            overlapping_ids = [item["id"] for item in items]
            print(f"Overlapping session IDs: {overlapping_ids}")

        return {
            "hasOverlappingSessions": overlapping_count > 0,
            "overlappingCount": overlapping_count
        }

    except ClientError as error:
        print(f"Error checking for overlapping sessions: {error}")
        # In case of error, we default to allowing revocation to avoid leaving
        # orphaned permissions. This is the safer default from a security perspective.
        return {
            "hasOverlappingSessions": False,
            "error": str(error)
        }


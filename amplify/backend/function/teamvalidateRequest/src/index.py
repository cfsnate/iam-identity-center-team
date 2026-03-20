import json
import os
import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
organizations = boto3.client("organizations")

eligibility_table = dynamodb.Table(os.environ["ELIGIBILITY_TABLE_NAME"])


def get_account_parent_ou(account_id):
    """Get the parent OU ID for an account from Organizations API"""
    try:
        response = organizations.list_parents(ChildId=account_id)
        parents = response.get("Parents", [])
        
        if not parents:
            print(f"No parent found for account {account_id}")
            return None
        
        parent = parents[0]
        parent_id = parent.get("Id")
        parent_type = parent.get("Type")
        
        # If parent is root, return None (root is not an OU)
        if parent_type == "ROOT":
            return None
            
        return parent_id
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == "AccountNotFoundException":
            print(f"Account {account_id} not found in Organizations")
            return None
        print(f"Error getting parent for account {account_id}: {e}")
        raise


def get_eligibility_entries(entity_id):
    """
    Get all eligibility entries for a single user or group ID.

    Supports both old format (id = entityId) and new format (entityId field
    queried via the byEntityId GSI). Deduplicates across both lookups.
    """
    entries = []
    seen_ids = set()

    # New format: query by entityId GSI
    try:
        response = eligibility_table.query(
            IndexName='byEntityId',
            KeyConditionExpression='entityId = :eid',
            ExpressionAttributeValues={':eid': entity_id}
        )
        for item in response.get('Items', []):
            item_id = item.get('id')
            if item_id not in seen_ids:
                seen_ids.add(item_id)
                entries.append(item)
    except ClientError as e:
        print(f"GSI query failed for {entity_id} (may not exist yet): {e.response['Error']['Message']}")

    # Old format: direct lookup where id = entityId
    try:
        response = eligibility_table.get_item(Key={"id": entity_id})
        if "Item" in response:
            item = response["Item"]
            if item.get("id") not in seen_ids:
                entries.append(item)
    except ClientError as e:
        print(f"Direct get_item failed for {entity_id}: {e.response['Error']['Message']}")

    return entries


def get_user_eligibility(user_id, group_ids):
    """Get all eligibility entries for user and their groups"""
    eligibility_entries = []

    for entity_id in [user_id] + group_ids:
        if not entity_id:
            continue
        entries = get_eligibility_entries(entity_id)
        eligibility_entries.extend(entries)

    return eligibility_entries


def validate_request(account_id, permission_set_id, user_id, group_ids):
    """
    Validate that the user is eligible to request access to the account/permission set.
    Returns (is_valid, reason)
    """
    # Get user's eligibility entries
    eligibility_entries = get_user_eligibility(user_id, group_ids)
    
    if not eligibility_entries:
        return False, "No eligibility entries found for user"
    
    # Check each eligibility entry
    for entry in eligibility_entries:
        # Check direct account grants
        accounts = entry.get("accounts", [])
        for account in accounts:
            if account.get("id") == account_id:
                # Check if permission set is allowed
                permissions = entry.get("permissions", [])
                for perm in permissions:
                    if perm.get("id") == permission_set_id:
                        return True, "Direct account grant"
        
        # Check OU-based grants
        ous = entry.get("ous", [])
        if ous:
            # Get account's parent OU from Organizations
            parent_ou = get_account_parent_ou(account_id)
            
            if parent_ou:
                for ou in ous:
                    if ou.get("id") == parent_ou:
                        # Check if permission set is allowed
                        permissions = entry.get("permissions", [])
                        for perm in permissions:
                            if perm.get("id") == permission_set_id:
                                return True, f"OU-based grant (OU: {parent_ou})"
    
    return False, "Account not in user's eligible accounts or OUs"


def handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    
    # Extract request details from GraphQL mutation arguments
    arguments = event.get("arguments", {})
    
    account_id = arguments.get("accountId")
    role_id = arguments.get("roleId")
    user_id = arguments.get("userId")
    group_ids = arguments.get("groupIds", [])
    
    if not account_id or not role_id:
        return {
            "valid": False,
            "reason": "Missing accountId or roleId"
        }
    
    if not user_id:
        return {
            "valid": False,
            "reason": "Missing userId"
        }
    
    # Validate the request
    is_valid, reason = validate_request(account_id, role_id, user_id, group_ids)
    
    print(f"Validation result for user {user_id}, account {account_id}, role {role_id}: {is_valid} - {reason}")
    
    return {
        "valid": is_valid,
        "reason": reason
    }

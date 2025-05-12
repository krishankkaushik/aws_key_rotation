#!/bin/bash

# Function to delete access keys for a user
delete_user_keys() {
    local username=$1
    echo "Deleting access keys for user: $username"
    
    # List all access keys for the user
    keys=$(aws iam list-access-keys --user-name "$username" --query 'AccessKeyMetadata[*].AccessKeyId' --output text)
    
    # Delete each access key
    for key in $keys; do
        echo "Deleting access key: $key"
        aws iam delete-access-key --user-name "$username" --access-key-id "$key"
    done
}

# Delete users and their access keys
for i in {1..10}; do
    username="test-user-$i"
    echo "Processing user: $username"
    
    # Delete access keys first
    delete_user_keys "$username"
    
    # Delete the user
    echo "Deleting user: $username"
    aws iam delete-user --user-name "$username"
done

echo "All users and their access keys have been deleted." 
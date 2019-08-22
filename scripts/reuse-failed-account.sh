#!/bin/bash

# Set profile
# AWS_PROFILE="us-east-1"
# AWS_DEFAULT_REGION

usage() {
    cat <<EOF
    usage: $0 [ OPTION ]
    Options
    -a         AWS Account ID (10 digit int)
    -p         AWS Profile, leave blank for none
EOF
}

if ( ! getopts ":a:p:h" opt); then
    echo ""
    echo "    $0 requries an argument!"
    usage
    exit 1 
fi

while getopts ":a:p:h" opt; do
    case $opt in
        a)
            AWS_ACCOUNT_ID_ARG="$OPTARG" >&2
            ;;
        p)
            AWS_PROFILE="$OPTARG" >&2
            ;;
        h)
            echo "Invalid option: -$OPTARG" >&2
            usage
            exit 1
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            usage
            exit 1
            ;;
        :)
            echo "$0 Requires an argument" >&2
            usage
            exit 1
            ;;
    esac
done

if [ -z "$AWS_ACCOUNT_ID_ARG" ]; then
    echo "Account ID required"
fi

# Assume role
if [ -z "$AWS_PROFILE" ]; then
    echo "AWS Account Profile required"
else
    export AWS_PROFILE
fi

AWS_STS_SESSION_NAME="SREResetFailedAccount"
AWS_PROFILE="orgtest"

SUPPORTED_REGIONS=(
  "us-east-1"
  "us-east-2"
  "us-west-1"
  "us-west-2"
  "ca-central-1"
  "eu-central-1"
  "eu-west-1"
  "eu-west-2"
  "eu-west-3"
  "ap-northeast-1"
  "ap-northeast-2"
  "ap-south-1"
  "ap-southeast-1"
  "ap-southeast-2"
  "sa-east-1"
)

# Get the account ID and check its part of the correct AWS payer account organization
AWS_ACCOUNT_ID=$(aws organizations list-accounts | jq -r --arg AWS_ACCOUNT_ID_ARG $AWS_ACCOUNT_ID_ARG '.Accounts[] | select(.Id==$AWS_ACCOUNT_ID_ARG) | .Id')
if [ -z "$AWS_ACCOUNT_ID" ]; then
    echo "Account ID is not part of organization"
else
    echo "Account ID $AWS_ACCOUNT_ID"
fi

# Get organization ID here and echo it next

# Assume role
AWS_ASSUME_ROLE=$(aws sts assume-role --role-arn arn:aws:iam::"${AWS_ACCOUNT_ID}":role/OrganizationAccountAccessRole --role-session-name ${AWS_STS_SESSION_NAME})

AWS_ACCESS_KEY_ID=$(echo "$AWS_ASSUME_ROLE" | jq -r '.Credentials.AccessKeyId')
AWS_SECRET_ACCESS_KEY=$(echo "$AWS_ASSUME_ROLE" | jq -r '.Credentials.SecretAccessKey')
AWS_SESSION_TOKEN=$(echo "$AWS_ASSUME_ROLE" | jq -r '.Credentials.SessionToken')

export AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY
export AWS_SESSION_TOKEN

# Echo out the account we are using
aws sts get-caller-identity

# Check account for any instances in all regions

for REGION in "${SUPPORTED_REGIONS[@]}"
do

  INSTANCE_LIST=( $(aws ec2 describe-instances --region="$REGION" | jq -r '.Reservations[].Instances[].InstanceId') )

  # Terminate any instances we find
  if [ "${#INSTANCE_LIST[@]}" > 0 ]; then
      echo "Found ${#INSTANCE_LIST[@]} instance(s) in region $REGION"
      for id in $"${INSTANCE_LIST[@]}"
      do
          echo "Terminating instance id $id"
          echo "aws ec2 terminate-instances --region=$REGION --instances-ids $id"
      done
  fi
done

# Check that there are no IAM users

for IAM_USER in $(aws iam list-users | jq -r '.Users[].UserName'); do
    echo "Cleaning up IAM user: $IAM_USER"
    exit 0
    aws iam delete-login-profile --user-name "$IAM_USER" 2> /dev/null
    if [ $? -eq 0 ]; then
        echo "Deleted login profile for user $IAM_USER"
    fi
    # Delete policy attached to IAM user
    aws iam detach-user-policy --user-name "$IAM_USER" --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
    
    # List access keys created for user
    ADMIN_ACCESS_KEY_IDS=$(aws iam list-access-keys --user-name "$IAM_USER" | jq -r '.AccessKeyMetadata[].AccessKeyId')
    
    # Delete access keys created for user
    for ID in ${ADMIN_ACCESS_KEY_IDS}; do
      echo "Deleting ACCESS KEY $ID"
      aws iam delete-access-key --user-name "$IAM_USER" --access-key-id "${ID}"
    done

    # Delete IAM user
    aws iam delete-user --user-name "$IAM_USER" 
done

# # Reset status
# 
# # List cluster context names `kubectl config view -o jsonpath='{"Cluster name\tServer\n"}{range .clusters[*]}{.name}{"\t"}{.cluster.server}{"\n"}{end}'`
# CLUSTER_NAME="192-168-99-100:8443"
# 
# APISERVER=$(kubectl config view -o jsonpath="{.clusters[?(@.name==\"$CLUSTER_NAME\")].cluster.server}")
# 
# # Service account for aws-account-operator in the aws-account-operator namespace
# # `oc get secrets -n aws-account-operator` look for aws-account-operator-token-<some id>
# AAO_SERVICE_ACCOUNT_NAME="aws-account-operator-token-s87z6"
# 
# TOKEN=$(oc get secret "${AAO_SERVICE_ACCOUNT_NAME}" -n aws-account-operator -o json | jq -r '.data.token' | base64 -d)
# 
# ACCOUNT_CR_NAME="osd-creds-mgmt-cfxdw2"
#  
# RETURN_CODE=$(curl -s -I -X GET $APISERVER/api --header "Authorization: Bearer $TOKEN" --insecure | grep -oE "HTTP\/2\ +[0-9]{3}")
# 
# if ! [ "$RETURN_CODE" = 'HTTP/2 200' ]; then
#     echo "Return code: $RETURN_CODE"
#     echo "Authentication failure?"
#     exit 1 
# fi
# 
# PATCH_DATA='[{"op": "add", "path": "/status/rotateCredentials", "value": false}, {"op": "add", "path": "/status/claimed", "value": false}, {"op": "add", "path": "/status/state", "value": ""}]'
# 
# curl --header "Content-Type: application/json-patch+json" \
# --request PATCH \
# --header "Authorization: Bearer $TOKEN" \
# --insecure \
# --data "${PATCH_DATA}" \
# "${APISERVER}"/apis/aws.managed.openshift.io/v1alpha1/namespaces/aws-account-operator/accounts/"${ACCOUNT_CR_NAME}"/status


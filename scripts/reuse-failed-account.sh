#!/bin/bash
set -o nounset
set -o pipefail

# Set profile
# AWS_PROFILE="us-east-1"
# AWS_DEFAULT_REGION

usage() {
    cat <<EOF
    usage: $0 [ OPTION ]
    Options
    -a         AWS Account CR Name on cluster
    -i         AWS Account ID (10 digit int)
    -p         AWS Profile, leave blank for none
EOF
}

if ( ! getopts ":a:i:p:h" opt); then
    echo ""
    echo "    $0 requries an argument!"
    usage
    exit 1 
fi

while getopts ":a:i:p:h" opt; do
    case $opt in
        a)
            AWS_ACCOUNT_CR_NAME="$OPTARG" >&2
            ;;
        i)
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

if [ -z "$AWS_ACCOUNT_CR_NAME" ]; then
    echo "AWS Account CR Name required"
    usage
    exit 1
fi

if [ -z "$AWS_ACCOUNT_ID_ARG" ]; then
    echo "AWS Account ID required"
    usage
    exit 1
fi

# Assume role
if [ -z "$AWS_PROFILE" ]; then
    echo "AWS Account Profile required"
    usage
    exit 1
else
    export AWS_PROFILE
fi

AWS_STS_SESSION_NAME="SREResetFailedAccount"

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
AWS_ACCOUNT_ID="$(aws organizations list-accounts | jq -r --arg AWS_ACCOUNT_ID_ARG "$AWS_ACCOUNT_ID_ARG" '.Accounts[] | select(.Id==$AWS_ACCOUNT_ID_ARG) | .Id')"
# AWS_ACCOUNT_ID="$(cat < list-accounts-orgtest.json | jq -r --arg AWS_ACCOUNT_ID_ARG "$AWS_ACCOUNT_ID_ARG" '.Accounts[] | select(.Id==$AWS_ACCOUNT_ID_ARG) | .Id')"
if [ -z "$AWS_ACCOUNT_ID" ]; then
    echo "AWS Account ID is not part of organization"
    exit 1
else
    echo "AWS Account ID $AWS_ACCOUNT_ID"
fi

# Assume role
AWS_ASSUME_ROLE=$(aws sts assume-role --role-arn arn:aws:iam::"${AWS_ACCOUNT_ID}":role/OrganizationAccountAccessRole --role-session-name ${AWS_STS_SESSION_NAME})

AWS_ACCESS_KEY_ID=$(echo "$AWS_ASSUME_ROLE" | jq -r '.Credentials.AccessKeyId')
AWS_SECRET_ACCESS_KEY=$(echo "$AWS_ASSUME_ROLE" | jq -r '.Credentials.SecretAccessKey')
AWS_SESSION_TOKEN=$(echo "$AWS_ASSUME_ROLE" | jq -r '.Credentials.SessionToken')

export AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY
export AWS_SESSION_TOKEN

# Echo out the account we are using
STS_CALLER_IDENTITY="$(aws sts get-caller-identity | jq -r '.Account')"

echo "!!!THESE SHOULD IDS MATCH!!! AWS ACCOUNT ID: $AWS_ACCOUNT_ID STS CALLER IDENTITY: $STS_CALLER_IDENTITY"
# if [[ "${AWS_ACCOUNT_ID}" == ${STS_CALLER_IDENTITY} ]]; then
#     echo "Error assuming role? Caller identity doesn't match the AWS Account ID passed in"
#     exit 1
# fi

# Check AWS account for instances in all regions and terminate them
for REGION in "${SUPPORTED_REGIONS[@]}"
do

  # Get a list of instance IDs
  INSTANCE_LIST=( $(aws ec2 describe-instances --region="$REGION" | jq -r '.Reservations[].Instances[].InstanceId') )
  #INSTANCE_LIST=( $(cat < describe-instances.json | jq -r '.Reservations[].Instances[].InstanceId') )

  # Terminate any instances ids we find
  if [ "${#INSTANCE_LIST[@]}" -gt 0 ]; then
      echo "Found ${#INSTANCE_LIST[@]} instance(s) in region $REGION"
      for id in $"${INSTANCE_LIST[@]}"
      do
          echo "Terminating instance id $id"
          aws ec2 terminate-instances --region="$REGION" --instances-ids "$id"
      done
  fi
done

# Check that there are no IAM users, if there are remove their login profile
# and then detach their policy ARNs (You can't delete the user without doing this first)

for IAM_USER in $(aws iam list-users | jq -r '.Users[].UserName'); do
# for IAM_USER in $(cat < iam-users.json | jq -r '.Users[].UserName'); do
    echo "Cleaning up IAM user: $IAM_USER"

    # Check to see if a IAM login profile exists
    LOGIN_PROFILE=$(aws iam get-login-profile --user-name "$IAM_USER" | jq -r '.LoginProfile.UserName' 2> /dev/null)

    # If the login profile exists delete it
    if ! [ "$LOGIN_PROFILE" = "" ]; then
      echo "Deleting login profile $LOGIN_PROFILE"
      if aws iam delete-login-profile --user-name "$IAM_USER" 2> /dev/null; then
          echo "Deleted login profile for user $IAM_USER"
      fi
    else
        echo "No login profile for IAM user: $IAM_USER"
    fi

    # Get attached policy ARNs to IAM user
    ATTACHED_USER_POLICY_ARNS=( $(aws iam list-attached-user-policies --user-name "$IAM_USER" | jq -r '.AttachedPolicies[].PolicyArn') )
    for POLICY_ARN in "${ATTACHED_USER_POLICY_ARNS[@]}"
    do
        # Detach those policy ARNs
        aws iam detach-user-policy --user-name "$IAM_USER" --policy-arn "$POLICY_ARN"
    done
    
    # List access keys created for user
    ADMIN_ACCESS_KEY_IDS=( $(aws iam list-access-keys --user-name "$IAM_USER" | jq -r '.AccessKeyMetadata[].AccessKeyId') )
    
    # Delete access keys created for user
    for ID in "${ADMIN_ACCESS_KEY_IDS[@]}"; do
      echo "Deleting ACCESS KEY $ID"
      aws iam delete-access-key --user-name "$IAM_USER" --access-key-id "${ID}"
    done

    # Delete IAM user
    aws iam delete-user --user-name "$IAM_USER"
done

# Remove any secrets the belong to the Account CR

for secret in $(oc get secrets -n aws-account-operator --no-headers | grep "${AWS_ACCOUNT_CR_NAME}" | awk '{print $1}'); do
    echo "Deleting secret $secret"
    oc delete secret "$secret" -n aws-account-operator
done

# Reset status
# List cluster context names `kubectl config view -o jsonpath='{"Cluster name\tServer\n"}{range .clusters[*]}{.name}{"\t"}{.cluster.server}{"\n"}{end}'`
CLUSTER_NAME="192-168-99-100:8443"

APISERVER=$(kubectl config view -o jsonpath="{.clusters[?(@.name==\"$CLUSTER_NAME\")].cluster.server}")

# Service account for aws-account-operator in the aws-account-operator namespace
# `oc get secrets -n aws-account-operator` look for aws-account-operator-token-<some id>
AAO_SERVICE_ACCOUNT_NAME="aws-account-operator-token-s87z6"

TOKEN=$(oc get secret "${AAO_SERVICE_ACCOUNT_NAME}" -n aws-account-operator -o json | jq -r '.data.token' | base64 -d)
 
RETURN_CODE=$(curl -s -I -X GET $APISERVER/api --header "Authorization: Bearer $TOKEN" --insecure | grep -oE "HTTP\/2\ +[0-9]{3}")

if ! [ "$RETURN_CODE" = 'HTTP/2 200' ]; then
    echo "Return code: $RETURN_CODE"
    echo "Authentication failure?"
    exit 1 
fi

PATCH_DATA='[
  {"op": "add", "path": "/status/rotateCredentials", "value": false},
  {"op": "add", "path": "/status/claimed", "value": false},
  {"op": "add", "path": "/status/state", "value": ""},
  {"op": "add", "path": "/status/conditions", "value": []}
]'

curl --header "Content-Type: application/json-patch+json" \
--request PATCH \
--header "Authorization: Bearer $TOKEN" \
--insecure \
--data "${PATCH_DATA}" \
"${APISERVER}"/apis/aws.managed.openshift.io/v1alpha1/namespaces/aws-account-operator/accounts/"${AWS_ACCOUNT_CR_NAME}"/status

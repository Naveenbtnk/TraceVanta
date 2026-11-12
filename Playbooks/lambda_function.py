import json
import os

import boto3

ec2 = boto3.client("ec2")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
QUARANTINE_SG_NAME = "Quarantine-SG"


def lambda_handler(event, context):
    """Route EventBridge events to the matching response playbook."""
    print("Received event:", json.dumps(event))

    source = event.get("source")
    detail_type = event.get("detail-type")

    try:
        if source == "aws.guardduty":
            message = handle_lateral_movement(event)
        elif source == "aws.cloudwatch" and detail_type == "CloudWatch Alarm State Change":
            message = handle_s3_exfiltration(event)
        else:
            print("Unrecognized event source, skipping.")
            return {"statusCode": 200, "body": json.dumps("Event ignored")}

        send_sns_notification(message)
    except Exception as exc:
        error_message = f"Error while handling event: {exc}"
        print(error_message)
        send_sns_notification(error_message)

    return {"statusCode": 200, "body": json.dumps("Event processed")}


def handle_lateral_movement(event):
    """Isolate the affected EC2 instance and preserve forensic evidence."""
    finding_type = event["detail"]["type"]
    instance_id = event["detail"]["resource"]["instanceDetails"]["instanceId"]

    print(f"Lateral movement detected: {finding_type} on instance {instance_id}")

    vpc_id = event["detail"]["resource"]["instanceDetails"]["networkInterfaces"][0]["vpcId"]

    try:
        response = ec2.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": [QUARANTINE_SG_NAME]},
                {"Name": "vpc-id", "Values": [vpc_id]},
            ]
        )
        quarantine_sg_id = response["SecurityGroups"][0]["GroupId"]
    except Exception:
        print(f"Security group '{QUARANTINE_SG_NAME}' not found, creating it.")
        quarantine_sg = ec2.create_security_group(
            GroupName=QUARANTINE_SG_NAME,
            Description="Deny all inbound and outbound traffic",
            VpcId=vpc_id,
        )
        quarantine_sg_id = quarantine_sg["GroupId"]

    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[quarantine_sg_id])
    print(f"Isolated instance {instance_id} with security group {quarantine_sg_id}")

    volume_id = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
        "Instances"
    ][0]["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    snapshot = ec2.create_snapshot(
        VolumeId=volume_id,
        Description=f"Forensic snapshot for instance {instance_id} due to {finding_type}",
    )
    print(f"Created snapshot {snapshot['SnapshotId']} for volume {volume_id}")

    return (
        "[SECURITY ALERT - LATERAL MOVEMENT]\n\n"
        f"Finding type: {finding_type}\n"
        f"Affected instance: {instance_id}\n\n"
        "AUTOMATED RESPONSE:\n"
        f"  - Instance isolated with security group: {quarantine_sg_id}\n"
        f"  - Forensic snapshot created: {snapshot['SnapshotId']}"
    )


def handle_s3_exfiltration(event):
    """Raise an alert for the S3 data exfiltration CloudWatch alarm."""
    alarm_name = event["detail"]["alarmName"]
    print(f"S3 exfiltration alarm received: {alarm_name}")

    # The alarm payload does not identify the accessed objects. A production
    # playbook would query CloudTrail for the GetObject calls behind the alarm
    # and act on those objects, for example with s3.put_object_tagging().
    return (
        "[SECURITY ALERT - S3 DATA EXFILTRATION]\n\n"
        f"Alarm: {alarm_name}\n"
        "Description: A high volume of S3 GetObject calls was detected.\n\n"
        "AUTOMATED RESPONSE:\n"
        "  - Event recorded. Review CloudTrail logs to identify the affected objects."
    )


def send_sns_notification(message):
    """Publish an alert to the configured SNS topic."""
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject="Automated Security Alert - TraceVanta",
        )
        print("SNS notification sent.")
    except Exception as exc:
        print(f"Failed to send SNS notification: {exc}")

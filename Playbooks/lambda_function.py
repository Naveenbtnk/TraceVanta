import json
import boto3
import os
from datetime import datetime

# Khởi tạo các client của AWS
ec2 = boto3.client('ec2')
s3 = boto3.client('s3')
sns = boto3.client('sns')

# Lấy ARN của SNS Topic từ biến môi trường
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

def lambda_handler(event, context):
    """
    Hàm chính, được kích hoạt bởi EventBridge.
    Phân tích sự kiện để xác định nguồn gốc và gọi hàm xử lý tương ứng.
    """
    print("Sự kiện nhận được:", json.dumps(event))

    # Xác định nguồn gốc của sự kiện
    source = event.get('source')
    detail_type = event.get('detail-type')

    response_message = ""

    try:
        if source == "aws.guardduty":
            response_message = handle_lateral_movement(event)
        elif source == "aws.cloudwatch" and detail_type == "CloudWatch Alarm State Change":
            response_message = handle_s3_exfiltration(event)
        else:
            print("Sự kiện không xác định, bỏ qua.")
            return

        # Gửi thông báo sau khi xử lý
        if response_message:
            send_sns_notification(response_message)

    except Exception as e:
        error_message = f"Lỗi xảy ra khi xử lý sự kiện: {str(e)}"
        print(error_message)
        send_sns_notification(error_message)

    return {
        'statusCode': 200,
        'body': json.dumps('Xử lý hoàn tất!')
    }


def handle_lateral_movement(event):
    """
    Xử lý phát hiện Dịch chuyển ngang từ GuardDuty.
    Hành động: Cô lập EC2 và tạo Snapshot.
    """
    finding_type = event['detail']['type']
    instance_id = event['detail']['resource']['instanceDetails']['instanceId']
    
    print(f"Phát hiện Dịch chuyển ngang: {finding_type} trên instance {instance_id}")

    # 1. Cô lập instance bằng cách thay đổi Security Group
    # Tạo một security group mới tên là 'Quarantine-SG' nếu chưa có.
    # Trong môi trường thực tế, bạn nên tạo sẵn SG này.
    quarantine_sg_name = 'Quarantine-SG'
    vpc_id = event['detail']['resource']['instanceDetails']['networkInterfaces'][0]['vpcId']
    
    try:
        response = ec2.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': [quarantine_sg_name]}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
        quarantine_sg_id = response['SecurityGroups'][0]['GroupId']
    except Exception:
        print(f"Chưa có Security Group '{quarantine_sg_name}', đang tạo mới...")
        quarantine_sg = ec2.create_security_group(
            GroupName=quarantine_sg_name,
            Description='Deny all inbound and outbound traffic',
            VpcId=vpc_id
        )
        quarantine_sg_id = quarantine_sg['GroupId']

    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[quarantine_sg_id])
    print(f"Đã cô lập thành công instance {instance_id} bằng Security Group {quarantine_sg_id}")

    # 2. Tạo Snapshot để điều tra
    volume_id = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]['BlockDeviceMappings'][0]['Ebs']['VolumeId']
    snapshot = ec2.create_snapshot(
        VolumeId=volume_id,
        Description=f"Forensic snapshot for instance {instance_id} due to {finding_type}"
    )
    print(f"Đã tạo thành công snapshot {snapshot['SnapshotId']} cho volume {volume_id}")

    message = (
        f"🚨 [CẢNH BÁO AN NINH - DỊCH CHUYỂN NGANG]\n\n"
        f"Loại phát hiện: {finding_type}\n"
        f"Instance bị ảnh hưởng: {instance_id}\n\n"
        f"✅ HÀNH ĐỘNG TỰ ĐỘNG:\n"
        f"  - Đã cô lập Instance bằng Security Group: {quarantine_sg_id}\n"
        f"  - Đã tạo Snapshot để điều tra: {snapshot['SnapshotId']}"
    )
    return message


def handle_s3_exfiltration(event):
    """
    Xử lý cảnh báo Đánh cắp dữ liệu S3 từ CloudWatch.
    Hành động: Gắn thẻ (Tag) vào các đối tượng S3 liên quan.
    """
    alarm_name = event['detail']['alarmName']
    
    # CloudTrail log không chứa trực tiếp tên file,
    # nên hành động thực tế sẽ phức tạp hơn.
    # Ở đây, chúng ta chỉ mô phỏng hành động và gửi thông báo.
    print(f"Phát hiện Đánh cắp dữ liệu S3 từ Alarm: {alarm_name}")

    # Trong một kịch bản nâng cao, bạn sẽ cần truy vấn CloudTrail log
    # để tìm chính xác các file đã bị truy cập trong khoảng thời gian xảy ra alarm.
    # Ví dụ: s3.put_object_tagging(...)
    
    message = (
        f"🚨 [CẢNH BÁO AN NINH - ĐÁNH CẮP DỮ LIỆU S3]\n\n"
        f"Tên cảnh báo: {alarm_name}\n"
        f"Mô tả: Phát hiện số lượng lớn hành vi tải file từ S3.\n\n"
        f"✅ HÀNH ĐỘNG TỰ ĐỘNG:\n"
        f"  - Đã ghi nhận sự kiện. Hãy kiểm tra CloudTrail log để xác định các file bị ảnh hưởng."
    )
    return message


def send_sns_notification(message):
    """
    Gửi thông báo đến SNS Topic.
    """
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject='Cảnh báo An ninh Tự động từ Hệ thống CDR'
        )
        print("Đã gửi thông báo thành công đến SNS.")
    except Exception as e:
        print(f"Lỗi khi gửi thông báo SNS: {str(e)}")
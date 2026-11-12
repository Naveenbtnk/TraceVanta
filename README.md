# TraceVanta

**Automated Cloud Detection and Response on AWS**

TraceVanta is a hands-on implementation of an event-driven security operations workflow on AWS. It detects two threat scenarios — S3 data exfiltration and internal reconnaissance — and executes containment playbooks automatically, shortening the window between detection and response.

> All resources and data in this repository are synthetic. The environment was an isolated AWS account created solely for this project.

## Table of Contents

- [Architecture](#architecture)
- [Detection and Response Pipeline](#detection-and-response-pipeline)
- [Key Features](#key-features)
- [Detection Matrix](#detection-matrix)
- [Tech Stack](#tech-stack)
- [Repository Structure](#repository-structure)
- [Implementation](#implementation)
  - [Phase 1: Lab Environment](#phase-1-lab-environment)
  - [Phase 2: Detection Services](#phase-2-detection-services)
  - [Phase 3: Automated Response](#phase-3-automated-response)
  - [Phase 4: Validation](#phase-4-validation)
- [Configuration Reference](#configuration-reference)
- [Design Notes and Limitations](#design-notes-and-limitations)
- [Skills Demonstrated](#skills-demonstrated)

## Architecture

![TraceVanta architecture workflow](Architecture_Workflow.png)

The editable diagram is available in [`Architecture_Workflow.drawio`](Architecture_Workflow.drawio).

## Detection and Response Pipeline

1. **Telemetry** — CloudTrail records S3 data events; VPC Flow Logs and CloudTrail events feed GuardDuty.
2. **Detection** — A CloudWatch metric filter and alarm detect abnormal `GetObject` volume. GuardDuty detects reconnaissance behavior.
3. **Routing** — EventBridge rules forward alarm state changes and GuardDuty findings to a single Lambda function.
4. **Response** — The Lambda playbook applies the appropriate containment action and publishes an SNS notification.
5. **Evidence** — The compromised instance is isolated and an EBS snapshot is preserved for investigation.

## Key Features

- **Native detection:** GuardDuty, CloudTrail, and CloudWatch Alarms, with no third-party tooling.
- **Automated containment:** Lambda playbooks isolate a compromised EC2 instance and preserve forensic evidence.
- **Data-centric monitoring:** S3 access patterns are monitored for signs of exfiltration.
- **Behavioral detection:** Internal reconnaissance is detected through GuardDuty findings.
- **Event-driven and serverless:** EventBridge, Lambda, and SNS keep the response path scalable and low-maintenance.
- **Operational visibility:** SNS email alerts summarize each finding and the actions taken.

## Detection Matrix

| Scenario | Signal | Detection | Automated response |
|---|---|---|---|
| S3 data exfiltration | More than two `GetObject` calls within a five-minute window | CloudTrail data events → CloudWatch metric filter and alarm | SNS email notification |
| Lateral movement | Port scan against the internal RDS endpoint | GuardDuty `Recon:EC2/Portscan` finding | EC2 instance quarantined, EBS forensic snapshot created, SNS notification |

## Tech Stack

| Layer | Services |
|---|---|
| Threat detection | Amazon GuardDuty, AWS CloudTrail, Amazon CloudWatch |
| Automated response | AWS Lambda (Python 3.9), Amazon EventBridge |
| Infrastructure | Amazon VPC, Amazon EC2, Amazon S3, Amazon RDS |
| Notifications | Amazon SNS |
| Identity and access | AWS IAM |
| Region | `ap-southeast-1` (Singapore) |

## Repository Structure

```text
.
├── Architecture_Workflow.drawio    # Editable architecture diagram
├── Architecture_Workflow.png       # Architecture diagram
├── Playbooks/
│   └── lambda_function.py          # EventBridge-triggered response playbook
├── S3_Sensitive_Data_Sample/       # Synthetic data used in the exfiltration test
└── images/                         # Implementation and validation screenshots
```

## Implementation

### Phase 1: Lab Environment

A single-region lab in `ap-southeast-1` provides both the attack surface and the protected assets.

- **Network:** A VPC with one public and one private subnet.
- **EC2:** A `t3.micro` instance in the public subnet serves as the initial point of compromise.
- **S3:** A private bucket holds synthetic sensitive documents and has public access fully blocked.
- **RDS:** A `db.t3.micro` MySQL instance in the private subnet, with public access disabled, serves as the internal target.
- **IAM:** An `EC2-S3-Access-Role` grants the instance read-only access to the bucket, enabling the exfiltration simulation.

<details>
<summary>VPC and networking screenshots (6)</summary>

![VPC configuration](images/1.jpg)
![VPC configuration](images/2.jpg)
![VPC configuration](images/3.jpg)
![VPC configuration](images/4.jpg)
![VPC configuration](images/5.jpg)
![VPC configuration](images/6.jpg)

</details>

<details>
<summary>EC2 instance screenshots (7)</summary>

![EC2 instance configuration](images/7.jpg)
![EC2 instance configuration](images/8.jpg)
![EC2 instance configuration](images/9.jpg)
![EC2 instance configuration](images/10.jpg)
![EC2 instance configuration](images/11.jpg)
![EC2 instance configuration](images/12.jpg)
![EC2 instance configuration](images/13.jpg)

</details>

<details>
<summary>S3 bucket screenshots (8)</summary>

![S3 bucket configuration](images/14.jpg)
![S3 bucket configuration](images/15.jpg)
![S3 bucket configuration](images/16.jpg)
![S3 bucket configuration](images/17.jpg)
![S3 bucket configuration](images/18.jpg)
![S3 bucket configuration](images/19.jpg)
![S3 bucket configuration](images/20.jpg)
![S3 bucket configuration](images/21.jpg)

</details>

<details>
<summary>RDS database screenshots (8)</summary>

![RDS configuration](images/22.jpg)
![RDS configuration](images/23.jpg)
![RDS configuration](images/24.jpg)
![RDS configuration](images/25.jpg)
![RDS configuration](images/26.jpg)
![RDS configuration](images/27.jpg)
![RDS configuration](images/28.jpg)
![RDS configuration](images/29.jpg)

</details>

<details>
<summary>IAM role screenshots (5)</summary>

![IAM role configuration](images/30.jpg)
![IAM role configuration](images/31.jpg)
![IAM role configuration](images/32.jpg)
![IAM role configuration](images/33.jpg)
![IAM role configuration](images/34.jpg)

</details>

### Phase 2: Detection Services

- **AWS CloudTrail:** The `CDR-S3-Monitoring-Trail` trail logs S3 data events such as `GetObject` to a dedicated bucket and to CloudWatch Logs.
- **Amazon CloudWatch:** A metric filter counts `GetObject` events, and the `S3DataExfiltrationDetected` alarm enters the `ALARM` state when more than two events occur within five minutes.
- **Amazon GuardDuty:** Enabled for the region to analyze VPC Flow Logs and CloudTrail events for threats such as port scanning.

<details>
<summary>CloudTrail screenshots (5)</summary>

![CloudTrail configuration](images/35.jpg)
![CloudTrail configuration](images/36.jpg)
![CloudTrail configuration](images/37.jpg)
![CloudTrail configuration](images/38.jpg)
![CloudTrail configuration](images/39.jpg)

</details>

<details>
<summary>CloudWatch screenshots (8)</summary>

![CloudWatch configuration](images/40.jpg)
![CloudWatch configuration](images/41.jpg)
![CloudWatch configuration](images/42.jpg)
![CloudWatch configuration](images/43.jpg)
![CloudWatch configuration](images/44.jpg)
![CloudWatch configuration](images/45.jpg)
![CloudWatch configuration](images/46.jpg)
![CloudWatch configuration](images/47.jpg)

</details>

<details>
<summary>GuardDuty screenshots (2)</summary>

![GuardDuty configuration](images/48.jpg)
![GuardDuty configuration](images/49.jpg)

</details>

### Phase 3: Automated Response

The Python Lambda function `CDR-Response-Function` is the single entry point for all events. It routes GuardDuty findings to the lateral movement playbook and CloudWatch alarm state changes to the exfiltration playbook.

- **Lateral movement playbook:** Finds or creates the `Quarantine-SG` security group, attaches it to the affected instance, creates an EBS snapshot for forensics, and sends an SNS alert.
- **S3 exfiltration playbook:** Sends an SNS alert with the alarm details and a pointer to CloudTrail for object-level analysis.
- **Error handling:** Exceptions are caught at the handler boundary and reported through SNS, so failures remain visible during incident response.
- **SNS:** The alert topic delivers email notifications to the security contact.
- **EventBridge:** `Catch-S3-Exfiltration-Alarm` matches the CloudWatch alarm state change, and `Catch-Lateral-Movement-Finding` matches GuardDuty findings. Both invoke the same Lambda function.

**Source code:** [`Playbooks/lambda_function.py`](Playbooks/lambda_function.py)

**Runtime configuration**

| Setting | Value |
|---|---|
| Runtime | Python 3.9 |
| Environment variable | `SNS_TOPIC_ARN` — ARN of the alert topic |
| Dependencies | `boto3`, provided by the Lambda runtime |
| Lab IAM policies | `AmazonEC2FullAccess`, `AmazonSNSFullAccess` |

For production, scope the execution role to the required actions: `ec2:Describe*`, `ec2:ModifyInstanceAttribute`, `ec2:CreateSnapshot`, and `sns:Publish`.

<details>
<summary>Lambda screenshots (3)</summary>

![Lambda function](images/50.jpg)
![Lambda function](images/51.jpg)
![Lambda environment variable](images/55.jpg)

</details>

<details>
<summary>Lambda permissions screenshot (1)</summary>

![Lambda execution role](images/52.jpg)

</details>

<details>
<summary>SNS screenshots (2)</summary>

![SNS configuration](images/53.jpg)
![SNS configuration](images/54.jpg)

</details>

<details>
<summary>EventBridge rules screenshots (5)</summary>

![EventBridge rule](images/56.jpg)
![EventBridge rule](images/57.jpg)
![EventBridge rule](images/58.jpg)
![EventBridge rule](images/59.jpg)
![EventBridge rule](images/60.jpg)

</details>

### Phase 4: Validation

Both scenarios were simulated from the compromised EC2 instance.

#### Test 1: Data Exfiltration

Three objects were downloaded from the sensitive bucket with `aws s3 cp`.

![Exfiltration command](images/61.jpg)
![Exfiltration command](images/62.jpg)

**Result**

- The CloudWatch alarm transitioned to the **In alarm** state.
- An SNS email notification was delivered immediately.

![CloudWatch alarm state](images/63.jpg)
![SNS email notification](images/64.jpg)

#### Test 2: Lateral Movement

A port scan was run against the internal RDS endpoint with `nmap -Pn`.

![Port scan command](images/65.jpg)
![Port scan command](images/66.jpg)

**Result**

- GuardDuty generated a `Recon:EC2/Portscan` finding.
- The instance security group was replaced with `Quarantine-SG`, isolating it from the network.
- An EBS snapshot was created for forensic investigation.
- An SNS alert reported the finding, the containment actions, and the handled snapshot rate-limit error.

![GuardDuty finding](images/67.jpg)
![Instance quarantined](images/68.jpg)
![Forensic EBS snapshot](images/70.jpg)
![SNS alert](images/69.jpg)

## Configuration Reference

| Component | Identifier |
|---|---|
| Lambda function | `CDR-Response-Function` |
| CloudTrail trail | `CDR-S3-Monitoring-Trail` |
| CloudWatch alarm | `S3DataExfiltrationDetected` |
| EventBridge rules | `Catch-S3-Exfiltration-Alarm`, `Catch-Lateral-Movement-Finding` |
| Quarantine security group | `Quarantine-SG` |
| SNS topic | `CDR-Security-Alerts` |

## Design Notes and Limitations

- **Object-level response:** The CloudWatch alarm carries the alarm state but not the names of the accessed objects. A production playbook would query CloudTrail for the relevant time window and act on those objects, for example with `s3.put_object_tagging()`.
- **Least privilege:** The lab uses broad AWS-managed policies for speed. A production deployment should use a narrowly scoped execution role.
- **Infrastructure as code:** Resources were provisioned through the AWS console. Migrating the lab to CDK or Terraform is a natural next step.
- **Scope:** The system is single-region. Multi-region aggregation and integration with AWS Security Hub are out of scope.
- **Rate limits:** The snapshot API returned a rate-limit error during validation; the error was surfaced through SNS, which confirmed the handler's failure path.

## Skills Demonstrated

- Detection engineering with native AWS security services
- Serverless response automation with EventBridge, Lambda, and SNS
- Incident containment and forensic evidence preservation
- CloudTrail data event analysis and CloudWatch metric filters
- Secure VPC, EC2, S3, RDS, and IAM configuration

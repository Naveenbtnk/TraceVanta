# TraceVanta

**Automated Cloud Detection & Response (CDR) on AWS**

TraceVanta demonstrates the implementation of an automated security operations (SecOps) system on Amazon Web Services. The system is designed to detect, respond to, and notify about specific security threats in real-time, significantly reducing the Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR).

## 📑 Table of Contents

- [Architecture Diagram](#architecture-diagram)
- [Key Features](#key-features)
- [Tech Stack](#tech-stack)
- [Project Implementation Steps](#project-implementation-steps)
  - [Phase 1: Lab Environment Setup](#phase-1-lab-environment-setup)
  - [Phase 2: Detection Services Configuration](#phase-2-detection-services-configuration)
  - [Phase 3: Automated Response Flow Implementation](#phase-3-automated-response-flow-implementation)
  - [Phase 4: Attack Simulation & Results](#phase-4-attack-simulation--results)
    - [Test 1: Data Exfiltration](#test-1-data-exfiltration)
    - [Test 2: Lateral Movement](#test-2-lateral-movement)
- [Conclusion & Key Takeaways](#conclusion--key-takeaways)

---

## Architecture Diagram

[<img src="Architecture_Workflow.png" alt="Architecture Workflow" width="1000"/>](Architecture_Workflow.png)

## Key Features

- **Automated Threat Detection:** Utilizes native AWS services like GuardDuty and CloudWatch to detect malicious activities and policy violations.
- **Real-time Automated Response:** Employs AWS Lambda and EventBridge to execute predefined response playbooks, such as isolating compromised resources and gathering forensic evidence.
- **Data-Centric Security Monitoring:** Actively monitors sensitive data stored in S3 for signs of exfiltration.
- **Behavioral Analysis:** Detects post-compromise activities like internal network reconnaissance (Lateral Movement).
- **Serverless & Scalable:** Built on a serverless architecture, ensuring high availability and cost-efficiency.

## Tech Stack

- **Threat Detection:** Amazon GuardDuty, AWS CloudTrail, Amazon CloudWatch Alarms
- **Automated Response & Processing:** AWS Lambda (Python), AWS EventBridge
- **Infrastructure:** Amazon EC2, Amazon S3, Amazon RDS, Amazon VPC
- **Notifications:** Amazon SNS (Simple Notification Service)
- **Identity & Access Management:** AWS IAM

## Project Implementation Steps

This project was built from the ground up on AWS. The following sections outline the key phases of implementation, from building the foundational infrastructure to testing the final automated response system.

### Phase 1: Lab Environment Setup

The first phase involved creating a realistic, isolated cloud environment in the `ap-southeast-1` (Singapore) region to serve as the attack surface.
* **VPC and Networking:** A Virtual Private Cloud (VPC) was created with one public and one private subnet. This provides a secure and isolated network foundation for all other resources.

![image](images/1.jpg)
![image](images/3.jpg)
![image](images/4.jpg)
![image](images/5.jpg)
![image](images/6.jpg)
    

* **EC2 Instance:** A `t3.micro` EC2 instance was launched into the public subnet to act as the initial point of compromise for attack simulations.

![image](images/7.jpg)
![image](images/8.jpg)
![image](images/9.jpg)
![image](images/10.jpg)
![image](images/11.jpg)
![image](images/12.jpg)
![image](images/13.jpg)
    
* **S3 Bucket:** A private S3 bucket was created to store simulated sensitive files (`customer-list.txt`, `financial-report-q3.txt`, etc.), serving as the target for the data exfiltration scenario. Public access was completely blocked.

![image](images/14.jpg)
![image](images/15.jpg)
![image](images/16.jpg)
![image](images/17.jpg)
![image](images/18.jpg)
![image](images/19.jpg)
![image](images/20.jpg)
![image](images/21.jpg)
    

* **RDS Database:** A `db.t3.micro` MySQL RDS instance was deployed into the private subnet with public access disabled. This serves as a high-value internal target for the lateral movement scenario.

![image](images/22.jpg)
![image](images/23.jpg)
![image](images/24.jpg)
![image](images/25.jpg)
![image](images/26.jpg)
![image](images/27.jpg)
![image](images/28.jpg)
![image](images/29.jpg)
    

* **IAM Role:** An IAM Role (`EC2-S3-Access-Role`) was created and attached to the EC2 instance, granting it read-only permissions to the S3 bucket. This is a crucial step to enable the data exfiltration simulation.

![image](images/30.jpg)
![image](images/31.jpg)
![image](images/32.jpg)
![image](images/33.jpg)
![image](images/34.jpg)
    

### Phase 2: Detection Services Configuration
With the environment in place, the next step was to deploy the security "sensors" to monitor for malicious activity.

* **AWS CloudTrail:** A trail (`CDR-S3-Monitoring-Trail`) was configured to specifically log S3 Data Events (Read actions like `GetObject`). Logs are delivered to a dedicated S3 bucket and CloudWatch Logs for analysis.

![image](images/35.jpg)
![image](images/36.jpg)
![image](images/37.jpg)
![image](images/38.jpg)
![image](images/39.jpg)
    

* **Amazon CloudWatch:** A Metric Filter was created to parse the CloudTrail logs and count `GetObject` events. An Alarm (`S3DataExfiltrationDetected`) was then configured to trigger if more than 2 `GetObject` events occurred within a 5-minute window.

![image](images/40.jpg)
![image](images/41.jpg)
![image](images/42.jpg)
![image](images/43.jpg)
![image](images/44.jpg)
![image](images/45.jpg)
![image](images/46.jpg)
![image](images/47.jpg)
    

* **Amazon GuardDuty:** GuardDuty was enabled for the region. This service acts as an intelligent threat detection system, automatically analyzing VPC Flow Logs and CloudTrail events to identify threats like port scanning.

![image](images/48.jpg)
![image](images/49.jpg)
  

### Phase 3: Automated Response Flow Implementation
This phase involved connecting the detection services to an automated response engine.

* **AWS Lambda:** A Python-based Lambda function (`CDR-Response-Function`) was created to act as the central "brain" of the system. The code contains the logic to handle different threats and execute specific containment actions.

![image](images/50.jpg)
![image](images/51.jpg)

👉 **Source code:** [`Playbooks/lambda_function.py`](Playbooks/lambda_function.py)
    

* **Lambda Permissions:** The Lambda function's execution role was granted the necessary permissions (`AmazonEC2FullAccess`, `AmazonSNSFullAccess`) to manage EC2 instances and send notifications.

![image](images/52.jpg)

* **Amazon SNS:** Send nofitication through email

![image](images/53.jpg)
![image](images/54.jpg)

* **AWS EventBridge:** Two rules were created to act as the "nervous system":

![image](images/56.jpg)

    - A rule (`Catch-S3-Exfiltration-Alarm`) to capture the `ALARM` state from the specific CloudWatch Alarm.

![image](images/57.jpg)
![image](images/58.jpg)
![image](images/59.jpg)

    - A rule (`Catch-Lateral-Movement-Finding`) to capture all new findings from GuardDuty.

![image](images/60.jpg)
    
    - Both rules were configured to trigger the same `CDR-Response-Function` Lambda function.
 

### Phase 4: Attack Simulation & Results

The final phase was to test the system by simulating the two defined attack scenarios.

#### Test 1: Data Exfiltration

* **Attack:** Executed `aws s3 cp` commands from the compromised EC2 instance to download 3 files from the sensitive S3 bucket.

![image](images/61.jpg)
![image](images/62.jpg)

* **Result:** The system worked perfectly.
- The CloudWatch Alarm successfully transitioned to the **"In alarm"** state.

![image](images/63.jpg)
 
- An email notification was immediately sent via SNS.

![image](images/64.jpg)
        
#### Test 2: Lateral Movement

* **Attack:** Executed an `nmap -Pn` port scan from the compromised EC2 instance against the internal RDS database endpoint.

![image](images/65.jpg)
![image](images/66.jpg)

* **Result:** The system detected and responded successfully.
- GuardDuty generated a **`Recon:EC2/Portscan`** finding.

![image](images/67.jpg)


- The EC2 instance's security group was changed to a **"Quarantine-SG"**, successfully isolating it from the network.

![image](images/68.jpg)

- An EBS **snapshot** was created for forensic purposes.

![image](images/70.jpg)

- A detailed notification was sent via SNS, including the error for rate-limiting on subsequent snapshot attempts, proving the error handling worked.

![image](images/69.jpg)


## Conclusion & Key Takeaways

This project successfully demonstrates the power of native AWS services in building a robust, cost-effective, and highly automated Cloud Detection and Response system. By integrating services like GuardDuty, CloudWatch, Lambda, and EventBridge, it's possible to create a security posture that not only detects threats in real-time but also contains them automatically, drastically reducing the window of opportunity for attackers.

**Key achievements and learnings from this project include:**

- **Hands-On Experience:** Gained practical, hands-on experience in configuring and integrating core AWS security and serverless services.
- **Security as Code:** Developed a Python-based Lambda function to programmatically execute security playbooks, a fundamental concept in modern DevSecOps.
- **Understanding Attacker Techniques:** Successfully simulated realistic attack scenarios, providing valuable insight into how threats like data exfiltration and lateral movement manifest in a cloud environment.
- **Demonstrated Value of Automation:** Proved that automation is key to achieving rapid response times (low MTTR), which is critical for effective incident response and minimizing potential damage from a security breach.

This project serves as a strong foundation and a practical demonstration of the skills required for a role in cloud security, system engineering, or network engineering, showcasing the ability to not only build but also secure cloud infrastructure.












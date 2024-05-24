# Deepfence Cloud Scanner
Deepfence Cloud Scanner runs in your cloud environment, gathering inventory and compliance information for the assets deployed in that environment. It submits that information to your Deepfence ThreatMapper or ThreatStryker Management Console.

Deploy Deepfence Cloud Scanner using the appropriate Terraform module for the cloud you wish to monitor.

## Deploying Cloud Scanner

- Cloud scanner is deployed in ECS Fargate / GCP Cloud Run / Azure Container Instance
- Deployment is done using AWS CloudFormation template or terraform
- Documentation: https://docs.deepfence.io/threatmapper/docs/cloudscanner/

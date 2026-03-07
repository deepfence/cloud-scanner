# Deepfence Cloud Scanner

Deepfence Cloud Scanner runs in your cloud environment, gathering inventory and compliance information for the assets deployed in that environment. It submits that information to your Deepfence ThreatMapper or ThreatStryker Management Console.

Deploy Deepfence Cloud Scanner using the appropriate Terraform module for the cloud you wish to monitor.

## Deploying Cloud Scanner

- Cloud scanner is deployed in ECS Fargate / GCP Cloud Run / Azure Container Instance
- Deployment is done using AWS CloudFormation template or terraform
- Documentation: https://threatmapper.org/threatmapper/docs/cloudscanner/

## Build Cloud Scanner

Cloud Scanner is part of ThreatMapper. Building Cloud Scanner is done from the ThreatMapper repository.
```shell
git clone https://github.com/deepfence/ThreatMapper
cd ThreatMapper
make bootstrap cloudscanner
```

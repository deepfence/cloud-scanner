# Using deepfence-cloud-scanner helm chart

### Single Account Cloud Scanner on EKS cluster using IAM roles for service accounts

1. **Prerequsite:** associate oidc provider with the EKS cluster where cloud scanner is installed ([aws docs](https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html))
2. Create the EKS IRSA role using the terrafrom script [terraform/self-hosted/single-account-eks-iam-role](terraform/self-hosted/single-account-eks-iam-role)
3. Note *namespace*, *service account name* and *iam role arn* from the terrafrom output
4. Update the deepfence-cloud-scanner helm chart values with deepfence key and console url, add service account annotation and service account name
    ```yaml
    serviceAccount:
      # Specifies whether a service account should be created
      create: true
      # Automatically mount a ServiceAccount's API credentials?
      automount: true
      # Annotations to add to the service account
      annotations: 
        "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789:role/test1-cloud-scanner"
      # The name of the service account to use.
      # If not set and create is true, a name is generated using the fullname template
      name: "deepfence-cloud-scanner"
    ```
5. Install the helm chart in the same *namespace* from Step 3.

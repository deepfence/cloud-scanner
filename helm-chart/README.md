# Using deepfence-cloud-scanner helm chart

### Single Account Cloud Scanner on EKS cluster using IAM roles for service accounts

1. **Prerequsite:** associate oidc provider with the EKS cluster where cloud scanner is installed ([aws docs](https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html))
2. Create the EKS IRSA role using the terrafrom script [cloudformation/self-hosted/eks-iam-roles/single-account-eks-iam-role](cloudformation/self-hosted/eks-iam-roles/single-account-eks-iam-role)
3. Or create the EKS IRSA role using the cloudformation template [cloudformation/self-hosted/eks-iam-roles/single-account-eks-iam-role/deepfence-cloud-scanner-single-account-iam-role.template](cloudformation/self-hosted/eks-iam-roles/single-account-eks-iam-role/deepfence-cloud-scanner-single-account-iam-role.template)
4. Note *namespace*, *service account name* and *iam role arn* from the terrafrom or cloudformation output
5. Update the deepfence-cloud-scanner helm chart values with deepfence key and console url, add service account annotation and service account name
    ```yaml
    serviceAccount:
      # Specifies whether a service account should be created
      create: true
      # Automatically mount a ServiceAccount's API credentials?
      automount: true
      # Annotations to add to the service account
      annotations: 
        "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789:role/test-cloud-scanner"
      # The name of the service account to use.
      # If not set and create is true, a name is generated using the fullname template
      name: "deepfence-cloud-scanner"
    ```
6. Install the helm chart in the same *namespace* from Step 3.

### Organization Account Cloud Scanner on EKS cluster using IAM roles for service accounts

1. **Prerequsite:** associate oidc provider with the EKS cluster where cloud scanner is installed ([aws docs](https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html))
2. Create the EKS IRSA role using the cloudformation template [cloudformation/self-hosted/eks-iam-roles/organization-eks-iam-role/deepfence-cloud-scanner-organization-stackset-iam-role.template](cloudformation/self-hosted/eks-iam-roles/organization-eks-iam-role/deepfence-cloud-scanner-organization-stackset-iam-role.template)
3. Note *namespace*, *service account name* and *iam role arn* from the cloudformation output
4. Update the deepfence-cloud-scanner helm chart values with deepfence key and console url along with org details, add service account annotation and service account name
    ```yaml
    serviceAccount:
      # Specifies whether a service account should be created
      create: true
      # Automatically mount a ServiceAccount's API credentials?
      automount: true
      # Annotations to add to the service account
      annotations: 
        "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789:role/test-cloud-scanner"
      # The name of the service account to use.
      # If not set and create is true, a name is generated using the fullname template
      name: "deepfence-cloud-scanner"
    ```
6. Install the helm chart in the same *namespace* from Step 3.

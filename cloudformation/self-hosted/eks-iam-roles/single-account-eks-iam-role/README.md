<!-- BEGIN_TF_DOCS -->
## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_iam_role.deepfence_cloud_scanner](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy_attachment.deepfence_cloud_scanner](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_eks_cluster.eks-cluster](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/eks_cluster) | data source |
| [aws_iam_policy.access_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy) | data source |
| [aws_iam_policy_document.deepfence_cloud_scanner_assume_role_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_access_policy"></a> [access\_policy](#input\_access\_policy) | access policy to be attached to cloud scanner, should be either *arn:aws:iam::aws:policy/SecurityAudit* or *arn:aws:iam::aws:policy/ReadOnlyAccess* | `string` | `"arn:aws:iam::aws:policy/SecurityAudit"` | no |
| <a name="input_eks_cluster_name"></a> [eks\_cluster\_name](#input\_eks\_cluster\_name) | eks cluster where cloud scanner will be deployed | `string` | n/a | yes |
| <a name="input_k8s_namespace"></a> [k8s\_namespace](#input\_k8s\_namespace) | k8s namespace for deepfence-cloud-scanner | `string` | `"deepfence"` | no |
| <a name="input_service_account_name"></a> [service\_account\_name](#input\_service\_account\_name) | k8s service account for deepfence-cloud-scanner | `string` | `"deepfence-cloud-scanner"` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_cloud_scanner_role_arn"></a> [cloud\_scanner\_role\_arn](#output\_cloud\_scanner\_role\_arn) | aws iam role arn for deepfence-cloud-scanner |
| <a name="output_k8s_namespace"></a> [k8s\_namespace](#output\_k8s\_namespace) | k8s namespace for deepfence-cloud-scanner |
| <a name="output_service_account_name"></a> [service\_account\_name](#output\_service\_account\_name) | k8s service account for deepfence-cloud-scanner |
<!-- END_TF_DOCS -->
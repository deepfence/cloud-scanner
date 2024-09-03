variable "eks_cluster_name" {
  type        = string
  description = "eks cluster where cloud scanner will be deployed"
}

variable "k8s_namespace" {
  default = "deepfence"
  type    = string
  description = "k8s namespace for deepfence-cloud-scanner"
}

variable "service_account_name" {
  default = "deepfence-cloud-scanner"
  type    = string
  description = "k8s service account for deepfence-cloud-scanner"
}

variable "access_policy" {
  type        = string
  default     = "arn:aws:iam::aws:policy/SecurityAudit"
  description = "access policy to be attached to cloud scanner, should be either *arn:aws:iam::aws:policy/SecurityAudit* or *arn:aws:iam::aws:policy/ReadOnlyAccess*"
}

output "k8s_namespace" {
  value = var.k8s_namespace
  description = "k8s namespace for deepfence-cloud-scanner"
}

output "service_account_name" {
  value = var.service_account_name
  description = "k8s service account for deepfence-cloud-scanner"
}

output "cloud_scanner_role_arn" {
  value = aws_iam_role.deepfence_cloud_scanner.arn
  description = "aws iam role arn for deepfence-cloud-scanner"
}

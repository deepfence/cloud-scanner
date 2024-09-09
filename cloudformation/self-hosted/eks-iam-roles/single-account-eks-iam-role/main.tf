data "aws_caller_identity" "current" {}

data "aws_eks_cluster" "eks-cluster" {
  name = var.eks_cluster_name
}

data "aws_iam_policy_document" "deepfence_cloud_scanner_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"
    principals {
      type = "Federated"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${replace(data.aws_eks_cluster.eks-cluster.identity[0].oidc[0].issuer, "https://", "")}"
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(data.aws_eks_cluster.eks-cluster.identity[0].oidc[0].issuer, "https://", "")}:sub"
      values = [
        "system:serviceaccount:${var.k8s_namespace}:${var.service_account_name}",
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(data.aws_eks_cluster.eks-cluster.identity[0].oidc[0].issuer, "https://", "")}:aud"
      values = [
        "sts.amazonaws.com"
      ]
    }
  }
}

resource "aws_iam_role" "deepfence_cloud_scanner" {
  name                  = "${var.eks_cluster_name}-deepfence-cloud-scanner"
  description           = "Permissions required by the deepfence cloud-scanner."
  assume_role_policy    = data.aws_iam_policy_document.deepfence_cloud_scanner_assume_role_policy.json
  force_detach_policies = true
  tags = {
    Name = "${var.eks_cluster_name}-cloud-scanner"
  }
}

data "aws_iam_policy" "access_policy" {
  arn = var.access_policy
}

resource "aws_iam_role_policy_attachment" "deepfence_cloud_scanner" {
  role       = aws_iam_role.deepfence_cloud_scanner.name
  policy_arn = data.aws_iam_policy.access_policy.arn
}

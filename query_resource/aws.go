package query_resource

var (
	awsCloudTablesJson = `[
  {
    "table": "aws_iam_account_summary",
    "columns": [
      "account_access_keys_present",
      "account_id",
      "account_mfa_enabled",
      "partition",
      "region"
    ],
    "id_column": ""
  },
  {
    "table": "aws_account",
    "columns": [
      "_ctx",
      "account_id",
      "arn",
      "partition",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_iam_virtual_mfa_device",
    "columns": [
      "serial_number",
      "region",
      "title"
    ],
    "id_column": "title"
  },
  {
    "table": "aws_iam_access_key",
    "columns": [
      "access_key_id",
      "account_id",
      "create_date",
      "partition",
      "region",
      "status",
      "title",
      "user_name"
    ],
    "id_column": "access_key_id"
  },
  {
    "table": "aws_iam_user",
    "columns": [
      "_ctx",
      "account_id",
      "arn",
      "attached_policy_arns",
      "groups",
      "inline_policies",
      "inline_policies_std",
      "name",
      "region",
      "tags",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_iam_account_password_policy",
    "columns": [
      "account_id",
      "max_password_age",
      "minimum_password_length",
      "password_reuse_prevention",
      "region",
      "require_lowercase_characters",
      "require_numbers",
      "require_symbols",
      "require_uppercase_characters"
    ],
    "id_column": ""
  },
  {
    "table": "aws_account_alternate_contact",
    "columns": [
      "account_id",
      "contact_type",
      "name",
      "region",
      "title"
    ],
    "id_column": "title"
  },
  {
    "table": "aws_iam_policy",
    "columns": [
      "account_id",
      "arn",
      "is_attached",
      "is_aws_managed",
      "name",
      "policy_std",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_iam_role",
    "columns": [
      "_ctx",
      "account_id",
      "arn",
      "attached_policy_arns",
      "inline_policies",
      "inline_policies_std",
      "name",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_iam_server_certificate",
    "columns": [
      "account_id",
      "arn",
      "expiration",
      "name",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_region",
    "columns": [
      "account_id",
      "name",
      "opt_in_status",
      "partition",
      "region",
      "title"
    ],
    "id_column": "title"
  },
  {
    "table": "aws_s3_bucket",
    "columns": [
      "_ctx",
      "account_id",
      "acl",
      "arn",
      "block_public_acls",
      "block_public_policy",
      "bucket_policy_is_public",
      "event_notification_configuration",
      "ignore_public_acls",
      "lifecycle_rules",
      "logging",
      "name",
      "object_lock_configuration",
      "object_ownership_controls",
      "policy",
      "policy_std",
      "region",
      "replication",
      "restrict_public_buckets",
      "server_side_encryption_configuration",
      "tags",
      "title",
      "versioning_enabled",
      "versioning_mfa_delete"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_accessanalyzer_analyzer",
    "columns": [
      "account_id",
      "arn",
      "name",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_macie2_classification_job",
    "columns": [
      "s3_job_definition",
      "arn",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_ebs_volume",
    "columns": [
      "account_id",
      "arn",
      "encrypted",
      "region",
      "state",
      "tags",
      "title",
      "volume_id"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_rds_db_instance",
    "columns": [
      "account_id",
      "arn",
      "auto_minor_version_upgrade",
      "backup_retention_period",
      "class",
      "copy_tags_to_snapshot",
      "db_instance_identifier",
      "deletion_protection",
      "enabled_cloudwatch_logs_exports",
      "engine",
      "enhanced_monitoring_resource_arn",
      "iam_database_authentication_enabled",
      "master_user_name",
      "multi_az",
      "port",
      "publicly_accessible",
      "region",
      "storage_encrypted",
      "tags",
      "title",
      "vpc_id",
      "vpc_security_groups"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_efs_file_system",
    "columns": [
      "account_id",
      "arn",
      "automatic_backups",
      "encrypted",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_s3_account_settings",
    "columns": [
      "account_id",
      "block_public_acls",
      "block_public_policy",
      "ignore_public_acls",
      "region",
      "restrict_public_buckets",
      "title"
    ],
    "id_column": "title"
  },
  {
    "table": "aws_cloudtrail_trail",
    "columns": [
      "_ctx",
      "account_id",
      "advanced_event_selectors",
      "arn",
      "event_selectors",
      "home_region",
      "include_global_service_events",
      "is_logging",
      "is_multi_region_trail",
      "is_organization_trail",
      "kms_key_id",
      "latest_delivery_time",
      "log_file_validation_enabled",
      "log_group_arn",
      "region",
      "s3_bucket_name",
      "s3_bucket_name",
      "tags",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_config_configuration_recorder",
    "columns": [
      "account_id",
      "arn",
      "recording_group",
      "region",
      "status",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_kms_key",
    "columns": [
      "account_id",
      "arn",
      "deletion_date",
      "key_manager",
      "key_rotation_enabled",
      "key_state",
      "origin",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_vpc",
    "columns": [
      "account_id",
      "arn",
      "owner_id",
      "region",
      "title",
      "vpc_id"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_vpc_flow_log",
    "columns": [
      "region",
      "resource_id",
      "title"
    ],
    "id_column": "resource_id"
  },
  {
    "table": "aws_sns_topic_subscription",
    "columns": [
      "region",
      "title",
      "topic_arn"
    ],
    "id_column": "topic_arn"
  },
  {
    "table": "aws_securityhub_hub",
    "columns": [
      "account_id",
      "hub_arn",
      "region",
      "title"
    ],
    "id_column": "hub_arn"
  },
  {
    "table": "aws_vpc_network_acl",
    "columns": [
      "account_id",
      "arn",
      "associations",
      "entries",
      "network_acl_id",
      "partition",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_vpc_security_group",
    "columns": [
      "account_id",
      "arn",
      "group_id",
      "group_name",
      "ip_permissions",
      "ip_permissions_egress",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_vpc_security_group_rule",
    "columns": [
      "cidr_ipv4",
      "cidr_ipv6",
      "from_port",
      "group_id",
      "group_name",
      "ip_protocol",
      "is_egress",
      "region",
      "security_group_rule_id",
      "title",
      "to_port",
      "type"
    ],
    "id_column": "security_group_rule_id"
  },
  {
    "table": "aws_ec2_application_load_balancer",
    "columns": [
      "_ctx",
      "account_id",
      "arn",
      "availability_zones",
      "load_balancer_attributes",
      "region",
      "scheme",
      "security_groups",
      "tags",
      "title",
      "vpc_id"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_redshift_cluster",
    "columns": [
      "account_id",
      "allow_version_upgrade",
      "arn",
      "automated_snapshot_retention_period",
      "cluster_namespace_arn",
      "cluster_parameter_groups",
      "db_name",
      "encrypted",
      "enhanced_vpc_routing",
      "kms_key_id",
      "logging_status",
      "master_username",
      "publicly_accessible",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_acm_certificate",
    "columns": [
      "account_id",
      "certificate_arn",
      "not_after",
      "region",
      "renewal_eligibility",
      "title"
    ],
    "id_column": "certificate_arn"
  },
  {
    "table": "aws_api_gateway_stage",
    "columns": [
      "_ctx",
      "account_id",
      "arn",
      "client_certificate_id",
      "method_settings",
      "name",
      "partition",
      "region",
      "rest_api_id",
      "tags",
      "title",
      "tracing_enabled",
      "web_acl_arn"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_cloudfront_distribution",
    "columns": [
      "account_id",
      "arn",
      "default_cache_behavior",
      "default_root_object",
      "logging",
      "origin_groups",
      "origins",
      "region",
      "title",
      "viewer_certificate",
      "web_acl_id"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_ec2_classic_load_balancer",
    "columns": [
      "access_log_enabled",
      "account_id",
      "additional_attributes",
      "arn",
      "availability_zones",
      "connection_draining_enabled",
      "cross_zone_load_balancing_enabled",
      "instances",
      "listener_descriptions",
      "name",
      "partition",
      "region",
      "scheme",
      "security_groups",
      "source_security_group_name",
      "tags",
      "title",
      "vpc_id"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_dax_cluster",
    "columns": [
      "account_id",
      "arn",
      "region",
      "sse_description",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_dynamodb_table",
    "columns": [
      "account_id",
      "arn",
      "billing_mode",
      "name",
      "point_in_time_recovery_description",
      "region",
      "sse_description",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_elasticsearch_domain",
    "columns": [
      "account_id",
      "arn",
      "domain_endpoint_options",
      "elasticsearch_cluster_config",
      "enabled",
      "encryption_at_rest_options",
      "log_publishing_options",
      "region",
      "title",
      "vpc_options"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_cloudwatch_log_group",
    "columns": [
      "account_id",
      "arn",
      "kms_key_id",
      "region",
      "retention_in_days",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_rds_db_cluster_snapshot",
    "columns": [
      "account_id",
      "arn",
      "db_cluster_snapshot_attributes",
      "region",
      "storage_encrypted",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_rds_db_snapshot",
    "columns": [
      "account_id",
      "arn",
      "db_snapshot_attributes",
      "encrypted",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_sagemaker_endpoint_configuration",
    "columns": [
      "account_id",
      "arn",
      "kms_key_id",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_sagemaker_notebook_instance",
    "columns": [
      "account_id",
      "arn",
      "direct_internet_access",
      "kms_key_id",
      "region",
      "root_access",
      "subnet_id",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_sns_topic",
    "columns": [
      "account_id",
      "application_failure_feedback_role_arn",
      "firehose_failure_feedback_role_arn",
      "http_failure_feedback_role_arn",
      "kms_master_key_id",
      "lambda_failure_feedback_role_arn",
      "region",
      "sqs_failure_feedback_role_arn",
      "title",
      "topic_arn"
    ],
    "id_column": "topic_arn"
  },
  {
    "table": "aws_wafv2_web_acl",
    "columns": [
      "account_id",
      "arn",
      "logging_configuration",
      "region",
      "rules",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_ec2_autoscaling_group",
    "columns": [
      "_ctx",
      "account_id",
      "autoscaling_group_arn",
      "availability_zones",
      "health_check_type",
      "launch_template_id",
      "load_balancer_names",
      "mixed_instances_policy_launch_template_overrides",
      "region",
      "tags",
      "target_group_arns",
      "title"
    ],
    "id_column": "autoscaling_group_arn"
  },
  {
    "table": "aws_api_gatewayv2_route",
    "columns": [
      "account_id",
      "api_id",
      "authorization_type",
      "partition",
      "region",
      "route_id",
      "title"
    ],
    "id_column": "api_id"
  },
  {
    "table": "aws_api_gatewayv2_stage",
    "columns": [
      "_ctx",
      "access_log_settings",
      "account_id",
      "api_id",
      "default_route_logging_level",
      "partition",
      "region",
      "stage_name",
      "tags",
      "title"
    ],
    "id_column": "api_id"
  },
  {
    "table": "aws_ec2_launch_configuration",
    "columns": [
      "account_id",
      "associate_public_ip_address",
      "launch_configuration_arn",
      "metadata_options_http_tokens",
      "metadata_options_put_response_hop_limit",
      "region",
      "title"
    ],
    "id_column": "launch_configuration_arn"
  },
  {
    "table": "aws_cloudformation_stack",
    "columns": [
      "account_id",
      "id",
      "notification_arns",
      "region",
      "stack_drift_status",
      "title"
    ],
    "id_column": "notification_arns"
  },
  {
    "table": "aws_codebuild_project",
    "columns": [
      "account_id",
      "arn",
      "environment",
      "logs_config",
      "region",
      "source",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_dms_replication_instance",
    "columns": [
      "account_id",
      "arn",
      "publicly_accessible",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_ebs_snapshot",
    "columns": [
      "account_id",
      "arn",
      "create_volume_permissions",
      "partition",
      "region",
      "snapshot_id",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_ec2_regional_settings",
    "columns": [
      "account_id",
      "default_ebs_encryption_enabled",
      "partition",
      "region",
      "title"
    ],
    "id_column": "title"
  },
  {
    "table": "aws_ec2_instance",
    "columns": [
      "account_id",
      "arn",
      "ebs_optimized",
      "iam_instance_profile_id",
      "instance_id",
      "instance_state",
      "instance_type",
      "metadata_options",
      "monitoring_state",
      "network_interfaces",
      "private_dns_name",
      "private_ip_address",
      "public_ip_address",
      "region",
      "security_groups",
      "state_transition_time",
      "tags",
      "title",
      "virtualization_type",
      "vpc_id"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_vpc_subnet",
    "columns": [
      "account_id",
      "map_public_ip_on_launch",
      "region",
      "title",
      "subnet_id"
    ],
    "id_column": "subnet_id"
  },
  {
    "table": "aws_vpc_endpoint",
    "columns": [
      "region",
      "service_name",
      "title",
      "vpc_id"
    ],
    "id_column": "vpc_id"
  },
  {
    "table": "aws_vpc_vpn_connection",
    "columns": [
      "account_id",
      "arn",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_ec2_transit_gateway",
    "columns": [
      "account_id",
      "auto_accept_shared_attachments",
      "region",
      "title",
      "transit_gateway_arn"
    ],
    "id_column": "transit_gateway_arn"
  },
  {
    "table": "aws_ec2_network_interface",
    "columns": [
      "groups",
      "region",
      "title"
    ],
    "id_column": "title"
  },
  {
    "table": "aws_ec2_launch_template",
    "columns": [
      "account_id",
      "launch_template_id",
      "region",
      "title"
    ],
    "id_column": "launch_template_id"
  },
  {
    "table": "aws_ecr_repository",
    "columns": [
      "account_id",
      "arn",
      "image_scanning_configuration",
      "image_tag_mutability",
      "lifecycle_policy",
      "policy",
      "region",
      "repository_name",
      "repository_uri",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_ecs_task",
    "columns": [
      "account_id",
      "cluster_arn",
      "cluster_name",
      "connectivity",
      "group",
      "last_status",
      "region",
      "service_name",
      "task_arn",
      "task_definition_arn"
    ],
    "id_column": "task_arn"
  },
  {
    "table": "aws_ecs_task_definition",
    "columns": [
      "account_id",
      "container_definitions",
      "network_mode",
      "pid_mode",
      "region",
      "task_definition_arn",
      "title"
    ],
    "id_column": "task_definition_arn"
  },
  {
    "table": "aws_ecs_service",
    "columns": [
      "account_id",
      "arn",
      "cluster_arn",
      "launch_type",
      "network_configuration",
      "platform_version",
      "region",
      "service_name",
      "task_definition",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_ecs_cluster",
    "columns": [
      "account_id",
      "region",
      "settings",
      "title",
      "cluster_arn"
    ],
    "id_column": "cluster_arn"
  },
  {
    "table": "aws_efs_access_point",
    "columns": [
      "access_point_arn",
      "account_id",
      "posix_user",
      "region",
      "root_directory",
      "title"
    ],
    "id_column": "access_point_arn"
  },
  {
    "table": "aws_eks_cluster",
    "columns": [
      "account_id",
      "arn",
      "encryption_config",
      "endpoint",
      "region",
      "resources_vpc_config",
      "status",
      "title",
      "version"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_elasticache_replication_group",
    "columns": [
      "account_id",
      "arn",
      "at_rest_encryption_enabled",
      "auth_token_enabled",
      "automatic_failover",
      "region",
      "replication_group_id",
      "snapshot_retention_limit",
      "title",
      "transit_encryption_enabled"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_elasticache_cluster",
    "columns": [
      "account_id",
      "arn",
      "auto_minor_version_upgrade",
      "cache_subnet_group_name",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_elastic_beanstalk_environment",
    "columns": [
      "account_id",
      "application_name",
      "arn",
      "health",
      "health_status",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_emr_cluster",
    "columns": [
      "account_id",
      "cluster_arn",
      "ec2_instance_attributes",
      "kerberos_attributes",
      "region",
      "status",
      "title"
    ],
    "id_column": "cluster_arn"
  },
  {
    "table": "aws_guardduty_detector",
    "columns": [
      "account_id",
      "arn",
      "master_account",
      "region",
      "status",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_kinesis_stream",
    "columns": [
      "account_id",
      "encryption_type",
      "region",
      "title",
      "stream_arn"
    ],
    "id_column": "stream_arn"
  },
  {
    "table": "aws_lambda_function",
    "columns": [
      "account_id",
      "arn",
      "dead_letter_config_target_arn",
      "package_type",
      "region",
      "reserved_concurrent_executions",
      "runtime",
      "title",
      "vpc_id",
      "vpc_subnet_ids"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_networkfirewall_firewall_policy",
    "columns": [
      "account_id",
      "arn",
      "firewall_policy",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_networkfirewall_rule_group",
    "columns": [
      "account_id",
      "arn",
      "region",
      "rules_source",
      "title",
      "type"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_opensearch_domain",
    "columns": [
      "account_id",
      "advanced_security_options",
      "arn",
      "cluster_config",
      "domain_endpoint_options",
      "domain_id",
      "domain_name",
      "encryption_at_rest_options",
      "log_publishing_options",
      "node_to_node_encryption_options_enabled",
      "region",
      "title",
      "vpc_options"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_ec2_network_load_balancer",
    "columns": [
      "_ctx",
      "account_id",
      "arn",
      "availability_zones",
      "region",
      "scheme",
      "security_groups",
      "tags",
      "title",
      "vpc_id"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_ec2_gateway_load_balancer",
    "columns": [
      "account_id",
      "arn",
      "availability_zones",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_rds_db_cluster",
    "columns": [
      "account_id",
      "arn",
      "backtrack_window",
      "copy_tags_to_snapshot",
      "db_cluster_identifier",
      "deletion_protection",
      "enabled_cloudwatch_logs_exports",
      "engine",
      "iam_database_authentication_enabled",
      "master_user_name",
      "members",
      "multi_az",
      "port",
      "region",
      "tags",
      "title",
      "vpc_security_groups"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_rds_db_event_subscription",
    "columns": [
      "account_id",
      "arn",
      "cust_subscription_id",
      "enabled",
      "event_categories_list",
      "region",
      "source_type",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_secretsmanager_secret",
    "columns": [
      "account_id",
      "arn",
      "created_date",
      "kms_key_id",
      "last_accessed_date",
      "last_changed_date",
      "last_rotated_date",
      "primary_region",
      "region",
      "rotation_lambda_arn",
      "rotation_rules",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_sqs_queue",
    "columns": [
      "account_id",
      "kms_master_key_id",
      "queue_arn",
      "region",
      "title"
    ],
    "id_column": "queue_arn"
  },
  {
    "table": "aws_ssm_managed_instance",
    "columns": [
      "arn",
      "instance_id",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_waf_web_acl",
    "columns": [
      "account_id",
      "arn",
      "logging_configuration",
      "region",
      "rules",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_wafregional_rule",
    "columns": [
      "account_id",
      "arn",
      "predicates",
      "region",
      "rule_id",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_wafregional_rule_group",
    "columns": [
      "account_id",
      "activated_rules",
      "arn",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_wafregional_web_acl",
    "columns": [
      "account_id",
      "arn",
      "region",
      "resources",
      "rules",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_waf_rule",
    "columns": [
      "account_id",
      "predicates",
      "region",
      "rule_id",
      "title"
    ],
    "id_column": "rule_id"
  },
  {
    "table": "aws_waf_rule_group",
    "columns": [
      "account_id",
      "activated_rules",
      "arn",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_vpc_internet_gateway",
    "columns": [
      "account_id",
      "attachments",
      "partition",
      "region",
      "title"
    ],
    "id_column": "title"
  },
  {
    "table": "aws_iam_group",
    "columns": [
      "account_id",
      "arn",
      "region",
      "title",
      "users"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_cloudwatch_alarm",
    "columns": [
      "account_id",
      "actions_enabled",
      "alarm_actions",
      "arn",
      "insufficient_data_actions",
      "ok_actions",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_guardduty_finding",
    "columns": [
      "account_id",
      "arn",
      "region",
      "service",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_backup_plan",
    "columns": [
      "account_id",
      "arn",
      "backup_plan",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_backup_recovery_point",
    "columns": [
      "account_id",
      "is_encrypted",
      "lifecycle",
      "recovery_point_arn",
      "region"
    ],
    "id_column": "recovery_point_arn"
  },
  {
    "table": "aws_backup_vault",
    "columns": [
      "account_id",
      "arn",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_backup_protected_resource",
    "columns": [
      "region",
      "resource_arn",
      "resource_type"
    ],
    "id_column": "resource_arn"
  },
  {
    "table": "aws_backup_selection",
    "columns": [
      "arn",
      "backup_plan_id",
      "list_of_tags",
      "region",
      "resources",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_fsx_file_system",
    "columns": [
      "account_id",
      "arn",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_vpc_route_table",
    "columns": [
      "account_id",
      "region",
      "route_table_id",
      "routes",
      "title"
    ],
    "id_column": "route_table_id"
  },
  {
    "table": "aws_vpc_eip",
    "columns": [
      "account_id",
      "allocation_id",
      "arn",
      "association_id",
      "partition",
      "region",
      "title"
    ],
    "id_column": "arn"
  },
  {
    "table": "aws_codedeploy_app",
    "columns": [
      "application_name",
      "arn",
      "compute_platform",
      "region",
      "title"
    ],
    "id_column": "arn"
  }
]`
)

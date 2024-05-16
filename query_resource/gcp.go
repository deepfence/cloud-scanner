package query_resource

var (
	gcpCloudTablesJson = `[
  {
    "table": "gcp_kms_key",
    "columns": [
      "key_ring_name",
      "location",
      "name",
      "project",
      "rotation_period",
      "self_link",
      "title"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_sql_database_instance",
    "columns": [
      "backend_type",
      "backup_enabled",
      "database_flags",
      "database_version",
      "instance_type",
      "instance_users",
      "ip_addresses",
      "ip_configuration",
      "ipv6_address",
      "location",
      "machine_type",
      "name",
      "project",
      "self_link",
      "state",
      "title"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_service_account_key",
    "columns": [
      "key_type",
      "location",
      "name",
      "project",
      "service_account_name",
      "valid_after_time"
    ],
    "id_column": "service_account_name"
  },
  {
    "table": "gcp_iam_policy",
    "columns": [
      "_ctx",
      "bindings",
      "location",
      "project",
      "title",
      "version"
    ],
    "id_column": "title"
  },
  {
    "table": "gcp_bigquery_dataset",
    "columns": [
      "access",
      "dataset_id",
      "kms_key_name",
      "location",
      "name",
      "project",
      "self_link",
      "self_link",
      "title"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_compute_firewall",
    "columns": [
      "action",
      "allowed",
      "description",
      "direction",
      "disabled",
      "location",
      "name",
      "network",
      "priority",
      "project",
      "self_link",
      "source_ranges",
      "title"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_project",
    "columns": [
      "create_time",
      "lifecycle_state",
      "name",
      "project_id",
      "project_number"
    ],
    "id_column": "project_id"
  },
  {
    "table": "gcp_service_account",
    "columns": [
      "display_name",
      "email",
      "location",
      "name",
      "project",
      "title",
      "unique_id"
    ],
    "id_column": "unique_id"
  },
  {
    "table": "gcp_organization",
    "columns": [
      "_ctx",
      "display_name",
      "name",
      "organization_id",
      "title"
    ],
    "id_column": "organization_id"
  },
  {
    "table": "gcp_dataproc_cluster",
    "columns": [
      "cluster_name",
      "config",
      "location",
      "project",
      "self_link",
      "title"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_audit_policy",
    "columns": [
      "_ctx",
      "audit_log_configs",
      "location",
      "project",
      "service"
    ],
    "id_column": "service"
  },
  {
    "table": "gcp_logging_sink",
    "columns": [
      "destination",
      "filter",
      "location",
      "name",
      "project",
      "self_link",
      "self_link",
      "title"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_logging_metric",
    "columns": [
      "filter",
      "location",
      "metric_descriptor_type",
      "name"
    ],
    "id_column": "name"
  },
  {
    "table": "gcp_compute_network",
    "columns": [
      "description",
      "gateway_ipv4",
      "ipv4_range",
      "location",
      "mtu",
      "name",
      "project",
      "routing_mode",
      "self_link",
      "title"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_project_service",
    "columns": [
      "location",
      "name",
      "project",
      "state"
    ],
    "id_column": "name"
  },
  {
    "table": "gcp_dns_policy",
    "columns": [
      "enable_logging",
      "location",
      "name",
      "networks"
    ],
    "id_column": "name"
  },
  {
    "table": "gcp_dns_managed_zone",
    "columns": [
      "dnssec_config_default_key_specs",
      "dnssec_config_state",
      "location",
      "name",
      "project",
      "self_link",
      "self_link",
      "title",
      "visibility"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_compute_subnetwork",
    "columns": [
      "description",
      "enable_flow_logs",
      "gateway_address",
      "ip_cidr_range",
      "ipv6_cidr_range",
      "location",
      "name",
      "network",
      "private_ip_google_access",
      "project",
      "self_link",
      "state",
      "title"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_compute_target_ssl_proxy",
    "columns": [
      "_ctx",
      "kind",
      "location",
      "name",
      "project",
      "self_link",
      "ssl_policy",
      "title"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_compute_instance",
    "columns": [
      "can_ip_forward",
      "confidential_instance_config",
      "cpu_platform",
      "iam_policy",
      "labels",
      "location",
      "machine_type_name",
      "metadata",
      "name",
      "network_interfaces",
      "project",
      "self_link",
      "service_accounts",
      "shielded_instance_config",
      "tags",
      "title"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_compute_target_https_proxy",
    "columns": [
      "_ctx",
      "kind",
      "location",
      "name",
      "project",
      "self_link",
      "ssl_policy",
      "title"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_compute_disk",
    "columns": [
      "disk_encryption_key_type",
      "location",
      "location_type",
      "name",
      "project",
      "self_link",
      "size_gb",
      "status",
      "title",
      "type_name"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_storage_bucket",
    "columns": [
      "iam_configuration_bucket_policy_only_enabled",
      "iam_configuration_uniform_bucket_level_access_enabled",
      "iam_policy",
      "id",
      "location",
      "log_bucket",
      "name",
      "project",
      "self_link",
      "storage_class",
      "title",
      "versioning_enabled"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_compute_project_metadata",
    "columns": [
      "common_instance_metadata",
      "location",
      "name",
      "project",
      "self_link"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_bigquery_table",
    "columns": [
      "kms_key_name",
      "location",
      "name",
      "project",
      "self_link",
      "self_link",
      "title"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_compute_url_map",
    "columns": [
      "default_service",
      "location",
      "name",
      "project",
      "self_link",
      "self_link"
    ],
    "id_column": "self_link"
  },
  {
    "table": "gcp_kubernetes_cluster",
    "columns": [
      "addons_config",
      "ip_allocation_policy",
      "legacy_abac_enabled",
      "location",
      "master_authorized_networks_config",
      "name",
      "node_config",
      "node_pools",
      "private_cluster_config",
      "project",
      "self_link",
      "self_link",
      "title"
    ],
    "id_column": "self_link"
  }
]`
)

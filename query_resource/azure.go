package query_resource

var (
	azureCloudTablesJson = `[
  {
    "table": "azuread_user",
    "columns": [
      "account_enabled",
      "created_date_time",
      "display_name",
      "id",
      "tenant_id",
      "user_principal_name",
      "user_type"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_subscription",
    "columns": [
      "_ctx",
      "display_name",
      "id",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azuread_authorization_policy",
    "columns": [
      "default_user_role_permissions",
      "display_name",
      "id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_security_center_subscription_pricing",
    "columns": [
      "id",
      "name",
      "pricing_tier",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azuread_conditional_access_policy",
    "columns": [
      "built_in_controls",
      "display_name",
      "id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_tenant",
    "columns": [
      "id",
      "name",
      "tenant_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_role_definition",
    "columns": [
      "_ctx",
      "id",
      "name",
      "permissions",
      "role_name",
      "role_type",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_security_center_auto_provisioning",
    "columns": [
      "auto_provision",
      "id",
      "name",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_security_center_contact",
    "columns": [
      "alert_notifications",
      "alerts_to_admins",
      "email",
      "id",
      "name",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_security_center_setting",
    "columns": [
      "enabled",
      "id",
      "name",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_storage_account",
    "columns": [
      "allow_blob_public_access",
      "blob_service_logging",
      "blob_soft_delete_enabled",
      "enable_https_traffic_only",
      "encryption_key_source",
      "encryption_scope",
      "id",
      "minimum_tls_version",
      "name",
      "network_rule_bypass",
      "network_rule_default_action",
      "primary_location",
      "private_endpoint_connections",
      "queue_logging_delete",
      "queue_logging_read",
      "queue_logging_write",
      "region",
      "require_infrastructure_encryption",
      "resource_group",
      "secondary_location",
      "sku_name",
      "subscription_id",
      "table_logging_delete",
      "table_logging_read",
      "table_logging_write",
      "title",
      "virtual_network_rules"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_storage_container",
    "columns": [
      "account_name",
      "id",
      "name",
      "public_access",
      "resource_group",
      "subscription_id",
      "type"
    ],
    "id_column": "name"
  },
  {
    "table": "azure_sql_server",
    "columns": [
      "encryption_protector",
      "firewall_rules",
      "id",
      "kind",
      "name",
      "public_network_access",
      "region",
      "resource_group",
      "server_audit_policy",
      "server_azure_ad_administrator",
      "server_security_alert_policy",
      "server_vulnerability_assessment",
      "subscription_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_sql_database",
    "columns": [
      "database_id",
      "id",
      "name",
      "region",
      "resource_group",
      "retention_policy_property",
      "subscription_id",
      "title",
      "transparent_data_encryption"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_postgresql_server",
    "columns": [
      "geo_redundant_backup",
      "id",
      "infrastructure_encryption",
      "name",
      "private_endpoint_connections",
      "public_network_access",
      "region",
      "resource_group",
      "server_configurations",
      "sku_tier",
      "ssl_enforcement",
      "subscription_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_mysql_server",
    "columns": [
      "geo_redundant_backup",
      "id",
      "infrastructure_encryption",
      "location",
      "minimal_tls_version",
      "name",
      "private_endpoint_connections",
      "public_network_access",
      "region",
      "resource_group",
      "server_configurations",
      "sku_tier",
      "ssl_enforcement",
      "subscription_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_cosmosdb_account",
    "columns": [
      "id",
      "ip_rules",
      "is_virtual_network_filter_enabled",
      "key_vault_key_uri",
      "name",
      "public_network_access",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_diagnostic_setting",
    "columns": [
      "_ctx",
      "id",
      "logs",
      "name",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_key_vault",
    "columns": [
      "diagnostic_settings",
      "enable_rbac_authorization",
      "id",
      "name",
      "network_acls",
      "private_endpoint_connections",
      "purge_protection_enabled",
      "region",
      "resource_group",
      "soft_delete_enabled",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_log_alert",
    "columns": [
      "condition",
      "enabled",
      "id",
      "location",
      "name",
      "region",
      "scopes",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_network_security_group",
    "columns": [
      "default_security_rules",
      "diagnostic_settings",
      "id",
      "name",
      "network_interfaces",
      "region",
      "resource_group",
      "resource_guid",
      "security_rules",
      "subnets",
      "subscription_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_location",
    "columns": [
      "id",
      "name",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_network_watcher",
    "columns": [
      "id",
      "name",
      "region",
      "resource_group"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_compute_virtual_machine",
    "columns": [
      "enable_automatic_updates",
      "extensions",
      "guest_configuration_assignments",
      "id",
      "identity",
      "managed_disk_id",
      "name",
      "network_interfaces",
      "os_type",
      "private_ips",
      "public_ips",
      "region",
      "resource_group",
      "security_profile",
      "size",
      "subscription_id",
      "tags",
      "title",
      "vm_id"
    ],
    "id_column": "vm_id"
  },
  {
    "table": "azure_compute_disk",
    "columns": [
      "disk_state",
      "encryption_type",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_network_watcher_flow_log",
    "columns": [
      "enabled",
      "id",
      "name",
      "region",
      "retention_policy_days",
      "target_resource_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_key_vault_key",
    "columns": [
      "enabled",
      "expires_at",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id",
      "vault_name"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_key_vault_secret",
    "columns": [
      "created_at",
      "enabled",
      "expires_at",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id",
      "updated_at",
      "value",
      "vault_name"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_app_service_web_app",
    "columns": [
      "auth_settings",
      "client_affinity_enabled",
      "client_cert_enabled",
      "configuration",
      "host_names",
      "https_only",
      "id",
      "identity",
      "kind",
      "name",
      "outbound_ip_addresses",
      "region",
      "resource_group",
      "state",
      "subscription_id",
      "title",
      "vnet_connection"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_app_service_function_app",
    "columns": [
      "client_cert_enabled",
      "configuration",
      "host_names",
      "https_only",
      "id",
      "kind",
      "name",
      "outbound_ip_addresses",
      "region",
      "reserved",
      "resource_group",
      "subscription_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_automation_variable",
    "columns": [
      "id",
      "is_encrypted",
      "name",
      "resource_group",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_redis_cache",
    "columns": [
      "enable_non_ssl_port",
      "id",
      "name",
      "region",
      "resource_group",
      "sku_name",
      "subnet_id",
      "subscription_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_service_fabric_cluster",
    "columns": [
      "azure_active_directory",
      "fabric_settings",
      "id",
      "name",
      "region",
      "resource_group"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_role_assignment",
    "columns": [
      "id",
      "name",
      "principal_id",
      "role_definition_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_policy_assignment",
    "columns": [
      "id",
      "name",
      "parameters",
      "policy_definition_id",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_cognitive_account",
    "columns": [
      "disable_local_auth",
      "encryption",
      "id",
      "name",
      "private_endpoint_connections",
      "public_network_access",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_security_center_jit_network_access_policy",
    "columns": [
      "id",
      "name",
      "subscription_id",
      "virtual_machines"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_kubernetes_cluster",
    "columns": [
      "addon_profiles",
      "api_server_access_profile",
      "disk_encryption_set_id",
      "enable_rbac",
      "id",
      "kubernetes_version",
      "name",
      "network_profile",
      "region",
      "resource_group",
      "subscription_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_api_management",
    "columns": [
      "id",
      "name",
      "region",
      "resource_group",
      "virtual_network_type"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_app_configuration",
    "columns": [
      "id",
      "name",
      "private_endpoint_connections",
      "public_network_access",
      "region",
      "resource_group",
      "sku_name"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_compute_disk_access",
    "columns": [
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_container_registry",
    "columns": [
      "data_endpoint_host_names",
      "encryption",
      "id",
      "login_credentials",
      "login_server",
      "name",
      "network_rule_set",
      "policies",
      "private_endpoint_connections",
      "public_network_access",
      "region",
      "resource_group",
      "subscription_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_data_factory",
    "columns": [
      "encryption",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_eventgrid_domain",
    "columns": [
      "id",
      "name",
      "private_endpoint_connections",
      "public_network_access",
      "region",
      "resource_group"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_eventgrid_topic",
    "columns": [
      "id",
      "name",
      "private_endpoint_connections",
      "public_network_access",
      "region",
      "resource_group"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_eventhub_namespace",
    "columns": [
      "diagnostic_settings",
      "id",
      "name",
      "region",
      "resource_group",
      "sku_tier",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_healthcare_service",
    "columns": [
      "cosmos_db_configuration",
      "id",
      "name",
      "private_endpoint_connections",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_mariadb_server",
    "columns": [
      "geo_redundant_backup_enabled",
      "id",
      "name",
      "public_network_access",
      "region",
      "resource_group",
      "subscription_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_search_service",
    "columns": [
      "diagnostic_settings",
      "id",
      "name",
      "public_network_access",
      "region",
      "resource_group",
      "sku_name",
      "subscription_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_servicebus_namespace",
    "columns": [
      "diagnostic_settings",
      "encryption",
      "id",
      "name",
      "private_endpoint_connections",
      "region",
      "resource_group",
      "servicebus_endpoint",
      "sku_name",
      "sku_tier",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_signalr_service",
    "columns": [
      "id",
      "name",
      "region",
      "resource_group",
      "sku",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_network_interface",
    "columns": [
      "enable_ip_forwarding",
      "hosted_workloads",
      "id",
      "ip_configurations",
      "is_primary",
      "mac_address",
      "name",
      "region",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_storage_sync",
    "columns": [
      "id",
      "incoming_traffic_policy",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_synapse_workspace",
    "columns": [
      "connectivity_endpoints",
      "default_data_lake_storage",
      "encryption",
      "id",
      "managed_resource_group_name",
      "managed_virtual_network",
      "managed_virtual_network_settings",
      "name",
      "private_endpoint_connections",
      "public_network_access",
      "region",
      "resource_group",
      "subscription_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_spring_cloud_service",
    "columns": [
      "id",
      "name",
      "network_profile",
      "region",
      "resource_group",
      "sku_tier",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_hybrid_compute_machine",
    "columns": [
      "id",
      "name",
      "os_name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_batch_account",
    "columns": [
      "diagnostic_settings",
      "encryption",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_compute_virtual_machine_scale_set",
    "columns": [
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id",
      "title",
      "virtual_machine_security_profile"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_data_lake_analytics_account",
    "columns": [
      "account_id",
      "diagnostic_settings",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_data_lake_store",
    "columns": [
      "account_id",
      "diagnostic_settings",
      "encryption_state",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_iothub",
    "columns": [
      "diagnostic_settings",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_logic_app_workflow",
    "columns": [
      "diagnostic_settings",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_stream_analytics_job",
    "columns": [
      "diagnostic_settings",
      "id",
      "job_id",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_resource_link",
    "columns": [
      "id",
      "name",
      "source_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_mssql_managed_instance",
    "columns": [
      "id",
      "name",
      "public_data_endpoint_enabled",
      "region",
      "resource_group",
      "security_alert_policies",
      "state",
      "subnet_id",
      "subscription_id",
      "title",
      "type"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_application_gateway",
    "columns": [
      "gateway_ip_configurations",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id",
      "web_application_firewall_configuration"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_frontdoor",
    "columns": [
      "front_door_id",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_virtual_network",
    "columns": [
      "address_prefixes",
      "enable_ddos_protection",
      "id",
      "name",
      "network_peerings",
      "region",
      "resource_group",
      "subnets",
      "subscription_id",
      "title",
      "type"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_hdinsight_cluster",
    "columns": [
      "cluster_definition",
      "cluster_id",
      "cluster_state",
      "compute_profile",
      "connectivity_endpoints",
      "disk_encryption_properties",
      "encryption_in_transit_properties",
      "id",
      "name",
      "provisioning_state",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_hpc_cache",
    "columns": [
      "encryption_settings",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_kusto_cluster",
    "columns": [
      "enable_disk_encryption",
      "enable_double_encryption",
      "id",
      "key_vault_properties",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_machine_learning_workspace",
    "columns": [
      "encryption",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_app_service_environment",
    "columns": [
      "cluster_settings",
      "id",
      "is_healthy_environment",
      "name",
      "provisioning_state",
      "region",
      "resource_group",
      "subscription_id",
      "title",
      "vnet_resource_group_name"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_databox_edge_device",
    "columns": [
      "id",
      "name",
      "region",
      "resource_group",
      "sku_name",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_application_insight",
    "columns": [
      "id",
      "name",
      "region",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_lb",
    "columns": [
      "id",
      "name",
      "region",
      "resource_group",
      "sku_name",
      "subscription_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_public_ip",
    "columns": [
      "id",
      "name",
      "region",
      "resource_group",
      "sku_name",
      "subscription_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_virtual_network_gateway",
    "columns": [
      "id",
      "name",
      "region",
      "resource_group",
      "sku_name",
      "subscription_id",
      "title"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_bastion_host",
    "columns": [
      "_ctx",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_key_vault_managed_hardware_security_module",
    "columns": [
      "diagnostic_settings",
      "enable_purge_protection",
      "id",
      "name",
      "region",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_log_profile",
    "columns": [
      "categories",
      "id",
      "log_event_location",
      "name",
      "region",
      "resource_group",
      "storage_account_id",
      "subscription_id"
    ],
    "id_column": "id"
  },
  {
    "table": "azure_subnet",
    "columns": [
      "service_endpoints",
      "id",
      "name",
      "network_security_group_id",
      "resource_group",
      "subscription_id"
    ],
    "id_column": "id"
  }
]`
)

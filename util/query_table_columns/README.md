# Extract tables from steampipe

- Extract all required tables (cloud resource types) and their columns from steampipe logs
- Set steampipe log level as trace in `~/.steampipe/config/default.spc`
- Then run compliance check on required benchmarks
```shell
steampipe check benchmark.cis_v300
steampipe check benchmark.pci_dss_v321
# etc.,
```
- Run the following command to parse only the required cloud resource types (tables) and fields (columns)
```shell
python3 extract_cloud_resource_types.py
```
- Run the following command to format the json after merging extra columns from old tables into new tables
```shell
python3 format_cloud_resource_types.py
```
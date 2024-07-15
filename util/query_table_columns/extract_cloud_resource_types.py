import json
import os
from collections import defaultdict
from pathlib import Path

cloud_provider = "aws"
required_columns = {
    "aws": ["arn", "title", "region"],
    "gcp": ["self_link", "name", "location"],
    "azure": ["name", "id", "region"]
}
search_text = "Got query context, table: " + cloud_provider
cloud_table = defaultdict(list)

if __name__ == '__main__':
    for file_name in os.listdir(str(Path.home()) + '/.steampipe/logs/'):
        if not file_name.startswith("plugin-"):
            continue
        with open(str(Path.home()) + '/.steampipe/logs/' + file_name, 'r') as in_file:
            for line in in_file:
                if search_text in line:
                    a = line.split("Got query context, table: ")
                    table_name = a[1].split(",")[0]
                    cols = a[1].split(",")[1].strip("").replace("]\n", "").replace("cols: [", "")
                    cloud_table[table_name].extend([i for i in cols.split(" ") if i])

for k, v in cloud_table.items():
    new_v = list(set(v + required_columns[cloud_provider]))
    new_v.sort()
    cloud_table[k] = new_v

Path("cloud_resource_tables.json").write_text(json.dumps(cloud_table))

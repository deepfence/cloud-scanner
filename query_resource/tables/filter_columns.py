import json
import os
from collections import defaultdict
from pathlib import Path

cloud_table = defaultdict(list)

cloud_provider = "aws"
search_text = "Got query context, table: " + cloud_provider

if __name__ == '__main__':
    for file_name in os.listdir(str(Path.home()) + '/.steampipe/logs/'):
        if not file_name.startswith("plugin-"):
            continue
        with open(str(Path.home()) + '/.steampipe/logs/' + file_name, 'r') as in_file:
            for line in in_file:
                if search_text in line:
                    a = line.split("Got query context, table: ")
                    table_name = a[1].split(",")[0]
                    cols = a[1].split(",")[1].strip("cols: [").strip("]\n")
                    cloud_table[table_name].extend(cols.split(" "))

required_columns = ["arn", "title", "region"]
# gcp_required_columns = ["self_link", "name", "location"]
# azure_required_columns = ["name", "id", "region"]
for k, v in cloud_table.items():
    new_v = list(set(v + required_columns))
    new_v.sort()
    cloud_table[k] = new_v

print(json.dumps(cloud_table))

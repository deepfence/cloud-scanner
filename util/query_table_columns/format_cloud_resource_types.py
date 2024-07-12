import json

# Copy the tables json from here to `current_table_json` variable
# https://github.com/deepfence/cloud-scanner/blob/main/query_resource/aws.go#L4
current_table_json = json.loads("""[]""")
current_table = {i["table"]: i["columns"] for i in current_table_json}
current_id_column = {i["table"]: i.get("id_column", "arn") for i in current_table_json}

new_tables = []

if __name__ == '__main__':
    with open("cloud_resource_tables.json", 'r') as small_file:
        small = json.load(small_file)
        for k, v in small.items():
            if k in current_table:
                merge = list(set(current_table[k]+v))
                merge.sort()
                new_tables.append(
                    {
                        "table": k,
                        "columns": merge,
                        "id_column": current_id_column[k]
                    }
                )
            else:
                v.sort()
                for i in v:
                    if i == "arn":
                        id_column = i
                        break
                if id_column == "":
                    print(k, v)
                new_tables.append(
                    {
                        "table": k,
                        "columns": v,
                        "id_column": id_column
                    }
                )

    new_tables = sorted(new_tables, key=lambda x: x["table"])
    print(json.dumps(new_tables))

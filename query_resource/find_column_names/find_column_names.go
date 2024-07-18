package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/deepfence/cloud-scanner/query_resource"
)

func queryResources(cloudProvider string, cloudResourceInfo query_resource.CloudResourceInfo) {
	query := "steampipe query --output json \"select \\\"" + strings.Join(cloudResourceInfo.Columns[:], "\\\" , \\\"") + "\\\" from " + cloudProvider + "." + cloudResourceInfo.Table + " \""
	var stdOut []byte
	var stdErr error
	stdOut, stdErr = exec.Command("bash", "-c", query).CombinedOutput()
	if stdErr != nil {
		if strings.Contains(string(stdOut), "does not exist") {
			fmt.Println(query)

			findColumnsquery := "steampipe query \"select * from " + cloudProvider + "." + cloudResourceInfo.Table + " where false\" --output csv"
			stdOut2, stdErr2 := exec.Command("bash", "-c", findColumnsquery).CombinedOutput()
			fmt.Println(string(stdOut2))
			if stdErr2 != nil {
				fmt.Println(stdErr2.Error())
			}
		}
		fmt.Println(string(stdOut), stdErr.Error())
		fmt.Println("-------------------")
	}
}

func queryResourceTest(cloudProvider string, cloudResourceTableJson string) {
	var cloudResourceTables []query_resource.CloudResourceInfo
	err := json.Unmarshal([]byte(cloudResourceTableJson), &cloudResourceTables)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	for _, cloudResourceTable := range cloudResourceTables {
		queryResources(cloudProvider, cloudResourceTable)
	}
}

func main() {
	queryResourceTest("aws", query_resource.AWSCloudTablesJson)
	//queryResourceTest("gcp", query_resource.GCPCloudTablesJson)
	//queryResourceTest("azure", query_resource.AzureCloudTablesJson)
	//queryResourceTest("azuread", query_resource.AzureADCloudTablesJson)
}

package query_resource

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	cloud_metadata "github.com/deepfence/cloud-scanner/cloud-metadata"
	"github.com/deepfence/cloud-scanner/internal/deepfence"
	"github.com/deepfence/cloud-scanner/util"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog/log"
)

type CloudResourceInfo struct {
	Table    string   `json:"table,omitempty"`
	Columns  []string `json:"columns,omitempty"`
	IdColumn string   `json:"id_column,omitempty"`
}

var (
	cloudProviderToResourceMap = map[string][]CloudResourceInfo{}
	chunkSize                  = 1000
)

func init() {
	var awsCloudTables []CloudResourceInfo
	err := json.Unmarshal([]byte(awsCloudTablesJson), &awsCloudTables)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cloudProviderToResourceMap[util.CloudProviderAWS] = awsCloudTables

	var gcpCloudTables []CloudResourceInfo
	err = json.Unmarshal([]byte(gcpCloudTablesJson), &gcpCloudTables)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cloudProviderToResourceMap[util.CloudProviderGCP] = gcpCloudTables

	var azureCloudTables []CloudResourceInfo
	err = json.Unmarshal([]byte(azureCloudTablesJson), &azureCloudTables)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cloudProviderToResourceMap[util.CloudProviderAzure] = azureCloudTables
}

const (
	Ec2DnsSuffix1 = ".compute.amazonaws.com"
	Ec2DnsSuffix2 = ".ec2.internal"

	postgresqlCacheConnectionString = "dbname=postgresqlcache user=postgresqlcache host=127.0.0.1 port=9193 sslmode=disable"
)

func clearPostgresqlCache() error {
	db, err := sql.Open("postgres", postgresqlCacheConnectionString)
	if err != nil {
		return err
	}
	if _, err = db.Exec(`TRUNCATE TABLE postgresqlcache`); err != nil {
		return err
	}
	return nil
}

func QueryAndRegisterResources(config util.Config, client *deepfence.Client) []error {
	err := clearPostgresqlCache()
	if err != nil {
		log.Warn().Msgf("failed to clear postgresql cache: " + err.Error())
	}
	log.Info().Msg("QueryAndRegisterResources after clearPostgresqlCache")
	var accountsToScan []string
	if len(config.MultipleAccountIds) > 0 {
		accountsToScan = config.MultipleAccountIds
	}
	if !util.InSlice(config.CloudMetadata.ID, accountsToScan) {
		accountsToScan = append(accountsToScan, config.CloudMetadata.ID)
	}
	log.Info().Msgf("Started querying resources for %s: %v", config.CloudProvider, accountsToScan)
	count := 0
	var errors = make([]error, 0)
	for _, accountId := range accountsToScan {
		for _, cloudResourceInfo := range cloudProviderToResourceMap[config.CloudProvider] {
			cloudResourceChunks := queryResources(accountId, cloudResourceInfo, config, chunkSize)
			for _, cloudResourceChunk := range cloudResourceChunks {
				count += len(cloudResourceChunk)
				err = client.RegisterCloudResources(cloudResourceChunk)
				if err != nil {
					errors = append(errors, err)
				}
			}
		}
	}
	log.Info().Msgf("Cloud resources ingested: %d", count)
	return errors
}

func clearPostgresqlCacheRows(keyPrefix string) error {
	db, err := sql.Open("postgres", postgresqlCacheConnectionString)
	if err != nil {
		return err
	}
	if _, err = db.Exec(`DELETE FROM TABLE postgresqlcache WHERE key LIKE '` + keyPrefix + `%'`); err != nil {
		return err
	}
	return nil
}

func QueryAndUpdateResources(config util.Config, client *deepfence.Client, cloudResourceTypesToRefresh map[string][]string) []error {
	log.Info().Msgf("Started querying updated resources for %s", config.CloudProvider)
	count := 0
	var errors = make([]error, 0)
	var err error
	for accountID, resourceTypesToRefresh := range cloudResourceTypesToRefresh {
		accountIDPrefix := ""
		if accountID != config.CloudMetadata.ID {
			accountIDPrefix = config.CloudProvider + "_" + accountID + "."
		}

		for _, cloudResourceInfo := range cloudProviderToResourceMap[config.CloudProvider] {
			if !util.InSlice(cloudResourceInfo.Table, resourceTypesToRefresh) {
				continue
			}
			err = clearPostgresqlCacheRows(accountIDPrefix + cloudResourceInfo.Table)
			if err != nil {
				errors = append(errors, err)
				continue
			}
			cloudResourceChunks := queryResources(accountID, cloudResourceInfo, config, chunkSize)
			for _, cloudResourceChunk := range cloudResourceChunks {
				count += len(cloudResourceChunk)
				err = client.RegisterCloudResources(cloudResourceChunk)
				if err != nil {
					errors = append(errors, err)
				}
			}
		}
	}

	log.Info().Msgf("Cloud resources ingested: %d", count)
	return errors
}

func queryResources(accountId string, cloudResourceInfo CloudResourceInfo, config util.Config, chunkSize int) [][]map[string]interface{} {
	var cloudResourceChunks = make([][]map[string]interface{}, 0)
	var cloudResources = make([]map[string]interface{}, 0)

	log.Debug().Msgf("Querying resources for %s", cloudResourceInfo.Table)
	query := "steampipe query --output json \"select \\\"" + strings.Join(cloudResourceInfo.Columns[:], "\\\" , \\\"") + "\\\" from " + cloudResourceInfo.Table + " \""
	if accountId != config.CloudMetadata.ID {
		query = "steampipe query --output json \"select \\\"" + strings.Join(cloudResourceInfo.Columns[:], "\\\" , \\\"") + "\\\" from aws_" + accountId + "." + cloudResourceInfo.Table + " \""
	}
	if config.CloudProvider == cloud_metadata.CloudProviderGCP && len(config.MultipleAccountIds) > 0 {
		query = "steampipe query --output json \"select \\\"" + strings.Join(cloudResourceInfo.Columns[:], "\\\" , \\\"") + "\\\" from gcp_" + strings.Replace(accountId, "-", "", -1) + "." + cloudResourceInfo.Table + " \""
	}

	var stdOut []byte
	var stdErr error
	for i := 0; i <= 3; i++ {
		stdOut, stdErr = exec.Command("bash", "-c", query).CombinedOutput()
		if stdErr != nil {
			log.Error().Msgf("Error at querying res: %v for query: %s", stdErr, query)
			log.Error().Msgf(string(stdOut))
			if strings.Contains(string(stdOut), util.ErrSteampipeDB) || strings.Contains(string(stdOut), util.ErrSteampipeInvalidClientTokenID) {
				util.RestartSteampipeService()
			} else {
				time.Sleep(util.SleepTime)
			}
			continue
		} else {
			break
		}
	}
	if stdErr != nil {
		return cloudResourceChunks
	}

	log.Trace().Msgf("Got stdout for %s: %s", cloudResourceInfo.Table, string(stdOut))
	var objMap []map[string]interface{}
	if err := json.Unmarshal(stdOut, &objMap); err != nil {
		log.Error().Msgf("Error: %v \n Steampipe Output: %s", err, string(stdOut))
		return cloudResourceChunks
	}
	log.Debug().Msgf("Got length of %d for %s", len(objMap), cloudResourceInfo.Table)

	var private_dns_name string
	for _, obj := range objMap {
		obj["account_id"] = util.GetNodeId(config.CloudProvider, accountId)
		obj["cloud_provider"] = config.CloudProvider
		if _, ok := obj["title"]; ok {
			obj["name"] = fmt.Sprint(obj["title"])
			delete(obj, "title")
		}
		if _, ok := obj[cloudResourceInfo.IdColumn]; ok {
			obj["arn"] = fmt.Sprintf("%v", obj[cloudResourceInfo.IdColumn])
		} else {
			obj["arn"] = ""
		}
		if _, ok := obj["id"]; !ok {
			obj["id"] = cloudResourceInfo.Table
		}
		if obj["id"] == "aws_ec2_instance" {
			private_dns_name = fmt.Sprintf("%v", obj["private_dns_name"])
			if private_dns_name != "" {
				private_dns_name = strings.TrimSuffix(private_dns_name, Ec2DnsSuffix1)
				private_dns_name = strings.TrimSuffix(private_dns_name, Ec2DnsSuffix2)
				obj["name"] = strings.TrimSuffix(private_dns_name, "."+fmt.Sprintf("%v", obj["region"]))
			}
		}
		obj["resource_id"] = cloudResourceInfo.Table
		if _, ok := obj["location"]; ok {
			obj["region"] = obj["location"]
			delete(obj, "location")
		}
		if obj["region"] == nil || obj["region"] == "" {
			obj["region"] = "global"
		}
		cloudResources = append(cloudResources, obj)
	}
	cloudResourceChunks = append(cloudResourceChunks, cloudResources)
	return cloudResourceChunks
}

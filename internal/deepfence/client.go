package deepfence

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"time"

	"github.com/deepfence/ThreatMapper/deepfence_utils/log"

	"github.com/deepfence/cloud-scanner/util"
	"github.com/google/uuid"

	"github.com/deepfence/golang_deepfence_sdk/client"
	oahttp "github.com/deepfence/golang_deepfence_sdk/utils/http"
)

type Client struct {
	client *oahttp.OpenapiHttpClient
	config util.Config
}

type WaitSignal struct {
	Status   string `json:"Status"`
	Reason   string `json:"Reason"`
	UniqueId string `json:"UniqueId"`
	Data     string `json:"Data"`
}

type AccessDeniedResponseError struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

func NewClient(config util.Config) (*Client, error) {
	log.Debug().Msgf("Building http client")
	client := oahttp.NewHttpsConsoleClient(config.ManagementConsoleUrl, config.ManagementConsolePort)
	err := client.APITokenAuthenticate(config.DeepfenceKey)
	if err != nil {
		return nil, err
	}
	return &Client{client: client, config: config}, nil
}

func (c *Client) GetCloudAccountsRefreshStatus() (map[string]util.RefreshMetadata, error) {
	req := c.client.Client().SearchAPI.SearchCloudAccounts(context.Background())

	searchFilter := map[string][]interface{}{"cloud_provider": {c.config.CloudProvider}}
	if c.config.IsOrganizationDeployment {
		searchFilter["organization_id"] = []interface{}{c.config.OrganizationID}
	} else {
		searchFilter["node_name"] = []interface{}{c.config.AccountID}
	}
	searchRequest := client.SearchSearchNodeReq{
		NodeFilter: client.SearchSearchFilter{
			Filters: client.ReportersFieldsFilters{
				ContainsFilter: client.ReportersContainsFilter{FilterIn: searchFilter},
			},
		},
		Window: client.ModelFetchWindow{
			Offset: 0,
			Size:   1000,
		},
	}
	req = req.SearchSearchNodeReq(searchRequest)
	log.Debug().Msgf("Fetch cloud accounts")

	accountsRefreshStatus := make(map[string]util.RefreshMetadata)
	cloudAccounts, _, err := c.client.Client().SearchAPI.SearchCloudAccountsExecute(req)
	if err != nil {
		log.Error().Msgf("Request errored on fetching cloud accounts: %s", err.Error())
		return accountsRefreshStatus, err
	}
	for _, cloudAccount := range cloudAccounts {
		refreshMetadataStr := cloudAccount.GetRefreshMetadata()
		var refreshMetadata util.RefreshMetadata
		if refreshMetadataStr != "" {
			err = json.Unmarshal([]byte(refreshMetadataStr), &refreshMetadata)
			if err != nil {
				log.Warn().Msg(err.Error())
			}
		}
		accountsRefreshStatus[cloudAccount.GetNodeName()] = refreshMetadata
	}
	log.Info().Msgf("Fetched cloud accounts")
	return accountsRefreshStatus, nil
}

func (c *Client) RegisterCloudAccount(monitoredOrganizationAccounts []util.MonitoredAccount, scheduleRefresh bool) error {
	nodeId := util.GetNodeID(c.config.CloudProvider, c.config.AccountID)

	req := c.client.Client().CloudNodesAPI.RegisterCloudNodeAccount(context.Background())
	if c.config.IsOrganizationDeployment {
		monitoredAccounts := make([]client.ModelCloudNodeMonitoredAccount, len(monitoredOrganizationAccounts))
		for i := range monitoredOrganizationAccounts {
			monitoredAccounts[i] = client.ModelCloudNodeMonitoredAccount{
				AccountId:   monitoredOrganizationAccounts[i].AccountID,
				AccountName: &monitoredOrganizationAccounts[i].AccountName,
				NodeId:      monitoredOrganizationAccounts[i].NodeID,
			}
		}

		req = req.ModelCloudNodeAccountRegisterReq(
			client.ModelCloudNodeAccountRegisterReq{
				AccountName:              &c.config.AccountName,
				AccountId:                c.config.AccountID,
				CloudProvider:            c.config.CloudProvider,
				HostNodeId:               c.config.NodeID,
				IsOrganizationDeployment: &c.config.IsOrganizationDeployment,
				MonitoredAccounts:        monitoredAccounts,
				NodeId:                   nodeId,
				OrganizationAccountId:    &c.config.OrganizationID,
				ScheduleRefresh:          &scheduleRefresh,
				Version:                  c.config.Version,
			},
		)
	} else {
		req = req.ModelCloudNodeAccountRegisterReq(
			client.ModelCloudNodeAccountRegisterReq{
				AccountName:              &c.config.AccountName,
				AccountId:                c.config.AccountID,
				CloudProvider:            c.config.CloudProvider,
				HostNodeId:               c.config.NodeID,
				IsOrganizationDeployment: &c.config.IsOrganizationDeployment,
				NodeId:                   nodeId,
				ScheduleRefresh:          &scheduleRefresh,
				Version:                  c.config.Version,
			},
		)
	}

	log.Debug().Msgf("Registering on management console")
	_, err := c.client.Client().CloudNodesAPI.RegisterCloudNodeAccountExecute(req)
	if err != nil {
		log.Error().Msgf("Request errored on registering on management console: %s", err.Error())
		return err
	}

	log.Info().Msgf("Register cloud account complete")
	return nil
}

func SendSuccessfulDeploymentSignal(successSignalUrl string) {
	httpClient, err := buildHttpClient()
	if err != nil {
		log.Error().Msgf("Unable to build http client for sending success signal for deployment: %s",
			err.Error())
	}
	retryCount := 0
	statusCode := 0
	var response []byte
	waitSignal := WaitSignal{
		Status:   "SUCCESS",
		Reason:   "Cloud Scanner Application ready",
		UniqueId: uuid.New().String(),
		Data:     "Cloud Scanner Application has been deployed.",
	}
	docBytes, err := json.Marshal(waitSignal)
	if err != nil {
		log.Error().Msgf("Unable to parse deployment success signal: %s", err.Error())
	}
	postReader := bytes.NewReader(docBytes)

	for {
		httpReq, err := http.NewRequest("PUT", successSignalUrl, postReader)
		if err != nil {
			log.Error().Msgf("Unable to http request for deployment success signal: %s", err.Error())
		}
		httpReq.Close = true
		httpReq.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(httpReq)
		if err != nil {
			log.Error().Msgf("Call for deployment success signal failed: %s", err.Error())
		}
		statusCode = resp.StatusCode
		if statusCode == 200 {
			response, err = io.ReadAll(resp.Body)
			if err != nil {
				log.Error().Msgf("Deployment success signal response cannot be parsed: %s", err.Error())
			}
			resp.Body.Close()
			break
		} else if statusCode == 403 {
			response, err = io.ReadAll(resp.Body)
			if err != nil {
				log.Error().Msgf("Deployment success signal response for 403 cannot be parsed: %s",
					err.Error())
			}
			resp.Body.Close()
			var errorResponse AccessDeniedResponseError
			err = xml.Unmarshal(response, &errorResponse)
			if err != nil {
				log.Error().Msgf("Deployment 403 access denied response XML cannot be parsed: %s", err.Error())
			}
			if errorResponse.Code == "AccessDenied" && errorResponse.Message == "Request has expired" {
				log.Info().Msgf("Expired Deployment success signal request: ")
				break
			}
		} else {
			if retryCount > 10 {
				response, err = io.ReadAll(resp.Body)
				if err != nil {
					log.Error().Msgf(err.Error())
				}
				log.Error().Msgf("Unsuccessful deployment success signal response. Got %d - %s",
					resp.StatusCode, response)
				resp.Body.Close()
				break
			}
			resp.Body.Close()
			retryCount += 1
			time.Sleep(5 * time.Second)
		}
	}

}

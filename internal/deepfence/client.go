package deepfence

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/deepfence/ThreatMapper/deepfence_utils/log"

	"github.com/deepfence/cloud-scanner/util"
	"github.com/google/uuid"

	"github.com/deepfence/golang_deepfence_sdk/client"
	oahttp "github.com/deepfence/golang_deepfence_sdk/utils/http"
)

var (
	HomeDirectory string
)

func init() {
	HomeDirectory = os.Getenv("HOME_DIR")
	if HomeDirectory == "" {
		HomeDirectory = "/home/deepfence"
	}
}

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

func (c *Client) RegisterCloudAccount(monitoredAccountIDs []string) error {
	nodeId := util.GetNodeId(c.config.CloudProvider, c.config.AccountID)

	req := c.client.Client().CloudNodesAPI.RegisterCloudNodeAccount(context.Background())
	if c.config.IsOrganizationDeployment {
		monitoredAccounts := map[string]string{}
		for _, accountID := range monitoredAccountIDs {
			monitoredAccounts[accountID] = util.GetNodeId(c.config.CloudProvider, accountID)
		}

		req = req.ModelCloudNodeAccountRegisterReq(
			client.ModelCloudNodeAccountRegisterReq{
				AccountId:                c.config.AccountID,
				CloudProvider:            c.config.CloudProvider,
				HostNodeId:               c.config.NodeID,
				IsOrganizationDeployment: &c.config.IsOrganizationDeployment,
				MonitoredAccountIds:      monitoredAccounts,
				NodeId:                   nodeId,
				OrganizationAccountId:    &c.config.AccountID,
				Version:                  c.config.Version,
			},
		)
	} else {
		req = req.ModelCloudNodeAccountRegisterReq(
			client.ModelCloudNodeAccountRegisterReq{
				AccountId:                c.config.AccountID,
				CloudProvider:            c.config.CloudProvider,
				HostNodeId:               c.config.NodeID,
				IsOrganizationDeployment: &c.config.IsOrganizationDeployment,
				NodeId:                   nodeId,
				Version:                  c.config.Version,
			},
		)
	}

	log.Debug().Msgf("Before CloudNodesAPI.RegisterCloudNodeAccountExecute")
	_, err := c.client.Client().CloudNodesAPI.RegisterCloudNodeAccountExecute(req)
	if err != nil {
		log.Error().Msgf("Request errored on registering on management console: %s", err.Error())
		return err
	}

	log.Info().Msgf("RegisterCloudAccount complete")
	return nil
}

func (c *Client) RegisterCloudResources(resources []map[string]interface{}) error {
	var out []client.IngestersCloudResource
	req := c.client.Client().CloudResourcesAPI.IngestCloudResources(context.Background())
	b, err := json.Marshal(resources)
	if err != nil {
		log.Error().Msgf("Marshal error: %v", err)
	}
	err = json.Unmarshal(b, &out)
	if err != nil {
		log.Error().Msgf("UnMarshal error: %v", err)
	}
	req = req.IngestersCloudResource(out)
	_, err = c.client.Client().CloudResourcesAPI.IngestCloudResourcesExecute(req)
	if err != nil {
		return err
	}
	log.Debug().Msgf("Resources ingested: %d", len(out))
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
			response, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Error().Msgf("Deployment success signal response cannot be parsed: %s", err.Error())
			}
			resp.Body.Close()
			break
		} else if statusCode == 403 {
			response, err = ioutil.ReadAll(resp.Body)
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
				response, err = ioutil.ReadAll(resp.Body)
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

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

	"github.com/deepfence/ThreatMapper/deepfence_utils/controls"
	"github.com/rs/zerolog/log"

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

func convertSliceType[T any, Y any](input []T) ([]Y, error) {
	var res []Y
	docBytes, err := json.Marshal(input)
	if err != nil {
		log.Error().Msgf(err.Error())
		return res, err
	}
	json.Unmarshal(docBytes, &res)
	return res, nil
}

func convertType[T any, Y any](input T) (Y, error) {
	var res Y
	docBytes, err := json.Marshal(input)
	if err != nil {
		log.Error().Msgf(err.Error())
		return res, err
	}
	json.Unmarshal(docBytes, &res)
	return res, nil
}

func (c *Client) IngestComplianceResults(complianceDocs []util.ComplianceDoc) error {
	log.Debug().Msgf("Number of docs to ingest: %d", len(complianceDocs))
	chunkSize := 200
	req := c.client.Client().CloudScannerAPI.IngestCloudCompliances(context.Background())
	for i := 0; i < len(complianceDocs); i += chunkSize {
		end := i + chunkSize
		// check to avoid slicing beyond slice capacity
		if end > len(complianceDocs) {
			end = len(complianceDocs)
		}
		chunk := complianceDocs[i:end]

		out, err := convertSliceType[util.ComplianceDoc, client.IngestersCloudCompliance](chunk)
		if err != nil {
			return err
		}

		req = req.IngestersCloudCompliance(out)
		_, err = c.client.Client().CloudScannerAPI.IngestCloudCompliancesExecute(req)

		if err != nil {
			return err
		}
	}
	return nil
}

type IngestersComplianceStats struct {
	Alarm                int32   `json:"alarm,omitempty"`
	CompliancePercentage float32 `json:"compliance_percentage,omitempty"`
	Error                int32   `json:"error,omitempty"`
	Info                 int32   `json:"info,omitempty"`
	Ok                   int32   `json:"ok,omitempty"`
	Skip                 int32   `json:"skip,omitempty"`
}

type CloudComplianceScanStatus struct {
	ScanId               string                   `json:"scan_id"`
	ScanMessage          string                   `json:"scan_message"`
	ScanStatus           string                   `json:"scan_status"`
	NodeId               string                   `json:"node_id"`
	ComplianceCheckTypes []string                 `json:"compliance_check_types"`
	Result               IngestersComplianceStats `json:"result"`
	TotalChecks          int32                    `json:"total_checks"`
	Type                 string                   `json:"type"`
}

func (c *Client) SendScanStatusToConsole(ccstatus CloudComplianceScanStatus) error {

	req := c.client.Client().CloudScannerAPI.IngestCloudComplianceScanStatus(context.Background())
	out, err := convertType[CloudComplianceScanStatus, client.IngestersCloudComplianceScanStatus](ccstatus)
	if err != nil {
		return err
	}

	req = req.IngestersCloudComplianceScanStatus([]client.IngestersCloudComplianceScanStatus{out})
	_, err = c.client.Client().CloudScannerAPI.IngestCloudComplianceScanStatusExecute(req)

	return err
}

func (c *Client) RegisterCloudAccount(hostId, cloudProvider, cloudMetaId string,
	multiIds []string, orgId *string, version string) error {

	nodeId := util.GetNodeId(cloudProvider, cloudMetaId)

	req := c.client.Client().CloudNodesAPI.RegisterCloudNodeAccount(context.Background())
	if len(multiIds) > 0 {
		monAccounts := map[string]string{}
		for _, accId := range multiIds {
			monAccounts[accId] = util.GetNodeId(cloudProvider, accId)
		}

		req = req.ModelCloudNodeAccountRegisterReq(
			client.ModelCloudNodeAccountRegisterReq{
				CloudAccount:        cloudMetaId,
				CloudProvider:       cloudProvider,
				MonitoredAccountIds: monAccounts,
				NodeId:              nodeId,
				HostNodeId:          &hostId,
				OrgAccId:            orgId,
				Version:             &version,
			},
		)
	} else {
		req = req.ModelCloudNodeAccountRegisterReq(
			client.ModelCloudNodeAccountRegisterReq{
				CloudAccount:  cloudMetaId,
				CloudProvider: cloudProvider,
				NodeId:        nodeId,
				HostNodeId:    &hostId,
				Version:       &version,
			},
		)
	}

	log.Info().Msgf("Before CloudNodesAPI.RegisterCloudNodeAccountExecute")
	out, _, err := c.client.Client().CloudNodesAPI.RegisterCloudNodeAccountExecute(req)
	if err != nil {
		log.Error().Msgf("Request errored on registering on management console: %s", err.Error())
		return err
	}

	if out.GetData().LogAction.Id != 0 && out.GetData().LogAction.RequestPayload != "" {
		var r controls.SendAgentDiagnosticLogsRequest
		err = json.Unmarshal([]byte(out.GetData().LogAction.RequestPayload), &r)
		if err != nil {
			log.Error().Msgf("Error in unmarshalling log action payload: %+v", err)
		} else {
			err = c.sendDiagnosticLogs(r, []string{HomeDirectory + "/.steampipe/logs"}, []string{})
			if err != nil {
				log.Error().Msgf("Error in sending diagnostic logs: %+v", err)
			}
		}
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

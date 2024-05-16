package deepfence

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/deepfence/ThreatMapper/deepfence_utils/controls"
	"github.com/deepfence/ThreatMapper/deepfence_utils/utils"
	"github.com/deepfence/golang_deepfence_sdk/client"
)

func (c *Client) sendDiagnosticLogs(req controls.SendAgentDiagnosticLogsRequest, pathsToZip []string, excludePathPrefixes []string) error {

	ctx := context.Background()

	fileName := "/tmp/" + req.FileName
	err := utils.RecursiveZip(pathsToZip, excludePathPrefixes, fileName)
	if err != nil {
		publishDiagnosticLogsStatus(ctx, c.client.Client(), req.NodeID, utils.ScanStatusFailed, err.Error())
		return err
	}
	defer os.RemoveAll(fileName)

	resp, statusCode, err := utils.UploadFile(req.UploadURL, fileName)
	if err != nil {
		publishDiagnosticLogsStatus(ctx, c.client.Client(), req.NodeID, utils.ScanStatusFailed, err.Error())
		return err
	}
	if statusCode != http.StatusOK {
		publishDiagnosticLogsStatus(ctx, c.client.Client(), req.NodeID, utils.ScanStatusFailed, string(resp))
		return errors.New(string(resp))
	}

	return publishDiagnosticLogsStatus(ctx, c.client.Client(), req.NodeID, utils.ScanStatusFailed, "")
}

func publishDiagnosticLogsStatus(ctx context.Context, httpsClient *client.APIClient, nodeId string, status string, message string) error {
	httpReq := httpsClient.DiagnosisAPI.UpdateCloudScannerDiagnosticLogsStatus(ctx, nodeId)
	httpReq = httpReq.DiagnosisDiagnosticLogsStatus(client.DiagnosisDiagnosticLogsStatus{
		Message: &message,
		Status:  status,
	})
	res, err := httpsClient.DiagnosisAPI.UpdateCloudScannerDiagnosticLogsStatusExecute(httpReq)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusNoContent {
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		return errors.New(string(body))
	}
	return nil
}

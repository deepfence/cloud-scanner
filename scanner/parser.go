package scanner

import (
	"crypto/md5"
	"fmt"
	"strings"

	"github.com/deepfence/cloud-scanner/util"
)

func (c *CloudComplianceScan) parseControlResult(complianceDocs *[]util.ComplianceDoc, complianceSummary *map[string]map[string]struct{}, group util.ComplianceGroup, control util.ComplianceControl, result util.ComplianceControlResult, accountId string) {
	var region string
	for _, dimension := range result.Dimensions {
		if dimension.Key == "region" || dimension.Key == "location" {
			region = dimension.Value
		}
		//} else if dimension.Key == "account_id" {
		//	accountId = dimension.Value
		//} else if dimension.Key == "project_id" {
		//	accountId = dimension.Value
		//} else if dimension.Key == "project" {
		//	accountId = dimension.Value
		//} else if dimension.Key == "subscription" {
		//	accountId = dimension.Value
		//}
	}

	docId := fmt.Sprintf("%x", md5.Sum([]byte(c.ScanID+control.ControlID+
		result.Resource+group.Title)))
	(*complianceSummary)[result.Status][docId] = struct{}{}
	prefix := ""
	if c.CloudProvider == util.CloudProviderAWS {
		prefix = "AWS/"
	} else if c.CloudProvider == util.CloudProviderGCP {
		prefix = "GCP/"
	} else if c.CloudProvider == util.CloudProviderAzure {
		prefix = "Azure/"
	}
	service := strings.TrimPrefix(control.Tags.Service, prefix)
	if service == "" {
		service = c.CloudProvider
	}

	nodeName := fmt.Sprintf("%s/%s", c.CloudProvider, accountId)
	nodeId := util.GetNodeID(c.CloudProvider, accountId)

	complianceDoc := util.ComplianceDoc{
		Timestamp: util.GetDatetimeNow(),
		// Count:               1,
		Reason:              result.Reason,
		Resource:            result.Resource,
		Status:              result.Status,
		Region:              region,
		AccountID:           accountId,
		Group:               group.Title,
		Service:             service,
		Title:               control.Title,
		ComplianceCheckType: group.ComplianceType,
		CloudProvider:       c.CloudProvider,
		NodeName:            nodeName,
		NodeID:              nodeId,
		ScanID:              c.ScanID,
		Type:                util.CloudComplianceScanIndexName,
		ControlID:           control.ControlID,
		Description:         control.Description,
		Severity:            control.Severity,
	}
	*complianceDocs = append(*complianceDocs, complianceDoc)
}

func (c *CloudComplianceScan) parseGroup(
	complianceDocs *[]util.ComplianceDoc,
	complianceSummary *map[string]map[string]struct{},
	group util.ComplianceGroup,
	accountId string,
) {
	for _, control := range group.Controls {
		for _, result := range control.Results {
			c.parseControlResult(complianceDocs, complianceSummary, group, control, result, accountId)
		}
	}
	for _, childGroup := range group.Groups {
		childGroup.ComplianceType = group.ComplianceType
		c.parseGroup(complianceDocs, complianceSummary, childGroup, accountId)
	}
}

func (c *CloudComplianceScan) ParseComplianceResults(complianceResults util.ComplianceGroup, accountId string) ([]util.ComplianceDoc, util.ComplianceSummary, error) {
	var complianceDocs []util.ComplianceDoc
	complianceSummaryMap := map[string]map[string]struct{}{
		util.StatusAlarm: make(map[string]struct{}),
		util.StatusOk:    make(map[string]struct{}),
		util.StatusInfo:  make(map[string]struct{}),
		util.StatusSkip:  make(map[string]struct{}),
		util.StatusError: make(map[string]struct{}),
		"":               make(map[string]struct{}),
	}
	for _, group := range complianceResults.Groups {
		c.parseGroup(&complianceDocs, &complianceSummaryMap, group, accountId)
	}
	summary := util.ComplianceSummary{
		Alarm: len(complianceSummaryMap[util.StatusAlarm]),
		Ok:    len(complianceSummaryMap[util.StatusOk]),
		Info:  len(complianceSummaryMap[util.StatusInfo]),
		Skip:  len(complianceSummaryMap[util.StatusSkip]),
		Error: len(complianceSummaryMap[util.StatusError]),
	}
	summary.Total = summary.Alarm + summary.Ok + summary.Info + summary.Skip + summary.Error

	return complianceDocs, summary, nil
}

func (c *CloudComplianceScan) ParseComplianceResultsForControls(complianceResults []util.ComplianceGroup, accountId string) ([]util.ComplianceDoc, util.ComplianceSummary, error) {
	var complianceDocs []util.ComplianceDoc
	complianceSummaryMap := map[string]map[string]struct{}{
		util.StatusAlarm: make(map[string]struct{}),
		util.StatusOk:    make(map[string]struct{}),
		util.StatusInfo:  make(map[string]struct{}),
		util.StatusSkip:  make(map[string]struct{}),
		util.StatusError: make(map[string]struct{}),
		"":               make(map[string]struct{}),
	}
	for _, complianceResult := range complianceResults {
		c.parseGroup(&complianceDocs, &complianceSummaryMap, complianceResult, accountId)
	}
	percentage := float32(0)
	total := len(complianceSummaryMap[util.StatusAlarm]) +
		len(complianceSummaryMap[util.StatusOk]) +
		len(complianceSummaryMap[util.StatusInfo]) +
		len(complianceSummaryMap[util.StatusSkip]) +
		len(complianceSummaryMap[util.StatusError])
	if total != 0 {
		percentage = float32(100*(len(complianceSummaryMap[util.StatusOk])+
			len(complianceSummaryMap[util.StatusInfo]))) / float32(total)
	}
	return complianceDocs, util.ComplianceSummary{
		Total:                total,
		Alarm:                len(complianceSummaryMap[util.StatusAlarm]),
		Ok:                   len(complianceSummaryMap[util.StatusOk]),
		Info:                 len(complianceSummaryMap[util.StatusInfo]),
		Skip:                 len(complianceSummaryMap[util.StatusSkip]),
		Error:                len(complianceSummaryMap[util.StatusError]),
		CompliancePercentage: percentage,
	}, nil
}

package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/deepfence/cloud-scanner/internal/deepfence"
	"github.com/deepfence/cloud-scanner/util"
	"github.com/rs/zerolog/log"
)

var (
	scanStatusFilename = os.Getenv("DF_INSTALL_DIR") + "/var/log/fenced/cloud-scanner-log/cloud_scanner_status.log"
	scanFilename       = os.Getenv("DF_INSTALL_DIR") + "/var/log/fenced/cloud-scanner/cloud_scanner.log"
	ScanFilename       = os.Getenv("DF_INSTALL_DIR") + "/var/log/fenced/cloud-scanner/cloud_scanner.log"
)

type Publisher struct {
	config         util.Config
	dfClient       *deepfence.Client
	stopScanStatus chan bool
}

func NewCliPublisher(config util.Config) (*Publisher, error) {
	return &Publisher{
		config: config,
	}, nil
}

func (p *Publisher) IngestComplianceResults(complianceDocs []util.ComplianceDoc) error {
	return p.dfClient.IngestComplianceResults(complianceDocs)
}

func (p *Publisher) OutputSummary(complianceSummary util.ComplianceSummary) {
	fmt.Println(p.config.NodeName + " - " + p.config.ComplianceBenchmark)
	fmt.Printf("Total Results: %d\n", complianceSummary.Total)
	fmt.Printf("Alarm: %d\n", complianceSummary.Alarm)
	fmt.Printf("Ok: %d\n", complianceSummary.Ok)
	fmt.Printf("Info: %d\n", complianceSummary.Info)
	fmt.Printf("Skip: %d\n", complianceSummary.Skip)
	fmt.Printf("Error: %d\n", complianceSummary.Error)
}

func (p *Publisher) WriteFile(filePath string, complianceDocs []util.ComplianceDoc) error {
	jsonString, err := json.MarshalIndent(complianceDocs, "", "\t")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, jsonString, os.ModePerm)
}

func WriteScanStatus(status, scanID, scanMessage string) {
	var scanLogDoc = make(map[string]interface{})
	scanLogDoc["scan_id"] = scanID
	scanLogDoc["scan_status"] = status
	scanLogDoc["scan_message"] = scanMessage

	byteJSON, err := json.Marshal(scanLogDoc)
	if err != nil {
		log.Error().Msgf("Error marshalling json for status: %s", err)
		return
	}

	log.Info().Msgf("Writing status: %s", status)
	err = writeToFile(byteJSON, scanStatusFilename)
	if err != nil {
		log.Error().Msgf("Error writing status data to %s, Error: %s", scanStatusFilename, err)
		return
	}
}

func writeToFile(data []byte, fileName string) error {
	jsonString := string(data)
	if err := os.MkdirAll(filepath.Dir(fileName), 0755); err != nil {
		return fmt.Errorf("os.MkdirAll: %w", err)
	}

	f, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("os.OpenFile:%s", err.Error())
	}

	defer f.Close()
	jsonString = strings.ReplaceAll(jsonString, "\n", " ")
	if _, err = f.WriteString(jsonString + "\n"); err != nil {
		return err
	}
	return nil
}

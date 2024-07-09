package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deepfence/ThreatMapper/deepfence_utils/log"
)

var (
	scanStatusFilename                 = os.Getenv("DF_INSTALL_DIR") + "/var/log/fenced/cloud-scanner-log/cloud_scanner_status.log"
	cloudResourceRefreshStatusFilename = os.Getenv("DF_INSTALL_DIR") + "/var/log/fenced/cloud-resource-refresh-log/cloud_resource_refresh_status.log"
	ScanFilename                       = os.Getenv("DF_INSTALL_DIR") + "/var/log/fenced/cloud-scanner/cloud_scanner.log"
)

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

	log.Debug().Msgf("Writing scan status: %s", status)
	err = writeToFile(byteJSON, scanStatusFilename)
	if err != nil {
		log.Error().Msgf("Error writing scan status data to %s, Error: %s", scanStatusFilename, err)
		return
	}
}

func WriteCloudResourceRefreshStatus(nodeID, refreshStatus, refreshMessage string) {
	var scanLogDoc = make(map[string]interface{})
	scanLogDoc["cloud_node_id"] = nodeID
	scanLogDoc["refresh_status"] = refreshStatus
	scanLogDoc["refresh_message"] = refreshMessage
	scanLogDoc["updated_at"] = time.Now().UTC().UnixMilli()

	byteJSON, err := json.Marshal(scanLogDoc)
	if err != nil {
		log.Error().Msgf("Error marshalling json for status: %s", err)
		return
	}

	log.Debug().Msgf("Writing refresh status: %s, %s", refreshStatus, refreshMessage)
	err = writeToFile(byteJSON, cloudResourceRefreshStatusFilename)
	if err != nil {
		log.Error().Msgf("Error writing refresh status data to %s, Error: %s", cloudResourceRefreshStatusFilename, err)
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

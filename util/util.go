package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os/exec"
	"time"

	cloud_metadata "github.com/deepfence/cloud-scanner/cloud-metadata"
	"github.com/rs/zerolog/log"
)

const (
	ErrSteampipeDB                   = "failed to connect to the database"
	ErrSteampipeInvalidClientTokenID = "The security token included in the request is invalid"
)

var (
	SleepTime = 5 * time.Second
)

func GetIntTimestamp() int64 {
	return time.Now().UTC().UnixNano() / 1000000
}

func GetDatetimeNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

func GetCloudMetadata() (cloud_metadata.CloudMetadata, error) {
	cloudMetadata := cloud_metadata.CloudMetadata{}
	cloudProvider := cloud_metadata.DetectCloudServiceProvider()
	var err error
	if cloudProvider == CloudProviderAWS {
		cloudMetadata, err = cloud_metadata.GetAWSMetadata(false)
		if err != nil {
			return cloudMetadata, err
		}
	} else if cloudProvider == "aws_fargate" {
		cloudMetadata, err = cloud_metadata.GetAWSFargateMetadata(false)
		if err != nil {
			return cloudMetadata, err
		}
		cloudMetadata.CloudProvider = CloudProviderAWS
	} else if cloudProvider == CloudProviderGCP {
		cloudMetadata, err = cloud_metadata.GetGoogleCloudMetadata(false)
		if err != nil {
			return cloudMetadata, err
		}
	} else if cloudProvider == CloudProviderAzure {
		cloudMetadata, err = cloud_metadata.GetAzureMetadata(false)
		if err != nil {
			return cloudMetadata, err
		}
	} else {
		return cloudMetadata, errors.New("only aws/azure/gcp cloud providers are supported")
	}
	return cloudMetadata, nil
}

func GetNodeId(cloudProvider string, accountId string) string {
	return fmt.Sprintf("%s-%s-%s", NodeTypeCloudAccount, cloudProvider, accountId)
}

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func RandomStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func RandomString(length int) string {
	return RandomStringWithCharset(length, charset)
}

func PrintJSON(d interface{}) string {
	s, _ := json.Marshal(d)
	return string(s)
}

func InSlice[T comparable](e T, s []T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func RestartSteampipeService() {
	log.Info().Msgf("Restarting steampipe service")
	stdOut, stdErr := exec.Command("bash", "-c", "steampipe service stop --force").CombinedOutput()
	if stdErr != nil {
		log.Error().Msgf(string(stdOut))
		log.Error().Msgf(stdErr.Error())
	}
	time.Sleep(5 * time.Second)

	stdOut, stdErr = exec.Command("bash", "-c", "rm -f /tmp/.s.PGSQL.9193.lock").CombinedOutput()
	if stdErr != nil {
		log.Error().Msgf(string(stdOut))
		log.Error().Msgf(stdErr.Error())
	}
	time.Sleep(5 * time.Second)

	stdOut, stdErr = exec.Command("bash", "-c", "steampipe service start").CombinedOutput()
	if stdErr != nil {
		log.Error().Msgf(string(stdOut))
		log.Error().Msgf(stdErr.Error())
	}
	log.Info().Msgf("Steampipe service restarted")
	time.Sleep(5 * time.Second)
}

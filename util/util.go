package util

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/deepfence/ThreatMapper/deepfence_utils/log"
	cloud_metadata "github.com/deepfence/cloud-scanner/cloud-metadata"
)

const (
	ErrSteampipeDB                   = "failed to connect to the database"
	ErrSteampipeInvalidClientTokenID = "The security token included in the request is invalid"
)

var (
	SleepTime = 5 * time.Second
)

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

func GetNodeID(cloudProvider string, accountID string) string {
	return fmt.Sprintf("%s-%s-%s", NodeTypeCloudAccount, cloudProvider, accountID)
}

func GetOrgNodeID(cloudProvider string, orgAccountID string) string {
	return fmt.Sprintf("%s-%s-cloud-org", cloudProvider, orgAccountID)
}

var randomLetters = []rune("abcdefghijklmnopqrstuvwxyz")

func RandomString(n int) string {
	randomGenerator := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]rune, n)
	for i := range b {
		b[i] = randomLetters[randomGenerator.Intn(len(randomLetters))]
	}
	return string(b)
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

func GetAWSCredentialsConfig(ctx context.Context, accountID string, region string, c Config, verifyCredential bool) (aws.Config, error) {
	var cfg aws.Config
	var err error

	if accountID == c.DeployedAccountID {
		cfg, err = config.LoadDefaultConfig(
			ctx,
			config.WithRegion(region),
		)
		if err != nil {
			log.Error().Msg(err.Error())
			return cfg, err
		}
	} else {
		if c.RoleName == "" {
			cfg, err = config.LoadDefaultConfig(
				ctx,
				config.WithRegion(region),
				config.WithSharedConfigProfile("profile_"+accountID),
			)
			if err != nil {
				log.Error().Msg(err.Error())
				return cfg, err
			}
		} else {
			cfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(region))
			if err != nil {
				log.Error().Msg(err.Error())
				return cfg, err
			}

			cfg.Credentials = aws.NewCredentialsCache(
				stscreds.NewAssumeRoleProvider(
					sts.NewFromConfig(cfg), fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, c.RoleName),
					func(o *stscreds.AssumeRoleOptions) { o.TokenProvider = stscreds.StdinTokenProvider },
				),
			)
		}
	}

	if verifyCredential {
		iamClient := iam.NewFromConfig(cfg)
		_, err = iamClient.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(c.RoleName)})
		if err != nil {
			log.Error().Msg(err.Error())
			return cfg, err
		}
	}
	return cfg, err
}

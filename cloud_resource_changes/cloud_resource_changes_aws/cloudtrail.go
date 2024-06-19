package cloud_resource_changes_aws

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/deepfence/ThreatMapper/deepfence_utils/log"
	"github.com/deepfence/cloud-scanner/util"
)

const (
	TaskRoleReadOnly      = "arn:aws:iam::aws:policy/ReadOnlyAccess"
	TaskRoleSecurityAudit = "arn:aws:iam::aws:policy/SecurityAudit"
)

var (
	RegionStartAfterMap     = make(map[string]map[string]time.Time, len(GetSupportedAwsRegions()))
	regionStartAfterMapLock sync.RWMutex
	ErrNoCloudTrailsFound   = errors.New("no cloudtrails found with management events and write or read-write mode")
)

type CloudResourceChangesAWS struct {
	config           util.Config
	cloudTrailTrails []CloudTrailTrail
}

func NewCloudResourcesChangesAWS(config util.Config) (*CloudResourceChangesAWS, error) {
	if config.CloudScannerPolicy != TaskRoleReadOnly {
		log.Warn().Msg("Task role is not set to arn:aws:iam::aws:policy/ReadOnlyAccess. Disabling CloudTrail based updates of cloud resources.")
		return &CloudResourceChangesAWS{
			config:           config,
			cloudTrailTrails: []CloudTrailTrail{},
		}, nil
	}
	return &CloudResourceChangesAWS{
		config:           config,
		cloudTrailTrails: make([]CloudTrailTrail, 0),
	}, nil
}

func (c *CloudResourceChangesAWS) Initialize() error {
	trails := getCloudTrailTrails(c.config)
	if len(trails) == 0 {
		return ErrNoCloudTrailsFound
	}
	c.cloudTrailTrails = trails
	log.Info().Msgf("Following CloudTrail Trails are monitored for events every hour to update the cloud resources in the management console")
	for i, trail := range c.cloudTrailTrails {
		log.Info().Msgf("%d. %s (Region: %s)", i+1, trail.Arn, trail.Region)
	}
	return nil
}

func (c *CloudResourceChangesAWS) GetResourceTypesToRefresh() (map[string][]string, error) {
	if len(c.cloudTrailTrails) == 0 {
		return nil, nil
	}
	cloudResourcesToUpdate := make(map[string][]string)
	for _, trail := range c.cloudTrailTrails {
		orgId := ""
		if c.config.IsOrganizationDeployment {
			orgId = getOrgId(trail.AccountID)
		}
		cloudResourcesToRefresh := c.getCloudTrailLogEventsFromS3Bucket(trail.IsOrganizationTrail, orgId,
			trail.AccountID, trail.S3BucketName, trail.S3KeyPrefix, c.getS3Region(trail.S3BucketName, trail.AccountID))

		for accountID, cloudResourceTypes := range cloudResourcesToRefresh {
			if _, ok := cloudResourcesToUpdate[accountID]; !ok {
				cloudResourcesToUpdate[accountID] = make([]string, 0)
			}
			for cloudResourceType, _ := range cloudResourceTypes {
				if !util.InSlice(cloudResourceType, cloudResourcesToUpdate[accountID]) {
					cloudResourcesToUpdate[accountID] = append(cloudResourcesToUpdate[accountID], cloudResourceType)
				}
			}
		}
	}

	log.Info().Msgf("Resources types to update: %v", cloudResourcesToUpdate)
	return cloudResourcesToUpdate, nil
}

func (c *CloudResourceChangesAWS) getS3Region(s3BucketName, accountId string) string {
	query := "steampipe query --output json \"select region from aws_" + c.config.AccountID + ".aws_s3_bucket WHERE name LIKE '" + s3BucketName + "' \""
	cmd := exec.Command("bash", "-c", query)
	stdOut, stdErr := cmd.CombinedOutput()
	s3Region := "us-east-1"
	if stdErr != nil {
		log.Error().Msgf("Error while obtaining s3 bucket region for cloudtrail: %v", stdErr)
		log.Error().Msgf(string(stdOut))
	}
	var s3BucketObjMapList []S3Details
	if err := json.Unmarshal(stdOut, &s3BucketObjMapList); err != nil {
		log.Error().Msgf("Error unmarshaling s3 bucket region: %v \n Steampipe Output: %s",
			err, string(stdOut))
	}
	if len(s3BucketObjMapList) == 0 {
		log.Error().Msgf("Unable to get s3 bucket region, defaulting to us-east-1")
	} else {
		s3Region = s3BucketObjMapList[0].Region
	}
	return s3Region
}

func getOrgId(accountId string) string {
	query := "steampipe query --output json \"select organization_id from aws_all.aws_account WHERE title LIKE '" + accountId + "' \""
	cmd := exec.Command("bash", "-c", query)
	stdOut, stdErr := cmd.CombinedOutput()
	orgId := ""
	if stdErr != nil {
		log.Error().Msgf("Error while obtaining org id for cloudtrail: %v", stdErr)
		log.Error().Msgf(string(stdOut))
		return orgId
	}
	var orgIdObjMapList []AccountDetails
	if err := json.Unmarshal(stdOut, &orgIdObjMapList); err != nil {
		log.Error().Msgf("Error unmarshaling org id: %v \n Steampipe Output: %s", err, string(stdOut))
		return orgId
	}
	if len(orgIdObjMapList) > 0 {
		orgId = orgIdObjMapList[0].OrgId
	}
	return orgId
}

func (c *CloudResourceChangesAWS) getCloudTrailLogEventsFromS3Bucket(isOrganizationTrail bool, orgId, accId, s3Bucket, s3Prefix, s3Region string) map[string]map[string]bool {
	logFilePrefix := ""
	if !c.config.IsOrganizationDeployment {
		if s3Prefix != "" {
			logFilePrefix = s3Prefix + "/"
		}
	}
	logFilePrefix = logFilePrefix + "AWSLogs/"
	if c.config.IsOrganizationDeployment {
		logFilePrefix = logFilePrefix + orgId + "/"
	}
	logFilePrefix = logFilePrefix + accId + "/"
	logFilePrefix = logFilePrefix + "CloudTrail/"
	awsRegions := GetSupportedAwsRegions()
	today := time.Now()
	yesterday := time.Now().AddDate(0, 0, -1)

	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Profile:           "profile_" + c.config.AccountID,
		Config: aws.Config{
			CredentialsChainVerboseErrors: aws.Bool(true),
			Region:                        aws.String(s3Region),
		},
	})
	if err != nil {
		log.Error().Msgf("NewSession Error: %s", err.Error())
		return nil
	}
	svc := s3.New(sess)
	cloudResourcesToRefresh := make(map[string]map[string]bool, 0)
	var stop bool
	for _, region := range awsRegions {
		lastModified := c.getLastModifiedFromMap(region, accId)
		if lastModified.Before(today) {
			yesterdayRegionalFilePrefix := logFilePrefix + region + "/" + fmt.Sprintf("%d/%02d/%02d/",
				yesterday.Year(), int(yesterday.Month()), yesterday.Day())
			stop = c.listAndProcessS3Objects(yesterdayRegionalFilePrefix, s3Bucket, err, svc, sess, cloudResourcesToRefresh, region, accId, lastModified)
			if stop {
				break
			}
		}
		regionalFilePrefix := logFilePrefix + region + "/"
		regionalFilePrefix = regionalFilePrefix + fmt.Sprintf("%d/%02d/%02d/", today.Year(), int(today.Month()), today.Day())
		stop = c.listAndProcessS3Objects(regionalFilePrefix, s3Bucket, err, svc, sess, cloudResourcesToRefresh, region, accId, lastModified)
		if stop {
			break
		}
	}
	return cloudResourcesToRefresh
}

func (c *CloudResourceChangesAWS) listAndProcessS3Objects(regionalFilePrefix string, s3Bucket string, err error, svc *s3.S3, sess *session.Session,
	cloudResourcesToRefresh map[string]map[string]bool, region string, accId string, lastModified time.Time) bool {

	params := &s3.ListObjectsV2Input{
		Bucket:       aws.String(s3Bucket),
		Delimiter:    aws.String("/"),
		EncodingType: aws.String("url"),
		Prefix:       aws.String(regionalFilePrefix),
	}
	if accId != c.config.AccountID {
		params = params.SetExpectedBucketOwner(accId)
	}
	err = svc.ListObjectsV2Pages(params, func(resp *s3.ListObjectsV2Output, lastPage bool) bool {
		for _, key := range resp.Contents {
			if lastModified.After(*key.LastModified) {
				continue
			}
			fileName := strings.Replace(*key.Key, regionalFilePrefix, "", -1)
			c.processCloudtrailEventLogFile(fileName, key, sess, s3Bucket, accId, cloudResourcesToRefresh)
			c.updateLastModifiedToMap(region, accId, key)
		}
		return lastPage
	})
	if err != nil {
		log.Error().Msgf("Error listing objects for region %s: %s", region, err.Error())
		if strings.Contains(err.Error(), "AccessDenied") {
			return true
		}
	}
	return false
}

func (c *CloudResourceChangesAWS) updateLastModifiedToMap(region string, accId string, key *s3.Object) {
	regionStartAfterMapLock.Lock()
	defer regionStartAfterMapLock.Unlock()
	if _, ok := RegionStartAfterMap[region]; ok {
		if lastModified, ok2 := RegionStartAfterMap[region][accId]; ok2 {
			if lastModified.Before(*key.LastModified) {
				RegionStartAfterMap[region][accId] = *key.LastModified
			}
		} else {
			RegionStartAfterMap[region][accId] = *key.LastModified
		}
	} else {
		RegionStartAfterMap[region] = make(map[string]time.Time)
		RegionStartAfterMap[region][accId] = *key.LastModified
	}
}

func (c *CloudResourceChangesAWS) getLastModifiedFromMap(region string, accId string) time.Time {
	regionStartAfterMapLock.RLock()
	defer regionStartAfterMapLock.RUnlock()
	if _, ok := RegionStartAfterMap[region]; ok {
		if lastRead, ok2 := RegionStartAfterMap[region][accId]; ok2 {
			return lastRead
		}
	}
	return time.Now().AddDate(0, 0, -1)
}

func (c *CloudResourceChangesAWS) processCloudtrailEventLogFile(fileName string, key *s3.Object, sess *session.Session, s3Bucket, accId string, cloudResourcesToRefresh map[string]map[string]bool) {
	file, err := os.Create("/tmp/" + fileName)
	if err != nil {
		log.Error().Msgf("Error creating file for S3 download %s: %s", *key.Key, err.Error())
	}
	defer os.Remove("/tmp/" + fileName)
	downloader := s3manager.NewDownloader(sess)
	s3ObjectInput := s3.GetObjectInput{
		Bucket: aws.String(s3Bucket),
		Key:    aws.String(*key.Key),
	}
	if accId != c.config.AccountID {
		s3ObjectInput.SetExpectedBucketOwner(accId)
	}
	_, err = downloader.Download(file, &s3ObjectInput)
	if err != nil {
		log.Error().Msgf("Unable to download item %q, %s", *key.Key, err.Error())
		return
	}
	reader, err := gzip.NewReader(file)
	defer reader.Close()
	var cloudTrailEvent CloudTrailLogFile
	err = json.NewDecoder(reader).Decode(&cloudTrailEvent)
	if err != nil {
		log.Error().Msgf("Error converting s3 object to json: %s", err.Error())
	}

	for _, r := range cloudTrailEvent.Records {
		if r.ReadOnly || !r.ManagementEvent {
			continue
		}
		if len(r.Resources) == 0 {
			continue
		}
		for _, resource := range r.Resources {
			if resource.Type != "" {
				if _, ok := cloudResourcesToRefresh[resource.AccountID]; !ok {
					cloudResourcesToRefresh[resource.AccountID] = make(map[string]bool)
				}
				cloudResourcesToRefresh[resource.AccountID][strings.ToLower(strings.Replace(resource.Type, "::", "_", -1))] = true
			}
		}
	}
}

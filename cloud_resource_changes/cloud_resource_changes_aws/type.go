package cloud_resource_changes_aws

import (
	"github.com/aws/aws-sdk-go/service/macie2"
)

type WebIdentitySessionContext struct {
	FederatedProvider string                 `json:"federatedProvider,omitempty"`
	Attributes        map[string]interface{} `json:"attributes,omitempty"`
}

type SessionContext struct {
	Attributes          map[string]interface{}    `json:"attributes,omitempty"`
	SessionIssuer       macie2.SessionIssuer      `json:"sessionIssuer,omitempty"`
	WebIdFederationData WebIdentitySessionContext `json:"webIdFederationData,omitempty"`
}

type UserIdentity struct {
	IdentityType     string         `json:"type,omitempty"`
	PrincipalId      string         `json:"principalId,omitempty"`
	Arn              string         `json:"arn,omitempty"`
	AccountId        string         `json:"accountId,omitempty"`
	AccessKeyId      string         `json:"accessKeyId,omitempty"`
	UserName         string         `json:"userName,omitempty"`
	InvokedBy        string         `json:"invokedBy,omitempty"`
	SessionContext   SessionContext `json:"sessionContext,omitempty"`
	IdentityProvider string         `json:"identityProvider,omitempty"`
}

type CloudTrailLogEventResources struct {
	AccountID string `json:"accountId"`
	Type      string `json:"type"`
}

type CloudTrailLogEvent struct {
	Type                         string                        `json:"type,omitempty"`
	TimeStamp                    int64                         `json:"time_stamp,omitempty"`
	Timestamp                    string                        `json:"@timestamp,omitempty"`
	Masked                       string                        `json:"masked,omitempty"`
	EventVersion                 string                        `json:"eventVersion,omitempty"`
	UserIdentity                 UserIdentity                  `json:"userIdentity,omitempty"`
	EventTime                    string                        `json:"eventTime,omitempty"`
	EventName                    string                        `json:"eventName,omitempty"`
	EventSource                  string                        `json:"eventSource,omitempty"`
	AwsRegion                    string                        `json:"awsRegion,omitempty"`
	SourceIPAddress              string                        `json:"sourceIPAddress,omitempty"`
	UserAgent                    string                        `json:"userAgent,omitempty"`
	RequestID                    string                        `json:"requestID,omitempty"`
	ErrorCode                    string                        `json:"errorCode,omitempty"`
	ErrorMessage                 string                        `json:"errorMessage,omitempty"`
	RequestParameters            map[string]interface{}        `json:"requestParameters,omitempty"`
	ResponseElements             map[string]interface{}        `json:"responseElements,omitempty"`
	ServiceEventDetails          map[string]interface{}        `json:"serviceEventDetails,omitempty"`
	AdditionalEventData          map[string]interface{}        `json:"additionalEventData,omitempty"`
	EventID                      string                        `json:"eventID,omitempty"`
	ReadOnly                     bool                          `json:"readOnly,omitempty"`
	ManagementEvent              bool                          `json:"managementEvent,omitempty"`
	Resources                    []CloudTrailLogEventResources `json:"resources,omitempty"`
	AccountId                    string                        `json:"accountId,omitempty"`
	EventCategory                string                        `json:"eventCategory,omitempty"`
	EventType                    string                        `json:"eventType,omitempty"`
	ApiVersion                   string                        `json:"apiVersion,omitempty"`
	RecipientAccountId           string                        `json:"recipientAccountId,omitempty"`
	SharedEventID                string                        `json:"sharedEventID,omitempty"`
	Annotation                   string                        `json:"annotation,omitempty"`
	VpcEndpointId                string                        `json:"vpcEndpointId,omitempty"`
	InsightDetails               map[string]interface{}        `json:"insightDetails,omitempty"`
	Addendum                     map[string]interface{}        `json:"addendum,omitempty"`
	EdgeDeviceDetails            map[string]interface{}        `json:"edgeDeviceDetails,omitempty"`
	TlsDetails                   map[string]interface{}        `json:"tlsDetails,omitempty"`
	SessionCredentialFromConsole string                        `json:"sessionCredentialFromConsole,omitempty"`
}

type CloudTrailLogFile struct {
	Records []CloudTrailLogEvent `json:"Records"`
}

type AccountDetails struct {
	OrgId string `json:"organization_id"`
}

type S3Details struct {
	Region string `json:"region"`
}

type CloudTrailTrail struct {
	AccountID              string `json:"account_id"`
	AdvancedEventSelectors []struct {
		FieldSelectors []struct {
			EndsWith      interface{} `json:"EndsWith"`
			Equals        []string    `json:"Equals"`
			Field         string      `json:"Field"`
			NotEndsWith   interface{} `json:"NotEndsWith"`
			NotEquals     interface{} `json:"NotEquals"`
			NotStartsWith interface{} `json:"NotStartsWith"`
			StartsWith    interface{} `json:"StartsWith"`
		} `json:"FieldSelectors"`
		Name string `json:"Name"`
	} `json:"advanced_event_selectors"`
	Arn                   string `json:"arn"`
	CloudwatchLogsRoleArn string `json:"cloudwatch_logs_role_arn"`
	EventSelectors        []struct {
		DataResources                 []any  `json:"DataResources"`
		ExcludeManagementEventSources []any  `json:"ExcludeManagementEventSources"`
		IncludeManagementEvents       bool   `json:"IncludeManagementEvents"`
		ReadWriteType                 string `json:"ReadWriteType"`
	} `json:"event_selectors"`
	HasCustomEventSelectors bool   `json:"has_custom_event_selectors"`
	HasInsightSelectors     bool   `json:"has_insight_selectors"`
	HomeRegion              string `json:"home_region"`
	InsightSelectors        any    `json:"insight_selectors"`
	IsLogging               bool   `json:"is_logging"`
	IsMultiRegionTrail      bool   `json:"is_multi_region_trail"`
	IsOrganizationTrail     bool   `json:"is_organization_trail"`
	KmsKeyID                any    `json:"kms_key_id"`
	Name                    string `json:"name"`
	Region                  string `json:"region"`
	S3BucketName            string `json:"s3_bucket_name"`
	S3KeyPrefix             string `json:"s3_key_prefix"`
}

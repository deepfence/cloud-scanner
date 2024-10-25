package cloud_resource_changes_aws

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConvertRows(t *testing.T) {

	jsonData := []byte(`
	{
		"columns": [
			{
				"name": "organization_id",
				"data_type": "text"
			}
		],
		"rows": [
			{
				"organization_id": "o-gmktzqiafl"
			}
		]
	}`)

	var steampipeQueryResponse SteampipeQueryResponse
	if err := json.Unmarshal(jsonData, &steampipeQueryResponse); err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return
	}

	accountDetails, err := ConvertRows[AccountDetails](steampipeQueryResponse.Rows)
	if err != nil {
		fmt.Println("Error converting rows to AccountDetails:", err)
		return
	}

	fmt.Printf("AccountDetails: %+v\n", accountDetails)

	assert.NoError(t, err, "Error converting rows to AccountDetails")

	assert.Len(t, accountDetails, 1, "Expected one AccountDetail")
	assert.Equal(t, "o-gmktzqiafl", accountDetails[0].OrgId, "Expected OrgId to be o-gmktzqiafl")

	jsonData2 := []byte(`
	{
		"columns": [
			{
				"name": "region",
				"data_type": "text"
			}
		],
		"rows": [
			{
				"region": "us-west-2"
			}
		]
	}`)

	if err := json.Unmarshal(jsonData2, &steampipeQueryResponse); err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return
	}

	s3Details, err := ConvertRows[S3Details](steampipeQueryResponse.Rows)
	if err != nil {
		fmt.Println("Error converting rows to S3Details:", err)
		return
	}

	fmt.Printf("S3Details: %+v\n", s3Details)

	assert.Len(t, s3Details, 1, "Expected one S3Detail")
	assert.Equal(t, "us-west-2", s3Details[0].Region, "Expected region to be us-west-2")
}

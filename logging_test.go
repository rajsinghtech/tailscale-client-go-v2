// Copyright (c) David Bond, Tailscale Inc, & Contributors
// SPDX-License-Identifier: MIT

package tailscale

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_LogstreamConfiguration(t *testing.T) {
	t.Parallel()

	client, server := NewTestHarness(t)
	server.ResponseCode = http.StatusOK

	expectedLogstream := &LogstreamConfiguration{
		DestinationType:      LogstreamCriblEndpoint,
		URL:                  "http://example.com",
		User:                 "my-user",
		UploadPeriodMinutes:  5,
		CompressionFormat:    CompressionFormatZstd,
		S3Bucket:             "my-bucket",
		S3Region:             "us-west-2",
		S3KeyPrefix:          "logs/",
		S3AuthenticationType: S3AccessKeyAuthentication,
		S3AccessKeyID:        "my-access-key-id",
		S3RoleARN:            "my-role-arn",
		S3ExternalID:         "my-external-id",
	}
	server.ResponseBody = expectedLogstream

	actualLogstream, err := client.Logging().LogstreamConfiguration(context.Background(), LogTypeConfig)
	assert.NoError(t, err)
	assert.Equal(t, http.MethodGet, server.Method)
	assert.Equal(t, "/api/v2/tailnet/example.com/logging/configuration/stream", server.Path)
	assert.Equal(t, expectedLogstream, actualLogstream)
}

func TestClient_SetLogstreamConfiguration(t *testing.T) {
	t.Parallel()

	client, server := NewTestHarness(t)
	server.ResponseCode = http.StatusOK

	logstreamRequest := SetLogstreamConfigurationRequest{
		DestinationType:      LogstreamCriblEndpoint,
		URL:                  "http://example.com",
		User:                 "my-user",
		Token:                "my-token",
		UploadPeriodMinutes:  5,
		CompressionFormat:    CompressionFormatZstd,
		S3Bucket:             "my-bucket",
		S3Region:             "us-west-2",
		S3KeyPrefix:          "logs/",
		S3AuthenticationType: S3AccessKeyAuthentication,
		S3AccessKeyID:        "my-access-key-id",
		S3SecretAccessKey:    "my-secret-access-key",
		S3RoleARN:            "my-role-arn",
		S3ExternalID:         "my-external-id",
	}
	server.ResponseBody = nil

	err := client.Logging().SetLogstreamConfiguration(context.Background(), LogTypeNetwork, logstreamRequest)
	assert.NoError(t, err)
	assert.Equal(t, http.MethodPut, server.Method)
	assert.Equal(t, "/api/v2/tailnet/example.com/logging/network/stream", server.Path)
	var receivedRequest SetLogstreamConfigurationRequest
	err = json.Unmarshal(server.Body.Bytes(), &receivedRequest)
	assert.NoError(t, err)
	assert.EqualValues(t, logstreamRequest, receivedRequest)
}

func TestClient_DeleteLogstream(t *testing.T) {
	t.Parallel()

	client, server := NewTestHarness(t)
	server.ResponseCode = http.StatusOK

	err := client.Logging().DeleteLogstreamConfiguration(context.Background(), LogTypeConfig)
	assert.NoError(t, err)
	assert.Equal(t, http.MethodDelete, server.Method)
	assert.Equal(t, "/api/v2/tailnet/example.com/logging/configuration/stream", server.Path)
}

func TestClient_CreateOrGetAwsExternalId(t *testing.T) {
	t.Parallel()

	client, server := NewTestHarness(t)
	server.ResponseCode = http.StatusOK

	wantExternalID := &AWSExternalID{
		ExternalID:            "external-id",
		TailscaleAWSAccountID: "account-id",
	}
	server.ResponseBody = wantExternalID

	gotExternalID, err := client.Logging().CreateOrGetAwsExternalId(context.Background(), true)
	assert.NoError(t, err)
	assert.Equal(t, server.Method, http.MethodPost)
	assert.Equal(t, server.Path, "/api/v2/tailnet/example.com/aws-external-id")
	assert.Equal(t, gotExternalID, wantExternalID)

	gotRequest := make(map[string]bool)
	err = json.Unmarshal(server.Body.Bytes(), &gotRequest)
	assert.NoError(t, err)
	assert.EqualValues(t, gotRequest, map[string]bool{"reusable": true})
}

func TestClient_ValidateAWSTrustPolicy(t *testing.T) {
	t.Parallel()

	client, server := NewTestHarness(t)
	server.ResponseCode = http.StatusOK

	roleARN := "arn:aws:iam::123456789012:role/example-role"

	err := client.Logging().ValidateAWSTrustPolicy(context.Background(), "external-id-0000-0000", roleARN)
	assert.NoError(t, err)
	assert.Equal(t, server.Method, http.MethodPost)
	assert.Equal(t, server.Path, "/api/v2/tailnet/example.com/aws-external-id/external-id-0000-0000/validate-aws-trust-policy")

	gotRequest := make(map[string]string)
	err = json.Unmarshal(server.Body.Bytes(), &gotRequest)
	assert.NoError(t, err)
	assert.EqualValues(t, gotRequest, map[string]string{"roleArn": roleARN})
}

func TestClient_GetNetworkFlowLogs(t *testing.T) {
	t.Parallel()

	client, server := NewTestHarness(t)
	server.ResponseCode = http.StatusOK

	logged1, err := time.Parse(time.RFC3339, "2024-06-06T15:27:26.583893Z")
	require.NoError(t, err)
	start1, err := time.Parse(time.RFC3339, "2024-06-06T15:25:26.583893Z")
	require.NoError(t, err)
	end1, err := time.Parse(time.RFC3339, "2024-06-06T15:26:26.583893Z")
	require.NoError(t, err)
	logged2, err := time.Parse(time.RFC3339, "2024-06-06T15:28:26.583893Z")
	require.NoError(t, err)
	start2, err := time.Parse(time.RFC3339, "2024-06-06T15:26:26.583893Z")
	require.NoError(t, err)
	end2, err := time.Parse(time.RFC3339, "2024-06-06T15:27:26.583893Z")
	require.NoError(t, err)
	requestStart, err := time.Parse(time.RFC3339, "2024-06-06T15:00:00Z")
	require.NoError(t, err)
	requestEnd, err := time.Parse(time.RFC3339, "2024-06-06T16:00:00Z")
	require.NoError(t, err)

	expectedResponse := &NetworkFlowLogsResponse{
		Logs: []NetworkFlowLog{
			{
				Logged: logged1,
				NodeID: "nBLYviWLGB21DEVEL",
				Start:  start1,
				End:    end1,
				VirtualTraffic: []TrafficStats{
					{
						Proto:   6,
						Src:     "108.86.185.125:52343",
						Dst:     "108.86.185.126:443",
						TxPkts:  10,
						TxBytes: 10000,
						RxPkts:  10,
						RxBytes: 5000,
					},
					{
						Proto:   6,
						Src:     "[fd7a:115c:a1e0::1]:22",
						Dst:     "[fd7a:115c:a1e0::2]:22",
						TxPkts:  5,
						TxBytes: 2500,
						RxPkts:  5,
						RxBytes: 2500,
					},
				},
			},
			{
				Logged: logged2,
				NodeID: "nABCDEFGHIJKLMNOP",
				Start:  start2,
				End:    end2,
				VirtualTraffic: []TrafficStats{
					{
						Proto:   6,
						Src:     "10.0.0.1:8080",
						Dst:     "10.0.0.2:8080",
						TxPkts:  100,
						TxBytes: 50000,
						RxPkts:  100,
						RxBytes: 50000,
					},
				},
			},
		},
	}
	server.ResponseBody = expectedResponse

	params := NetworkFlowLogsRequest{
		Start: requestStart,
		End:   requestEnd,
	}
	actualResponse, err := client.Logging().GetNetworkFlowLogs(context.Background(), params)
	assert.NoError(t, err)
	assert.Equal(t, http.MethodGet, server.Method)
	assert.Equal(t, "/api/v2/tailnet/example.com/logging/network", server.Path)
	
	assert.Equal(t, expectedResponse, actualResponse)
}


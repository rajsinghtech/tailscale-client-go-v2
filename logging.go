// Copyright (c) David Bond, Tailscale Inc, & Contributors
// SPDX-License-Identifier: MIT

package tailscale

import (
	"context"
	"net/http"
	"time"
)

// LoggingResource provides access to https://tailscale.com/api#tag/logging.
type LoggingResource struct {
	*Client
}

const (
	LogstreamSplunkEndpoint  LogstreamEndpointType = "splunk"
	LogstreamElasticEndpoint LogstreamEndpointType = "elastic"
	LogstreamPantherEndpoint LogstreamEndpointType = "panther"
	LogstreamCriblEndpoint   LogstreamEndpointType = "cribl"
	LogstreamDatadogEndpoint LogstreamEndpointType = "datadog"
	LogstreamAxiomEndpoint   LogstreamEndpointType = "axiom"
	LogstreamS3Endpoint      LogstreamEndpointType = "s3"
)

const (
	LogTypeConfig  LogType = "configuration"
	LogTypeNetwork LogType = "network"
)

const (
	CompressionFormatNone CompressionFormat = "none"
	CompressionFormatZstd CompressionFormat = "zstd"
	CompressionFormatGzip CompressionFormat = "gzip"
)

const (
	S3AccessKeyAuthentication S3AuthenticationType = "accesskey"
	S3RoleARNAuthentication   S3AuthenticationType = "rolearn"
)

// LogstreamConfiguration type defines a log stream entity in tailscale.
type LogstreamConfiguration struct {
	LogType              LogType               `json:"logType,omitempty"`
	DestinationType      LogstreamEndpointType `json:"destinationType,omitempty"`
	URL                  string                `json:"url,omitempty"`
	User                 string                `json:"user,omitempty"`
	UploadPeriodMinutes  int                   `json:"uploadPeriodMinutes,omitempty"`
	CompressionFormat    CompressionFormat     `json:"compressionFormat,omitempty"`
	S3Bucket             string                `json:"s3Bucket,omitempty"`
	S3Region             string                `json:"s3Region,omitempty"`
	S3KeyPrefix          string                `json:"s3KeyPrefix,omitempty"`
	S3AuthenticationType S3AuthenticationType  `json:"s3AuthenticationType,omitempty"`
	S3AccessKeyID        string                `json:"s3AccessKeyId,omitempty"`
	S3RoleARN            string                `json:"s3RoleArn,omitempty"`
	S3ExternalID         string                `json:"s3ExternalId,omitempty"`
}

// SetLogstreamConfigurationRequest type defines a request for setting a LogstreamConfiguration.
type SetLogstreamConfigurationRequest struct {
	DestinationType      LogstreamEndpointType `json:"destinationType,omitempty"`
	URL                  string                `json:"url,omitempty"`
	User                 string                `json:"user,omitempty"`
	Token                string                `json:"token,omitempty"`
	UploadPeriodMinutes  int                   `json:"uploadPeriodMinutes,omitempty"`
	CompressionFormat    CompressionFormat     `json:"compressionFormat,omitempty"`
	S3Bucket             string                `json:"s3Bucket,omitempty"`
	S3Region             string                `json:"s3Region,omitempty"`
	S3KeyPrefix          string                `json:"s3KeyPrefix,omitempty"`
	S3AuthenticationType S3AuthenticationType  `json:"s3AuthenticationType,omitempty"`
	S3AccessKeyID        string                `json:"s3AccessKeyId,omitempty"`
	S3SecretAccessKey    string                `json:"s3SecretAccessKey,omitempty"`
	S3RoleARN            string                `json:"s3RoleArn,omitempty"`
	S3ExternalID         string                `json:"s3ExternalId,omitempty"`
}

// LogstreamEndpointType describes the type of the endpoint.
type LogstreamEndpointType string

// LogType describes the type of logging.
type LogType string

// CompressionFormat specifies what kind of compression to use on logs.
type CompressionFormat string

// S3AuthenticationType describes the type of authentication used to stream logs to a LogstreamS3Endpoint.
type S3AuthenticationType string

// LogstreamConfiguration retrieves the tailnet's [LogstreamConfiguration] for the given [LogType].
func (lr *LoggingResource) LogstreamConfiguration(ctx context.Context, logType LogType) (*LogstreamConfiguration, error) {
	req, err := lr.buildRequest(ctx, http.MethodGet, lr.buildTailnetURL("logging", logType, "stream"))
	if err != nil {
		return nil, err
	}

	return body[LogstreamConfiguration](lr, req)
}

// SetLogstreamConfiguration sets the tailnet's [LogstreamConfiguration] for the given [LogType].
func (lr *LoggingResource) SetLogstreamConfiguration(ctx context.Context, logType LogType, request SetLogstreamConfigurationRequest) error {
	req, err := lr.buildRequest(ctx, http.MethodPut, lr.buildTailnetURL("logging", logType, "stream"), requestBody(request))
	if err != nil {
		return err
	}

	return lr.do(req, nil)
}

// DeleteLogstreamConfiguration deletes the tailnet's [LogstreamConfiguration] for the given [LogType].
func (lr *LoggingResource) DeleteLogstreamConfiguration(ctx context.Context, logType LogType) error {
	req, err := lr.buildRequest(ctx, http.MethodDelete, lr.buildTailnetURL("logging", logType, "stream"))
	if err != nil {
		return err
	}

	return lr.do(req, nil)
}

// AWSExternalID represents an AWS External ID that Tailscale can use to stream logs from a
// particular Tailscale AWS account to a LogstreamS3Endpoint that uses S3RoleARNAuthentication.
type AWSExternalID struct {
	ExternalID            string `json:"externalId,omitempty"`
	TailscaleAWSAccountID string `json:"tailscaleAwsAccountId,omitempty"`
}

// CreateOrGetAwsExternalId gets an AWS External ID that Tailscale can use to stream logs to
// a LogstreamS3Endpoint using S3RoleARNAuthentication, creating a new one for this tailnet
// when necessary.
func (lr *LoggingResource) CreateOrGetAwsExternalId(ctx context.Context, reusable bool) (*AWSExternalID, error) {
	req, err := lr.buildRequest(ctx, http.MethodPost, lr.buildTailnetURL("aws-external-id"), requestBody(map[string]bool{
		"reusable": reusable,
	}))
	if err != nil {
		return nil, err
	}
	return body[AWSExternalID](lr, req)
}

// ValidateAWSTrustPolicy validates that Tailscale can assume your AWS IAM role with (and only
// with) the given AWS External ID.
func (lr *LoggingResource) ValidateAWSTrustPolicy(ctx context.Context, awsExternalID string, roleARN string) error {
	req, err := lr.buildRequest(ctx, http.MethodPost, lr.buildTailnetURL("aws-external-id", awsExternalID, "validate-aws-trust-policy"), requestBody(map[string]string{
		"roleArn": roleARN,
	}))
	if err != nil {
		return err
	}
	return lr.do(req, nil)
}

// NetworkFlowLog represents a network flow log entry from the Tailscale API.
type NetworkFlowLog struct {
	Logged time.Time `json:"logged"`
	NodeID string    `json:"nodeId"`
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	VirtualTraffic  []TrafficStats `json:"virtualTraffic,omitempty"`
	SubnetTraffic   []TrafficStats `json:"subnetTraffic,omitempty"`
	ExitTraffic     []TrafficStats `json:"exitTraffic,omitempty"`
	PhysicalTraffic []TrafficStats `json:"physicalTraffic,omitempty"`
}

// TrafficStats represents traffic flow statistics.
// This type is used for all traffic types: virtual, subnet, exit, and physical.
type TrafficStats struct {
	Proto   int    `json:"proto,omitempty"`   // IP protocol number (e.g., 6 for TCP, 17 for UDP)
	Src     string `json:"src,omitempty"`     // Source address and port
	Dst     string `json:"dst,omitempty"`     // Destination address and port
	TxPkts  uint64 `json:"txPkts,omitempty"`  // Transmitted packets
	TxBytes uint64 `json:"txBytes,omitempty"` // Transmitted bytes
	RxPkts  uint64 `json:"rxPkts,omitempty"`  // Received packets
	RxBytes uint64 `json:"rxBytes,omitempty"` // Received bytes
}

// NetworkFlowLogsResponse represents the response from the network flow logs endpoint.
type NetworkFlowLogsResponse struct {
	Logs []NetworkFlowLog `json:"logs"`
}

// NetworkFlowLogsRequest represents query parameters for fetching network flow logs.
type NetworkFlowLogsRequest struct {
	Start time.Time // Start time for the log query (required)
	End   time.Time // End time for the log query (required)
}

// GetNetworkFlowLogs retrieves network flow logs for the tailnet.
// Both start and end parameters are required by the backend API.
// Times should be within the last 30 days (older times will be adjusted by the server).
func (lr *LoggingResource) GetNetworkFlowLogs(ctx context.Context, params NetworkFlowLogsRequest) (*NetworkFlowLogsResponse, error) {
	url := lr.buildTailnetURL("logging", "network")
	q := url.Query()
	if !params.Start.IsZero() {
		q.Set("start", params.Start.Format(time.RFC3339))
	}
	if !params.End.IsZero() {
		q.Set("end", params.End.Format(time.RFC3339))
	}
	url.RawQuery = q.Encode()

	req, err := lr.buildRequest(ctx, http.MethodGet, url)
	if err != nil {
		return nil, err
	}

	return body[NetworkFlowLogsResponse](lr, req)
}

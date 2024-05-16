package deepfence

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

func buildHttpClient() (*http.Client, error) {
	// Set up our own certificate pool
	tlsConfig := &tls.Config{RootCAs: x509.NewCertPool(), InsecureSkipVerify: true}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     tlsConfig,
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 1024,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Minute,
				KeepAlive: 15 * time.Minute,
			}).DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute,
		},
		Timeout: 15 * time.Minute,
	}
	return client, nil
}

type dfApiAuthResponse struct {
	AccessToken  string                 `json:"access_token,omitempty"`
	RefreshToken string                 `json:"refresh_token,omitempty"`
	Error        map[string]interface{} `json:"error_fields,omitempty"`
	Message      string                 `json:"message,omitempty"`
}

// data needs to be in this format for kafka rest proxy
// {"records":[{"value":<record1>},{"value":record2}]}
func ToKafkaRestFormat(data []interface{}) *bytes.Buffer {
	values := make([]string, len(data))
	for i, d := range data {
		encoded, err := json.Marshal(&d)
		if err != nil {
			log.Error().Msgf("failed to encode doc: %s", err)
			continue
		}
		values[i] = "{\"value\":" + string(encoded) + "}"
	}
	return bytes.NewBuffer([]byte("{\"records\":[" + strings.Join(values, ",") + "]}"))
}

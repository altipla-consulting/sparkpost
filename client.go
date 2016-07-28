package sparkpost

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/juju/errors"
)

type Client struct {
	key string
}

func NewClient(apiKey string) *Client {
	return &Client{key: apiKey}
}

type SendingDomain struct {
	Domain string             `json:"domain"`
	DKIM   *SendingDomainDKIM `json:"dkim"`
}

type SendingDomainDKIM struct {
	Private string `json:"private"`
	Public  string `json:"public"`

	// Subdomain that will be used to verify; e.g.: scph0316
	Selector string `json:"selector"`

	// Colon separated list of headers to sign. SparkPost UI by default uses "from:to:subject:date"
	Headers string `json:"headers"`
}

func (c *Client) CreateSendingDomain(domain *SendingDomain) error {
	return errors.Trace(c.call("POST", "sending-domains", domain, nil))
}

type verificationRequest struct {
	DKIMVerify bool `json:"dkim_verify"`
	SPFVerify  bool `json:"spf_verify"`
}

type verificationResponse struct {
	Result *verificationResult `json:"results"`
}

type verificationResult struct {
	SPFStatus  string           `json:"spf_status"`
	DKIMStatus string           `json:"dkim_status"`
	DNS        *verificationDNS `json:"dns"`
}

type verificationDNS struct {
	SPFError  string `json:"spf_error"`
	DKIMError string `json:"dkim_error"`
}

type VerificationStatus struct {
	SPFStatus  string
	SPFError   string
	DKIMStatus string
	DKIMError  string
}

func (c *Client) VerifySendingDomain(domain string) (*VerificationStatus, error) {
	req := &verificationRequest{
		DKIMVerify: true,
		SPFVerify:  true,
	}
	resp := new(verificationResponse)
	if err := c.call("POST", fmt.Sprintf("sending-domains/%s/verify", domain), req, resp); err != nil {
		return nil, errors.Trace(err)
	}

	return &VerificationStatus{
		SPFStatus:  resp.Result.SPFStatus,
		SPFError:   resp.Result.DNS.SPFError,
		DKIMStatus: resp.Result.DKIMStatus,
		DKIMError:  resp.Result.DNS.DKIMError,
	}, nil
}

func (c *Client) call(method, endpoint string, request, response interface{}) error {
	buf := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buf).Encode(request); err != nil {
		return errors.Trace(err)
	}

	req, _ := http.NewRequest(method, fmt.Sprintf("https://api.sparkpost.com/api/v1/%s", endpoint), buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.key)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Trace(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Trace(err)
		}

		return errors.Errorf("sparkpost error: %s", content)
	}

	if response != nil {
		if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

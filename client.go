package sparkpost

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

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

// Generate a RSA key suitable for DKIM signing and return the private key, the
// public key and the error.
func GenerateDKIMKey() (string, string, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return "", "", errors.Trace(err)
	}
	privEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	pubKeyASN1, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", errors.Trace(err)
	}
	pubEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyASN1,
	})

	private := strings.Split(string(privEncoded), "\n")
	private = private[1 : len(private)-2]

	public := strings.Split(string(pubEncoded), "\n")
	public = public[1 : len(public)-2]

	return strings.Join(private, ""), strings.Join(public, ""), nil
}

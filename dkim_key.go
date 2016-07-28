package sparkpost

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/juju/errors"
)

// GenerateDKIMKey generates a RSA key suitable for DKIM signing and return
// the private key, the public key and the error.
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

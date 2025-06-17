// Package bocalmail provides a simple email client for sending emails. Used for testing.
package bocalmail

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-smtp"
)

const (
	SendSuccess SendResult = "Success"
	SendFailure SendResult = "Failure"
)

type SendResult string

type Scenario struct {
	Name       string
	Smtpmfrom  string
	FromHeader string
	DkimDomain string
	DkimSign   bool
	ExpectPass bool
}

// CreateEmailBody creates an email body.
func CreateEmailBody() string {
	// Needs NOT to end with \r\n.
	return "This is a test email for DMARC verification.\r\n"
}

// CreateEmailHeaders creates email headers.
func CreateEmailHeaders(sc Scenario, toHeader string) string {
	fromHeader := sc.FromHeader
	subject := fmt.Sprintf("Test Email %s", time.Now().Format(time.RFC1123Z))
	date := time.Now().Format(time.RFC1123Z)
	messageID := fmt.Sprintf("<%d@example.com>", time.Now().UnixNano())

	return fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"Date: %s\r\n"+
			// Needs to end with \r\n.
			"Message-ID: %s\r\n",
		fromHeader, toHeader, subject, date, messageID)
}

// SignWithDKIM signs an email with a private DKIM key.
func SignWithDKIM(emailString, dkimDomain, dkimSelector string,
	privateKey crypto.Signer) ([]byte, error) {
	options := &dkim.SignOptions{
		Domain:                 dkimDomain,
		Selector:               dkimSelector,
		Signer:                 privateKey,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		// SEE HEADERS IN createEmailHeaders()!
		HeaderKeys: []string{"From", "To", "Subject", "Date", "Message-ID"},
	}

	var signedBuf bytes.Buffer
	if err := dkim.Sign(&signedBuf, strings.NewReader(emailString), options); err != nil {
		return nil, err
	}

	return signedBuf.Bytes(), nil
}

// SendEmail sends an email.
// If sending fails, it returns SendFailure.
//
// If everything is successful, it returns, SendResult will contain the status text response from the SMTP server.
func SendEmail(
	cert tls.Certificate,
	addr string,
	email []byte,
	smtpmfrom, rcpt string,
) (SendResult, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // Same as in 'bocal-smtpd'
		//nolint:gosec // For testing purposes only.
		InsecureSkipVerify: true,        // WARNING: Only for testing! Do NOT use in production.
		ServerName:         "localhost", // ServerName should match the CN of the server certificate
	}

	c, err := smtp.DialStartTLS(addr, tlsConfig)
	if err != nil {
		return SendFailure, err
	}

	defer func() {
		if qErr := c.Quit(); qErr != nil {
			err = errors.Join(qErr)
		}
	}()

	if err = c.Mail(smtpmfrom, nil); err != nil {
		return SendFailure, err
	}

	if err = c.Rcpt(rcpt, nil); err != nil {
		return SendFailure, err
	}

	wc, err := c.Data()
	if err != nil {
		return SendFailure, err
	}

	_, err = wc.Write(email)
	if err != nil {
		return SendFailure, err
	}

	cmd, err := wc.CloseWithResponse()
	if err != nil {
		return SendFailure, err
	}

	return SendResult(cmd.StatusText), nil
}

// LoadPrivateKey loads a private key.
func LoadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	privateKeyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	var privateKey *rsa.PrivateKey

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parsse key as PKCS#8: %w", err)
	}

	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("parsed private key is not an RSA private key")
	}

	return privateKey, nil
}

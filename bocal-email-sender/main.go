package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
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

type scenario struct {
	name       string
	smtpmfrom  string
	fromHeader string
	dkimDomain string
	dkimSign   bool
	expectPass bool
}

func main() {
	dkimPrivateKey, err := loadPrivateKey("/app/keys/dkim.private")
	if err != nil {
		log.Fatalf("Failed to load DKIM key: %v", err)
	}

	// Test scenarios
	scenarios := []scenario{
		{
			name:       "Valid SPF and DKIM",
			smtpmfrom:  "sender@example.com",
			fromHeader: "sender@example.com",
			dkimDomain: "example.com",
			dkimSign:   true,
			expectPass: true,
		},
		{
			name:       "SPF Pass, DKIM Fail",
			smtpmfrom:  "sender@example.com",
			fromHeader: "sender@example.com",
			dkimDomain: "",
			dkimSign:   false,
			expectPass: true,
		},
		{
			name:       "SPF Fail, DKIM Pass",
			smtpmfrom:  "sender@test.com", // Different from SPF domain
			fromHeader: "sender@example.com",
			dkimDomain: "example.com",
			dkimSign:   true,
			expectPass: true,
		},
		{
			name:       "SPF and DKIM Fail",
			smtpmfrom:  "sender@test.com",
			fromHeader: "sender@example.com",
			dkimDomain: "",
			dkimSign:   false,
			expectPass: false,
		},
		{
			name:       "Domain Alignment Fail",
			smtpmfrom:  "sender@example.com",
			fromHeader: "sender@test.com", // Misaligned
			dkimDomain: "example.com",
			dkimSign:   true,
			expectPass: false,
		},
	}

	for i, scenario := range scenarios {
		if i > 0 {
			log.Println()
		}

		log.Printf("running scenario %d: %s", i, scenario.name)

		toHeader := "user@usermail.bocal.fyi"
		emailBody := createEmailBody()
		emailHeaders := createEmailHeaders(scenario, toHeader)
		emailString := emailHeaders + "\r\n" + emailBody
		dkimSelectorField := "selector"

		var finalEmail []byte
		if scenario.dkimSign {
			signed, signErr := signWithDKIM(
				emailString,
				scenario.dkimDomain,
				dkimSelectorField,
				dkimPrivateKey,
			)
			if signErr != nil {
				log.Printf("Failed to sign email: %v", signErr)
				continue
			}

			finalEmail = signed
		} else {
			finalEmail = []byte(emailString)
		}

		res, sendErr := sendEmail(finalEmail, scenario.smtpmfrom, toHeader)
		if sendErr != nil {
			log.Printf("Failed to send email: %v, %v", sendErr, res)
			log.Printf("Got: %v, expected result: %v", res, scenario.expectPass)
			if scenario.expectPass {
				log.Print("ERROR! expected failure")
			}
			continue
		}

		log.Printf("Email sent. Got: %v, expected result: %v", res, scenario.expectPass)
		if !scenario.expectPass {
			log.Print("ERROR! expected pass")
		}

		time.Sleep(1 * time.Second)
	}
}

// createEmailBody creates an email body.
func createEmailBody() string {
	// Needs NOT to end with \r\n.
	return "This is a test email for DMARC verification.\r\n"
}

// createEmailHeaders creates email headers.
func createEmailHeaders(sc scenario, toHeader string) string {
	fromHeader := sc.fromHeader
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

// signWithDKIM signs an email with a private DKIM key.
func signWithDKIM(emailString, dkimDomain, dkimSelector string,
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

// sendEmail sends an email.
func sendEmail(email []byte, smtpmfrom, rcpt string) (SendResult, error) {
	smtpSrv := os.Getenv("SMTP_SERVER")
	smtpPort := os.Getenv("SMTP_PORT")

	if len(smtpSrv) == 0 {
		log.Fatal("SMTP_SERVER not set")
	}

	if len(smtpPort) == 0 {
		log.Fatal("SMTP_SERVER not set")
	}

	addr := fmt.Sprintf("%s:%s", smtpSrv, smtpPort)

	cert, err := tls.LoadX509KeyPair("/app/certs/client.crt", "/app/certs/client.key")
	if err != nil {
		return SendFailure, fmt.Errorf("failed to load client certificates: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS13, // Same as in 'bocal-smtpd'
		InsecureSkipVerify: true,             // WARNING: Only for testing! Do NOT use in production.
		ServerName:         "localhost",      // ServerName should match the CN of the server certificate
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

	status := cmd.StatusText
	return SendResult(status), nil
}

// loadPrivateKey loads a private key.
func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
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

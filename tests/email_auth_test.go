package emailauth_test

import (
	"crypto/rsa"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"

	"bocal.fyi/mail-server/internal/bocalmail"
)

var AuthScenarios = []bocalmail.Scenario{
	{
		Name:       "Valid SPF, Valid DKIM",
		Smtpmfrom:  "sender@example.com",
		FromHeader: "sender@example.com",
		DkimDomain: "example.com",
		DkimSign:   true,
		ExpectPass: true,
	},
	{
		Name:       "SPF Pass, DKIM Fail",
		Smtpmfrom:  "sender@example.com",
		FromHeader: "sender@example.com",
		DkimDomain: "",
		DkimSign:   false,
		ExpectPass: true,
	},
	{
		Name:       "SPF Fail, DKIM Pass",
		Smtpmfrom:  "sender@test.com", // SPF misaligned, different from Smtpmfrom.
		FromHeader: "sender@example.com",
		DkimDomain: "example.com",
		DkimSign:   true,
		ExpectPass: true,
	},
	{
		Name:       "SPF Fail, DKIM Fail",
		Smtpmfrom:  "sender@test.com",
		FromHeader: "sender@example.com", // SPF misaligned, different from Smtpmfrom.
		DkimDomain: "",
		DkimSign:   false,
		ExpectPass: false,
	},
}

var (
	DKIMPrivateKey  *rsa.PrivateKey
	buildBocalSmtpd bool
)

func init() {
	flag.BoolVar(&buildBocalSmtpd, "build-bocal-smtpd", false, "Build bocal-smtpd before tests")
}

func TestMain(m *testing.M) {
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("=== Setting up test environment ===")
	logger.Info("flags", slog.Bool("build-bocal-smtpd", buildBocalSmtpd))

	scriptPath := "./prepare-test-env.sh"
	args := []string{}
	if buildBocalSmtpd {
		args = append(args, "--build-bocal-smtpd")
	}
	cmd := exec.Command(scriptPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = "../"
	logger.Info("Running setup script", slog.String("script", scriptPath))
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to set up test environment", slog.Any("error", err))
		os.Exit(1)
	}
	logger.Info("Test environment setup complete.")

	// Load the DKIM private key from the host filesystem once
	hostPrivateKeyPath := "../dns/keys/dkim.private"
	var err error
	DKIMPrivateKey, err = bocalmail.LoadPrivateKey(hostPrivateKeyPath)
	if err != nil {
		logger.Error(
			"Failed to load DKIM private key for tests",
			slog.Any("error", err),
			slog.String("path", hostPrivateKeyPath),
		)
	}

	code := m.Run()
	os.Exit(code)
}

func TestEmailAuthScenarios(t *testing.T) {
	cert, err := tls.LoadX509KeyPair(
		"../internal/bocalmail/fullchain.pem",
		"../internal/bocalmail/privatekey.pem",
	)
	if err != nil {
		t.Fatal("Failed to load certificates for sendMail tls", err)
	}

	t.Parallel()
	for i, scenario := range AuthScenarios {
		t.Run(fmt.Sprintf("Scenario %d: %s", i+1, scenario.Name), func(t *testing.T) {
			t.Parallel()

			// The part before the domain is the eid of a feed.
			// Make sure to use a real eid to add content to the database.
			toHeader := "2188676a-34ed-404a-888c-05ba461aebef@usermail.bocal.fyi"
			emailBody := bocalmail.CreateEmailBody()
			emailHeaders := bocalmail.CreateEmailHeaders(scenario, toHeader)
			emailString := emailHeaders + "\r\n" + emailBody

			var finalEmail []byte
			if scenario.DkimSign {
				signed, signErr := bocalmail.SignWithDKIM(
					emailString,
					scenario.DkimDomain,
					"selector",
					DKIMPrivateKey,
				)
				if signErr != nil {
					t.Fatal("Failed to sign email", signErr)
				}
				finalEmail = signed
			} else {
				finalEmail = []byte(emailString)
			}

			statusText, sErr := bocalmail.SendEmail(
				cert,
				"127.0.0.1:465",
				finalEmail,
				scenario.Smtpmfrom,
				toHeader,
			)
			if scenario.ExpectPass {
				if sErr != nil {
					t.Errorf(
						"Scenario '%s': Expected successful send, but received error: %v",
						scenario.Name,
						sErr,
					)
				}

				if sErr == nil {
					if !strings.HasPrefix(string(statusText), "2") {
						t.Errorf(
							"Scenario '%s': Expected 2xx success status, but got '%s'",
							scenario.Name,
							statusText,
						)
					} else {
						t.Logf("Scenario '%s': Email sent successfully as expected (Status: '%s').", scenario.Name, statusText)
					}
				}
			}

			if !scenario.ExpectPass {
				if sErr == nil {
					t.Errorf(
						"Scenario '%s': Expected an error, but the email was sent successfully (Status: '%s').",
						scenario.Name,
						statusText,
					)
				} else {
					t.Logf("Scenario '%s': Received expected error: %v", scenario.Name, sErr)
				}
			}
		})
	}
}

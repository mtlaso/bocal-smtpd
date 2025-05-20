package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wttw/spf"
	"golang.org/x/net/publicsuffix"
)

const (
	timeout        = time.Second * 20
	maxMessageSize = 1024 * 1024 // 1 MB
	// 451 Requested action aborted: local error in processing.
	codeRequestedActionAborted = 451
	codeDeferred               = 451
	codeRejected               = 550
)

var (
	errInternalServer = &smtp.SMTPError{
		Code:    codeRequestedActionAborted,
		Message: "Internal server error",
	}

	errTempfail = &smtp.SMTPError{
		Code:    codeDeferred,
		Message: "Temporary authentication failure",
	}

	errNoFromHeader = &smtp.SMTPError{
		Code:    codeRequestedActionAborted,
		Message: "No From header",
	}

	errReject = &smtp.SMTPError{
		Code:    codeRejected,
		Message: "Email rejected due to DMARC policy",
	}
)

func defaultDmarcRecord() *dmarc.Record {
	return &dmarc.Record{
		Policy:        dmarc.PolicyNone,
		SPFAlignment:  dmarc.AlignmentRelaxed,
		DKIMAlignment: dmarc.AlignmentRelaxed,
	}
}

// The Backend implements SMTP server methods.
type Backend struct {
	logger *slog.Logger
	dbURL  string
}

// NewSession is called after client greeting (EHLO, HELO).
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	// TODO: do a PTR check?
	// net.LookupAddr(addr string)
	remoteAddr, ok := c.Conn().RemoteAddr().(*net.TCPAddr)
	var clientIP net.IP
	if ok {
		clientIP = remoteAddr.IP
	}

	return &Session{
		clientIP: clientIP,
		logger:   b.logger,
		helo:     c.Hostname(),
		traceID:  uuid.NewString(),
		dbURL:    b.dbURL,
	}, nil
}

// Session is returned after successful login.
//
// https://dmarc.org/presentations/Email-Authentication-Basics-2015Q2.pdf
type Session struct {
	// smtpmfrom is the value of MAIL FROM/FROM command/envelope sender domain (sent during smtp conversation).
	// It is described in RFC 5321 2.3.1.
	//
	// It is NOT the "From" header in the email message content.
	// E.g: 123@example.com.
	smtpmfrom string
	helo      string
	// rcpts is a slice of recipients because a newsletter could be sent to multiple recipients.
	rcpts    []string
	clientIP net.IP
	logger   *slog.Logger
	traceID  string
	dbURL    string
}

// SpfAlignment checks SPF is aligned. Returns true if SPF is aligned.
//
// smtp.mfrom domain must match RFC5322.From domain.
// https://dmarc.org/presentations/Email-Authentication-Basics-2015Q2.pdf p.42.
func (s *Session) SpfAlignment(smtpmfromDomain, fromDomain string, dmarcPolicy *dmarc.Record) bool {
	switch dmarcPolicy.SPFAlignment {
	case dmarc.AlignmentStrict:
		// Require exact match.
		// As per https://dmarc.org/presentations/Email-Authentication-Basics-2015Q2.pdf, p.42.
		return strings.EqualFold(smtpmfromDomain, fromDomain)
	default:
		// Default is AlignmentRelaxed.
		// As per https://dmarc.org/presentations/Email-Authentication-Basics-2015Q2.pdf, p.50.
		smtpfromOrg, err := publicsuffix.EffectiveTLDPlusOne(smtpmfromDomain)
		if err != nil {
			s.logger.Error(
				"SpfAlignement: Failed to get organizational domain for smtpmfrom",
				slog.String("traceID", s.traceID),
				slog.String("domain", smtpmfromDomain),
				slog.Any("error", err),
			)
			return false
		}

		fromOrg, err := publicsuffix.EffectiveTLDPlusOne(fromDomain)
		if err != nil {
			s.logger.Error(
				"SpfAlignement: Failed to get organizational domain for From header",
				slog.String("traceID", s.traceID),
				slog.String("domain", fromDomain),
				slog.Any("error", err),
			)
			return false
		}

		s.logger.Debug(
			"SpfAlignement: Relaxed check",
			slog.String("traceID", s.traceID),
			slog.String("mailFromOrg", smtpfromOrg),
			slog.String("fromOrg", fromOrg),
		)

		return strings.EqualFold(smtpfromOrg, fromOrg)
	}
}

// DkimAlignmentAndPass checks if ANY valid DKIM signature aligns with the From domain.
// Returns true if at least one valid signature aligns.
//
// https://dmarc.org/presentations/Email-Authentication-Basics-2015Q2.pdf p.42.
func (s *Session) DkimAlignmentAndPass(
	dkimVerifications []*dkim.Verification,
	fromDomain string,
	dmarcPolicy *dmarc.Record,
) bool {
	for _, verification := range dkimVerifications {
		// Found ONE valid signature.
		if verification.Err == nil {
			switch dmarcPolicy.DKIMAlignment {
			case dmarc.AlignmentStrict:
				// Require exact match.
				// As per https://dmarc.org/presentations/Email-Authentication-Basics-2015Q2.pdf, p.42.
				return strings.EqualFold(verification.Domain, fromDomain)

			default:
				// Default is AlignmentRelaxed.
				// As per https://dmarc.org/presentations/Email-Authentication-Basics-2015Q2.pdf, p.50.
				dkimDomainOrg, err := publicsuffix.EffectiveTLDPlusOne(verification.Domain)
				if err != nil {
					s.logger.Error(
						"DkimAlignement: Failed to get organizational domain for DKIM DOMAIN (d=)",
						slog.String("traceID", s.traceID),
						slog.String("domain", verification.Domain),
						slog.Any("error", err),
					)
					return false
				}

				fromDomainOrg, err := publicsuffix.EffectiveTLDPlusOne(fromDomain)
				if err != nil {
					s.logger.Error(
						"DkimAlignement: Failed to get organizational domain for From header",
						slog.String("traceID", s.traceID),
						slog.String("domain", fromDomain),
						slog.Any("error", err),
					)
					return false
				}

				return strings.EqualFold(dkimDomainOrg, fromDomainOrg)
			}
		}
	}

	return false
}

// AuthMechanisms returns a slice of available auth mechanisms; only PLAIN is
// supported in this example.
func (s *Session) AuthMechanisms() []string {
	return []string{}
}

// Auth is the handler for supported authenticators.
func (s *Session) Auth(_ string) (sasl.Server, error) {
	return nil, errors.New("unsupported mechanism")
}

// Mail is the handler for MAIL command.
func (s *Session) Mail(from string, _ *smtp.MailOptions) error {
	// log.Printf("Session from %s: Mail from: %v \n", s.clientIP, from)
	s.logger.Info("MAIL CMD",
		slog.String("traceID", s.traceID),
		slog.Any("client IP", s.clientIP),
		slog.Any("mail from", from),
	)
	s.smtpmfrom = from
	// Empty for a new transaction.
	// RFC5321 3.3:
	// This command (MAIL FROM) tells the SMTP-receiver that a new mail transaction is
	// starting and to reset all its state tables and buffers, including any
	// recipients or mail data.
	s.rcpts = []string{}
	return nil
}

// Rcpt is the handler for RCPT command.
func (s *Session) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.logger.Info("RCPT CMD",
		slog.String("traceID", s.traceID),
		slog.Any("client IP", s.clientIP),
		slog.Any("smtpmfrom", s.smtpmfrom),
		slog.Any("mail to", to),
	)

	if strings.HasSuffix(to, "@usermail.bocal.fyi") {
		s.rcpts = append(s.rcpts, to)
	}

	return nil
}

// Data is the handler for DATA command.
func (s *Session) Data(r io.Reader) error {
	// Save r io.Reader to an unconsumed buffer
	// so that reading from it can be repeated without modifying the original data.
	var emailBuf bytes.Buffer
	if _, err := io.Copy(&emailBuf, r); err != nil {
		s.logger.Error("DATA: failed to read email",
			slog.String("traceID", s.traceID),
			slog.Any("error", err))
		return errInternalServer
	}

	s.logger.Info("DATA CMD",
		slog.String("traceID", s.traceID),
		slog.Any("client IP", s.clientIP),
		slog.Any("smtpmfrom", s.smtpmfrom),
		slog.Any("rcpts", s.rcpts),
		slog.Int("length", emailBuf.Len()))

	// Parse email.
	emailMessage, err := mail.ReadMessage(bytes.NewReader(emailBuf.Bytes()))
	if err != nil {
		s.logger.Error("DATA: failed to read email",
			slog.String("traceID", s.traceID),
			slog.Any("error", err))
		return errInternalServer
	}

	fromHeader := emailMessage.Header.Get("From")
	if fromHeader == "" {
		s.logger.Error("DATA: missing From header in the message",
			slog.String("traceID", s.traceID),
		)
		// TODO: is this code correct?
		// As per RFC 7489 > 6.6.1
		// > Messages that have no RFC5322.From field at all are typically rejected, since that form is forbidden under RFC 5322 [MAIL];
		return errNoFromHeader
	}

	fromAddr, err := mail.ParseAddress(fromHeader)
	if err != nil {
		s.logger.Error("DATA: failed to parse From header",
			slog.String("traceID", s.traceID),
			slog.Any("error", err))
		return errInternalServer
	}

	fromDomain := strings.Split(fromAddr.Address, "@")[1]

	if len(s.smtpmfrom) == 0 || s.smtpmfrom == "<>" {
		s.logger.Error("DATA: invalid smtpmfrom",
			slog.String("traceID", s.traceID),
			slog.Any("smtpmfrom", s.smtpmfrom))
		return errInternalServer
	}
	smtpmfromDomain := strings.Split(s.smtpmfrom, "@")[1]

	// SPF.
	// s.helo: Fallback to the RFC5321.HELO domain for a “null sender”.
	// https://dmarc.org/presentations/Email-Authentication-Basics-2015Q2.pdf, p.16.
	spfResult, explanation := spf.Check(context.Background(), s.clientIP, s.smtpmfrom, s.helo)
	s.logger.Info("DATA: spf",
		slog.String("traceID", s.traceID),
		slog.Any("result", spfResult),
		slog.Any("error", explanation),
	)

	// DKIM.
	// Doc: Why can't I verify a net/mail.Message directly? A net/mail.Message header is already parsed, and whitespace characters (especially continuation lines) are removed.
	dkimVerifications, dkimErr := dkim.Verify(bytes.NewReader(emailBuf.Bytes()))
	if dkimErr != nil {
		s.logger.Error("DATA: DKIM verification failed",
			slog.String("traceID", s.traceID),
			slog.Any("error", dkimErr))
	} else {
		s.logger.Info("DATA: DKIM verification results",
			slog.String("traceID", s.traceID),
			slog.Int("signatures", len(dkimVerifications)))
		for i, v := range dkimVerifications {
			s.logger.Info("DATA: DKIM signature result",
				slog.String("traceID", s.traceID),
				slog.Int("index", i),
				slog.String("domain", v.Domain),
				slog.String("selector", v.Identifier),
				slog.Any("error", v.Err))
		}
	}

	// DMARC.
	// DMARC operates on the 'From:' email header.
	var dmarcRecord *dmarc.Record
	dmarcRecord, dmarcErr := dmarc.Lookup(strings.Split(fromAddr.Address, "@")[1])
	if dmarcErr != nil {
		s.logger.Error("DATA: failed to lookup DMARC",
			slog.String("traceID", s.traceID),
			slog.Any("error", dmarcErr))
	}
	if dmarcRecord == nil {
		s.logger.Warn("DATA: no DMARC record found, using default one",
			slog.String("traceID", s.traceID),
		)
		dmarcRecord = defaultDmarcRecord()
	}

	s.logger.Info("DATA: dmarc record",
		slog.String("traceID", s.traceID),
		slog.Any("result", dmarcRecord),
	)

	// DMARC auth evaluation.
	isDkimAlignedAndPassed := s.DkimAlignmentAndPass(dkimVerifications, fromDomain, dmarcRecord)
	isSpfAligned := s.SpfAlignment(smtpmfromDomain, fromDomain, dmarcRecord)
	s.logger.Info("DATA: Alignment results",
		slog.String("traceID", s.traceID),
		slog.Bool("spf domain alignment", isSpfAligned),
		slog.Bool("dkim alignment and pass", isDkimAlignedAndPassed),
		slog.String("spf result", spfResult.String()),
	)

	dmarcResult := checkDmarc(isSpfAligned, isDkimAlignedAndPassed, spfResult, dkimErr, dmarcErr, dmarcRecord)
	s.logger.Info("DATA: DMARC result",
		slog.String("traceID", s.traceID),
		slog.String("outcome", string(dmarcResult.Outcome)),
		slog.String("action", string(dmarcResult.Action)),
	)
	switch dmarcResult.Action {
	case ActionReject:
		return errReject
	case ActionQuarantine:
		// Process the email but mark it as suspicious/spam in your system
		// You might want to add headers or flags for your processing system
		// ...
		return nil
	case ActionDefer:
		return errTempfail

	case ActionAccept:
		for _, rcpt := range s.rcpts {
			go func(emailMessage *mail.Message, rcpt string) {
				if pErr := s.processEmail(emailMessage, rcpt); pErr != nil {
					s.logger.Error(
						"Failed to process email",
						slog.String("traceID", s.traceID),
						slog.Any("error", pErr),
					)
				}
			}(emailMessage, rcpt)
		}
		return nil
	}

	return nil
}

// processEmail will process the email.
// It takes the email and adds it to the database.
func (s *Session) processEmail(emailMessage *mail.Message, rcpt string) error {
	dbpool, err := pgxpool.New(context.Background(), s.dbURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer dbpool.Close()

	// Find the feed id with the rcpt.
	// The 'rcpt' is the eid (external id) of a feed.
	var feedID string
	feedEID := strings.Split(rcpt, "@")[0]
	err = dbpool.QueryRow(context.Background(), `
		SELECT id
		FROM feeds
		WHERE eid = $1`, feedEID).Scan(&feedID)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	s.logger.Info("Found feed id", slog.String("id", feedID), slog.String("rcpt", rcpt))

	// Add content to 'feeds_content'.
	url := fmt.Sprintf("https://bocal.fyi/userfeeds/%s/content/%s", feedEID, uuid.NewString())
	date := time.Now()
	title := emailMessage.Header.Get("Subject")
	var content []byte
	content, err = io.ReadAll(emailMessage.Body)
	if err != nil {
		// Content is optional if it cannot be read.
		s.logger.Warn("could not read email content", slog.Any("error", err))
		content = []byte{}
	}

	cmdTag, err := dbpool.Exec(context.Background(), `
		INSERT INTO feeds_content ("feedId", date, url, title, content)
		VALUES($1, $2, $3, $4, $5)`,
		feedID,
		date,
		url,
		title,
		string(content),
	)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	if cmdTag.RowsAffected() != 1 {
		return fmt.Errorf("nothing was inserted %w", err)
	}

	return nil
}

func (s *Session) Reset() {
	s.logger.Info("Reset",
		slog.String("traceID", s.traceID),
	)
	s.smtpmfrom = ""
	s.rcpts = []string{}
	s.traceID = ""
}

func (s *Session) Logout() error {
	s.logger.Info("Logout")
	return nil
}

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if len(dbURL) == 0 {
		log.Fatal("DATABASE_URL not set")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	be := &Backend{
		logger: logger,
		dbURL:  dbURL,
	}
	server := smtp.NewServer(be)

	server.Addr = "0.0.0.0:1025"
	server.Domain = "localhost"
	server.WriteTimeout = timeout
	server.ReadTimeout = timeout
	server.MaxMessageBytes = maxMessageSize
	server.MaxRecipients = 50

	// TLS config.
	server.AllowInsecureAuth = false
	certPath := os.Getenv("TLS_CERT_PATH")
	keyPath := os.Getenv("TLS_KEY_PATH")

	if len(certPath) == 0 {
		log.Fatal("TLS_CERT_PATH not set")
	}

	if len(keyPath) == 0 {
		log.Fatal("TLS_KEY_PATH not set")
	}

	// TODO: load production certificates.
	// Make sure that docker reloads after loading the certificates because the certificates are automatically renewed every n (e.g., 90) days (see cerbot).
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatal(err)
	}
	server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}

	logger.Info("SMTP server started at", slog.Any("addr", server.Addr))
	if err = server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

type Outcome string

const (
	// OutcomePass indicates that authentication passed (SPF or DKIM aligned and passed).
	OutcomePass Outcome = "Pass"

	// OutcomeFail Authentication failed (neither SPF nor DKIM aligned and passed).
	OutcomeFail Outcome = "Fail"

	// OutcomeTempError Temporary error occurred during verification.
	OutcomeTempError Outcome = "TempError"

	// OutcomePermError Permanent error occurred during verification.
	OutcomePermError Outcome = "PermError"

	// OutcomeNoPolicy No DMARC policy found for the domain.
	OutcomeNoPolicy Outcome = "NoPolicy"
)

type Action string

const (
	// ActionAccept Process the message normally.
	ActionAccept Action = "Accept"

	// ActionQuarantine Process the message but mark as suspicious (e.g., spam folder).
	ActionQuarantine Action = "Quarantine"

	// ActionReject Reject the message with a 5xx error.
	ActionReject Action = "Reject"

	// ActionDefer Temporarily reject with a 4xx error (try again later).
	ActionDefer Action = "Defer"
)

// DmarcResult represents the DMARC authentication result.
type DmarcResult struct {
	// Outcome represents the DMARC authentication result:
	Outcome Outcome

	// Action represents what the receiver should do with the message:
	Action Action
}

// checkDmarc checks the DMARC policy and returns the DMARC auth outcome.
//
// Flow:
//
// 1. If everything passes (DMARC Outcome is Pass): Process the email normally.
//
// 2. If not everything passes, check if it was some kind of error (DMARC Outcome is TempError or PermError):
//  2. 1 If TempError: Return a 4xx temporary error (defer).
//  2. 2 If PermError: Process (typically), potentially marking as suspicious.
//
// 3. If it failed because it only did not pass (DMARC Outcome is Fail),
// and the dmarc policy is either None or Quarantine: Process the email (potentially marking as spam/suspicious). (If the policy were Reject, you would reject instead of processing).
func checkDmarc(
	isSpfAligned, isDkimAlignedAndPassed bool,
	spfResult spf.ResultType,
	dkimErr error,
	dmarcErr error,
	dmarcRecord *dmarc.Record,
) DmarcResult {
	// (SPF passes AND aligns) OR (DKIM verifies AND aligns).
	if (spfResult == spf.Pass && isSpfAligned) || isDkimAlignedAndPassed {
		return DmarcResult{Outcome: OutcomePass, Action: ActionAccept}
	}

	// At this point, DMARC auth did not pass.
	// Check for errors or failure that dictate DMARC outcome.

	// Check for TEMPORARY errors first.
	if spfResult == spf.Temperror || (dkimErr != nil && dkim.IsTempFail(dkimErr)) ||
		(dmarcErr != nil && dmarc.IsTempFail(dmarcErr)) {
		return DmarcResult{Outcome: OutcomeTempError, Action: ActionDefer}
	}

	// Check for PERMANENT errors.
	// DMARC doensn't have a IsPermFailI() method.
	if spfResult == spf.Permerror || (dkimErr != nil && dkim.IsPermFail(dkimErr)) {
		// Letting Permerror pass may be a security risk because:
		// 1. Misconfiguration Exploitation: Attackers could deliberately exploit misconfigured DMARC, SPF, or DKIM settings to bypass authentication.
		// 2. False Sense of Security: Domain owners might believe they're protected by DMARC when in fact their misconfiguration means emails are being accepted despite authentication failures.
		// 3. Bypass through Deliberate Errors: In some cases, attackers might be able to craft messages that trigger permanent errors rather than clear failures.
		// But:
		// 1. Avoiding False Positives: Rejecting all emails with permanent errors could block legitimate emails due to DNS issues or misconfiguration.
		// 2. Gradual Adoption: DMARC was designed for gradual adoption, allowing domain owners to monitor before enforcing strict policies.
		// 3. Domain Owner Control: The philosophy is that domain owners should decide the policy through their DMARC record, not receiving servers
		return DmarcResult{Outcome: OutcomePermError, Action: ActionQuarantine}
	}

	// Check for NoPolicy.
	if errors.Is(dmarcErr, dmarc.ErrNoPolicy) {
		// TODO: mark as suspicious and show in UI?
		return DmarcResult{Outcome: OutcomeNoPolicy, Action: ActionAccept}
	}

	// Apply DMARC Policy based on Outcome and dmarcPolicy.
	// At this point, the DMARC policy is a fail.
	switch dmarcRecord.Policy {
	case dmarc.PolicyNone:
		return DmarcResult{Outcome: OutcomeFail, Action: ActionAccept}
	case dmarc.PolicyQuarantine:
		return DmarcResult{Outcome: OutcomeFail, Action: ActionQuarantine}
	case dmarc.PolicyReject:
		return DmarcResult{Outcome: OutcomeFail, Action: ActionReject}
	default:
		return DmarcResult{Outcome: OutcomeFail, Action: ActionAccept}
	}
}

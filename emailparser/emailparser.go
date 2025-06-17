// Package emailparser provides functionality to parse email messages.
//
// Ressource: https://github.com/kirabou/parseMIMEemail.go?tab=readme-ov-file.
package emailparser

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"os"
	"strings"
)

var ErrInvalidBoundary = errors.New("invalid boundary: multipart content requires a boundary parameter")

type Parser struct {
	log *slog.Logger
}

// New creates a new email parser.
func New() *Parser {
	defaultLogger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	return &Parser{
		log: defaultLogger,
	}
}

// SetLogger sets a custom structured logger for the parser.
func (p *Parser) SetLogger(logger *slog.Logger) {
	p.log = logger
}

type Email struct {
	// Message is the original email message.
	Message     *mail.Message
	ContentType string
	// Parts represents the MIME parts of an email.
	Parts       []EmailPart
	IsMultipart bool
}

type EmailPart struct {
	// Only defined for multipart emails (Email.IsMultipart).
	//
	// Headers in EmailPart = MIME part headers (the headers that appear after each boundary)
	//
	// Single-part emails (Content-Type: text/plain) have NO part headers.
	//
	// Only multipart emails have part headers.
	Headers textproto.MIMEHeader

	// Raw content.
	Content []byte

	// Only when IsHTML or IsText are true.
	DecodedContent string
	IsHTML         bool
	IsText         bool
	IsBinary       bool
	IsAttachment   bool

	// Only when IsAttachment is true.
	Filename string
}

// ParseEmail parses an email message.
// It takes the email content as a string.
func (p *Parser) ParseEmail(emailContent string) (*Email, error) {
	msg, err := mail.ReadMessage(strings.NewReader(emailContent))
	if err != nil {
		return nil, fmt.Errorf("error reading email: %w", err)
	}

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return nil, fmt.Errorf("error parsing media type (ParseEmail): %w", err)
	}

	email := &Email{
		Message:     msg,
		ContentType: mediaType,
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		email.IsMultipart = true
		parts, pErr := p.parseMultipart(email.Message.Body, params["boundary"])
		if pErr != nil {
			return nil, fmt.Errorf("error parsing multipart: %w", pErr)
		}

		email.Parts = parts
	} else {
		email.IsMultipart = false
		part, pErr := p.parseSinglePart(email.Message.Body, email.Message.Header)
		if pErr != nil {
			return nil, fmt.Errorf("error parsing single part: %w", pErr)
		}

		email.Parts = []EmailPart{*part}
	}

	return email, nil
}

// parseSinglePart parses a single part of a multipart message.
// It takes the message reader and the email headers to process the content.
func (p *Parser) parseSinglePart(msg io.Reader, emailHeaders mail.Header) (*EmailPart, error) {
	slurp, err := io.ReadAll(msg)
	if err != nil {
		return nil, fmt.Errorf("error reading content: %w", err)
	}

	// NO headers, because it's not a multipart email!!!.
	emailPart := &EmailPart{
		Content: slurp,
	}

	// Since a non multipart email doesn't have headers, we use the email headers to determine the content type.
	emailPart.IsHTML = strings.Contains(strings.ToLower(emailHeaders.Get("Content-Type")), "text/html")
	emailPart.IsText = strings.Contains(strings.ToLower(emailHeaders.Get("Content-Type")), "text/plain")

	if emailPart.IsText || emailPart.IsHTML {
		// Since a non multipart email doesn't have headers, we use the email headers to determine the content type.
		decoded, decodeErr := p.decodeContent(slurp, emailHeaders.Get("Content-Transfer-Encoding"))
		if decodeErr != nil {
			p.log.Error("error decoding content", slog.Any("error", decodeErr))
		} else {
			emailPart.DecodedContent = decoded
		}
	}
	return emailPart, nil
}

// parseMultipart parses a multipart message.
// It takes the message reader and the boundary string.
//
//nolint:gocognit // it's ok.
func (p *Parser) parseMultipart(msg io.Reader, boundary string) ([]EmailPart, error) {
	if boundary == "" {
		return nil, ErrInvalidBoundary
	}
	var parts []EmailPart
	reader := multipart.NewReader(msg, boundary)

	for {
		// `NextRawPart` is used instead of `NextPart` to get 'quoted-printable' encoded content.
		part, err := reader.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading reader part: %w", err)
		}

		// Check the Content-type because there could be nested parts.
		mediaType, params, mimeParseErr := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if mimeParseErr != nil {
			if cErr := part.Close(); cErr != nil {
				p.log.Error("error closing part", slog.Any("error", cErr))
			}
			return nil, fmt.Errorf("error parsing media type (parseMultipart): %w", mimeParseErr)
		}

		// Check if there are nested parts.
		if strings.HasPrefix(mediaType, "multipart/") {
			subParts, parseErr := p.parseMultipart(part, params["boundary"])
			if parseErr != nil {
				if cErr := part.Close(); cErr != nil {
					p.log.Error("error closing part", slog.Any("error", cErr))
				}
				return nil, fmt.Errorf("error processing subpart: %w", parseErr)
			}

			parts = append(parts, subParts...)

			if cErr := part.Close(); cErr != nil {
				p.log.Error("error closing part", slog.Any("error", cErr))
			}
			// Call continue to go to the next iteration of the loop.
			// If not called, it will reprocess the same part.
			continue
		}

		emailPart, err := p.processPart(part)
		if err != nil {
			return nil, fmt.Errorf("error processing part: %w", err)
		}

		parts = append(parts, *emailPart)

		if cErr := part.Close(); cErr != nil {
			p.log.Error("error closing part", slog.Any("error", cErr))
		}
	}

	return parts, nil
}

// processPart processes a part of an email message.
func (p *Parser) processPart(part *multipart.Part) (*EmailPart, error) {
	slurp, err := io.ReadAll(part)
	if err != nil {
		return nil, fmt.Errorf("error reading part (slurp): %w", err)
	}

	emailPart := EmailPart{
		Headers: part.Header,
		Content: slurp,
	}

	emailPart.IsHTML = strings.Contains(strings.ToLower(emailPart.Headers.Get("Content-Type")), "text/html")
	emailPart.IsText = strings.Contains(strings.ToLower(emailPart.Headers.Get("Content-Type")), "text/plain")
	emailPart.IsAttachment = p.isAttachment(emailPart.Headers)
	emailPart.IsBinary = !emailPart.IsHTML && !emailPart.IsText
	emailPart.Filename = part.FileName()

	// Only decode if the email part is text or HTML.
	if emailPart.IsText || emailPart.IsHTML {
		decoded, decodeErr := p.decodeContent(slurp, emailPart.Headers.Get("Content-Transfer-Encoding"))
		if decodeErr != nil {
			p.log.Error("error decoding content", slog.Any("error", decodeErr))
		} else {
			emailPart.DecodedContent = decoded
		}
	}

	return &emailPart, nil
}

// isAttachment checks if the email part is an attachment.
// Returns true if the email part is an attachment.
func (p *Parser) isAttachment(mimeHeaders textproto.MIMEHeader) bool {
	contentDisposition := mimeHeaders.Get("Content-Disposition")
	if contentDisposition == "" {
		return false
	}

	return strings.HasPrefix(strings.ToLower(contentDisposition), "attachment")
}

// decodeContent decodes the content of an email part.
// It takes the content bytes and the content transfer encoding string.
func (p *Parser) decodeContent(slurp []byte, contentTransferEncoding string) (string, error) {
	encoding := strings.ToLower(strings.TrimSpace(contentTransferEncoding))

	switch encoding {
	// 8BIT, 7BIT and BINARY imply no encoding were performed.
	case "7bit", "8bit", "binary", "":
		return string(slurp), nil
	// A binary-to-text encoding scheme is used.
	case "base64":
		// Clean up the base64 content (remove whitespace/newlines)
		cleaned := strings.ReplaceAll(string(slurp), "\n", "")
		cleaned = strings.ReplaceAll(cleaned, "\r", "")
		cleaned = strings.ReplaceAll(cleaned, " ", "")

		decoded, err := base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return "", fmt.Errorf("base64 decode error: %w", err)
		}
		return string(decoded), nil
	// A binary-to-text encoding scheme is used.
	case "quoted-printable":
		qpReader := quotedprintable.NewReader(strings.NewReader(string(slurp)))
		decoded, err := io.ReadAll(qpReader)
		if err != nil {
			return "", fmt.Errorf("quoted-printable decode error: %w", err)
		}
		return string(decoded), nil

	default:
		return string(slurp), fmt.Errorf("unknown encoding: %s", encoding)
	}
}

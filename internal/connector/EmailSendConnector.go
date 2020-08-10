package connector

import (
	"bytes"
	"context"
	"fmt"
	"net/smtp"
	"strings"
)

const (
	mime = "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
)

type EmailSender interface {
	SendEmail(ctx context.Context, to, cc, bcc []string, from, subject, body string) error
}

type Recipients struct {
	To map[string]bool
}

func (r *Recipients) AddAll(re []string) {
	for _, ri := range re {
		r.To[ri] = true
	}
}

func (r *Recipients) Recipients() []string {
	ret := make([]string, 0)
	for k, _ := range r.To {
		ret = append(ret, k)
	}
	return ret
}

type DummyMailSender struct {
	LastSentMail *DummyMail
}

type DummyMail struct {
	From    string
	To      string
	Cc      string
	Bcc     string
	Subject string
	Body    string
}

func (sender *DummyMailSender) SendEmail(ctx context.Context, to, cc, bcc []string, from, subject, body string) error {
	sender.LastSentMail = &DummyMail{
		From:    from,
		Subject: subject,
		Body:    body,
	}
	if to != nil {
		sender.LastSentMail.To = strings.Join(to, ",")
	}
	if cc != nil {
		sender.LastSentMail.Cc = strings.Join(cc, ",")
	}
	if bcc != nil {
		sender.LastSentMail.Bcc = strings.Join(bcc, ",")
	}
	return nil
}

type SendMailSender struct {
	Host     string
	Port     int
	User     string
	Password string
}

func (sender *SendMailSender) SendEmail(ctx context.Context, to, cc, bcc []string, from, subject, body string) error {

	auth := smtp.PlainAuth("", sender.User, sender.Password, sender.Host)
	rec := &Recipients{
		To: make(map[string]bool),
	}
	var bodyBuffer bytes.Buffer
	if to != nil && len(to) > 0 {
		rec.AddAll(to)
		bodyBuffer.WriteString("To: ")
		bodyBuffer.WriteString(strings.Join(to, ","))
		bodyBuffer.WriteString("\r\n")
	}

	if cc != nil && len(cc) > 0 {
		rec.AddAll(cc)
		bodyBuffer.WriteString("Cc: ")
		bodyBuffer.WriteString(strings.Join(cc, ","))
		bodyBuffer.WriteString("\r\n")
	}
	if bcc != nil && len(bcc) > 0 {
		rec.AddAll(bcc)
		bodyBuffer.WriteString("\r\n")
	}
	bodyBuffer.WriteString("Subject: ")
	bodyBuffer.WriteString(subject)
	bodyBuffer.WriteString("\r\n\r\n")
	bodyBuffer.WriteString(mime)
	bodyBuffer.WriteString("\r\n")
	bodyBuffer.WriteString(body)

	err := smtp.SendMail(fmt.Sprintf("%s:%d", sender.Host, sender.Port), auth, from, rec.Recipients(), bodyBuffer.Bytes())
	if err != nil {
		return err
	}
	return nil
}

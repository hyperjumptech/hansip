package connector

import (
	"bytes"
	"context"
	"fmt"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/sirupsen/logrus"
	"net/smtp"
	"strings"
)

var (
	mailerLog = logrus.WithField("system", "mailer")
)

const (
	mime = "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
)

type EmailSender interface {
	SendEmail(ctx context.Context, to, cc, bcc []string, from, fromName, subject, body string) error
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
	for k := range r.To {
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

func (sender *DummyMailSender) SendEmail(ctx context.Context, to, cc, bcc []string, from, fromName, subject, body string) error {
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

func (sender *SendMailSender) SendEmail(ctx context.Context, to, cc, bcc []string, from, fromName, subject, body string) error {

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

	sendmailLog := mailerLog.WithField("mailer", "sendmail").WithField("mailto", strings.Join(to, ","))

	err := smtp.SendMail(fmt.Sprintf("%s:%d", sender.Host, sender.Port), auth, from, rec.Recipients(), bodyBuffer.Bytes())
	if err != nil {
		sendmailLog.Error(err)
		return err
	}
	sendmailLog.Debug("send mail success")
	return nil
}

type SendGridSender struct {
	Token string
}

func getMailBoxName(email string) string {
	if strings.Index(email, "@") > 0 {
		return email[:strings.Index(email, "@")]
	}
	return email
}

func (sender *SendGridSender) SendEmail(ctx context.Context, to, cc, bcc []string, from, fromName, subject, body string) error {
	sendGridMail := mail.NewV3Mail()

	persona := mail.NewPersonalization()
	if to != nil {
		for _, t := range to {
			persona.AddTos(mail.NewEmail(getMailBoxName(t), t))
		}
	}
	if cc != nil {
		for _, t := range cc {
			persona.AddCCs(mail.NewEmail(getMailBoxName(t), t))
		}
	}
	if bcc != nil {
		for _, t := range bcc {
			persona.AddBCCs(mail.NewEmail(getMailBoxName(t), t))
		}
	}
	persona.Subject = subject
	sendGridMail.AddPersonalizations(persona)

	content := mail.NewContent("text/html", body)
	sendGridMail.AddContent(content)

	sendGridMail.SetFrom(mail.NewEmail(fromName, from))

	if len(sender.Token) == 0 {
		panic("sendgrid mailer with no token configured")
	}

	sendGridClient := sendgrid.NewSendClient(sender.Token)
	resp, err := sendGridClient.Send(sendGridMail)
	sendgridLog := mailerLog.WithField("mailer", "sendgrid").WithField("mailto", strings.Join(to, ","))
	if err != nil {
		sendgridLog.Errorf("error while sending email. got %s", err.Error())
		return err
	}
	sendgridLog.Debugf("response status %d, body %s", resp.StatusCode, resp.Body)
	return nil
}

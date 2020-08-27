package connector

import (
	"bytes"
	"context"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/sirupsen/logrus"
)

var (
	mailerLog = logrus.WithField("system", "mailer")
)

const (
	mime = "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
)

// EmailSender interface for the different scenarios
type EmailSender interface {
	SendEmail(ctx context.Context, to, cc, bcc []string, from, fromName, subject, body string) error
}

// Recipients is the sender array
type Recipients struct {
	To map[string]bool
}

// AddAll add string to recipients
func (r *Recipients) AddAll(re []string) {
	for _, ri := range re {
		r.To[ri] = true
	}
}

// Recipients create recipient
func (r *Recipients) Recipients() []string {
	ret := make([]string, 0)
	for k := range r.To {
		ret = append(ret, k)
	}
	return ret
}

// DummyMailSender str
type DummyMailSender struct {
	LastSentMail *DummyMail
}

// DummyMail struct to send email to the ether
type DummyMail struct {
	From    string
	To      string
	Cc      string
	Bcc     string
	Subject string
	Body    string
}

// SendEmail doesn't really send anything
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

// SendMailSender is the mail sender struct
type SendMailSender struct {
	Host     string
	Port     int
	User     string
	Password string
}

// SendEmail sends out mail to smtp
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

//SendGridSender token
type SendGridSender struct {
	Token string
}

func getMailBoxName(email string) string {
	if strings.Index(email, "@") > 0 {
		return email[:strings.Index(email, "@")]
	}
	return email
}

// SendEmail from Token
// @return
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

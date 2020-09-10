package mailer

import (
	"context"
	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/connector"
	"github.com/hyperjumptech/hansip/internal/constants"
	log "github.com/sirupsen/logrus"
	"strings"
	"text/template"
)

var (
	mailerLogger  = log.WithField("go", "Mailer")
	MailerChannel chan *Email
	KillChannel   chan bool
	Sender        connector.EmailSender
	Templates     map[string]*EmailTemplates
)

type Email struct {
	context  context.Context
	From     string
	FromName string
	To       []string
	Cc       []string
	Bcc      []string
	Template string
	Data     interface{}
}

type EmailTemplates struct {
	SubjectTemplate *template.Template
	BodyTemplate    *template.Template
}

func parseTemplate(name, text string) *template.Template {
	tmpl, err := template.New(name).Parse(text)
	if err != nil {
		panic(err)
	}
	return tmpl
}

func init() {
	MailerChannel = make(chan *Email)
	KillChannel = make(chan bool)
	Templates = make(map[string]*EmailTemplates)
	Templates["EMAIL_VERIFY"] = &EmailTemplates{
		SubjectTemplate: parseTemplate("verifySubject", config.Get("mailer.templates.emailveri.subject")),
		BodyTemplate:    parseTemplate("verifyBody", config.Get("mailer.templates.emailveri.body")),
	}
	Templates["PASSPHRASE_RECOVERY"] = &EmailTemplates{
		SubjectTemplate: parseTemplate("passRecoverSubject", config.Get("mailer.templates.passrecover.subject")),
		BodyTemplate:    parseTemplate("passRecoverBody", config.Get("mailer.templates.passrecover.body")),
	}

}

func Start() {
	mailerLogger.Info("Mailer starting")
	running := true
	for running {
		select {
		case mail := <-MailerChannel:
			fLog := mailerLogger.WithField("RequestID", mail.context.Value(constants.RequestID))
			if Sender == nil {
				fLog.Errorf("not sent because mail Sender is nil")
			} else {
				if templates, ok := Templates[mail.Template]; ok {
					subjectWriter := &strings.Builder{}
					err := templates.SubjectTemplate.Execute(subjectWriter, mail.Data)
					if err != nil {
						fLog.Errorf("templates.SubjectTemplate.Execute got %s", err.Error())
					}
					bodyWriter := &strings.Builder{}
					err = templates.BodyTemplate.Execute(bodyWriter, mail.Data)
					if err != nil {
						fLog.Errorf("templates.BodyTemplate.Execute got %s", err.Error())
					}
					err = Sender.SendEmail(mail.context, mail.To, mail.Cc, mail.Bcc, mail.From, mail.FromName, subjectWriter.String(), bodyWriter.String())
					if err != nil {
						fLog.Errorf("Sender.SendEmail got %s", err.Error())
					}
					fLog.Tracef("email sent to %s", mail.To)
				} else {
					fLog.Errorf("not sent because mail template not recognized %s", mail.Template)
				}
			}
		case stop := <-KillChannel:
			if stop {
				running = false
				break
			}
		}
	}
	mailerLogger.Info("Mailer stopped")
}

func Send(context context.Context, mail *Email) {
	mail.context = context
	MailerChannel <- mail
}

func Stop() {
	KillChannel <- true
}

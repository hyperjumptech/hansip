package mailer

import (
	"context"
	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/connector"
	"github.com/hyperjumptech/hansip/internal/constants"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/url"
	"strings"
	"text/template"
)

var (
	mailerLogger = log.WithField("go", "Mailer")

	// MailerChannel mailer channel to receive new mail to send.
	MailerChannel chan *Email

	// KillChannel a bolean channel to detect mailer server shutdown
	KillChannel chan bool

	// Sender the connector used in this mailer
	Sender connector.EmailSender

	// Templates maps list of email template to use
	Templates map[string]*EmailTemplates
)

// Email contains data structure of a new email
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

// TemplateLoader will load from specified resourceURI.
// if the specified resource URI is not valid, it will return the resource in the parameter.
// if the specified resource URI is valid, it will load the specified file and return its content.
func TemplateLoader(resourceURI string) (string, error) {
	url, err := url.ParseRequestURI(resourceURI)
	if err != nil {
		return resourceURI, nil
	}
	filePath := url.Path
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// EmailTemplates data structure for an email template
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

	emailVeriSubTempl, err := TemplateLoader(config.Get("mailer.templates.emailveri.subject"))
	if err != nil {
		panic(err.Error())
	}
	emailVeriBodTempl, err := TemplateLoader(config.Get("mailer.templates.emailveri.body"))
	if err != nil {
		panic(err.Error())
	}

	emailPassRecSubTempl, err := TemplateLoader(config.Get("mailer.templates.passrecover.subject"))
	if err != nil {
		panic(err.Error())
	}

	emailPassRecBodTempl, err := TemplateLoader(config.Get("mailer.templates.passrecover.body"))
	if err != nil {
		panic(err.Error())
	}

	Templates["EMAIL_VERIFY"] = &EmailTemplates{
		SubjectTemplate: parseTemplate("verifySubject", emailVeriSubTempl),
		BodyTemplate:    parseTemplate("verifyBody", emailVeriBodTempl),
	}
	Templates["PASSPHRASE_RECOVERY"] = &EmailTemplates{
		SubjectTemplate: parseTemplate("passRecoverSubject", emailPassRecSubTempl),
		BodyTemplate:    parseTemplate("passRecoverBody", emailPassRecBodTempl),
	}

}

// Start will start this mailer server
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

// Send will add an email to the channel for sending.
func Send(context context.Context, mail *Email) {
	mail.context = context
	MailerChannel <- mail
}

// Stop stop the channel
func Stop() {
	KillChannel <- true
}

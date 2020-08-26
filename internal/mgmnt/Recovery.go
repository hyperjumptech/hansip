package mgmnt

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/constants"
	"github.com/hyperjumptech/hansip/internal/mailer"
	"github.com/hyperjumptech/hansip/pkg/helper"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

var (
	recoveryLogger = log.WithField("go", "Recovery")
)

// RecoverPassphraseRequest passphrase
type RecoverPassphraseRequest struct {
	Email string `json:"email"`
}

// RecoverPassphrase handler
func RecoverPassphrase(w http.ResponseWriter, r *http.Request) {
	fLog := recoveryLogger.WithField("func", "RecoverPassphrase").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	req := &RecoverPassphraseRequest{}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fLog.Errorf("ioutil.ReadAll got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	err = json.Unmarshal(body, req)
	if err != nil {
		fLog.Errorf("json.Unmarshal got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	user, err := UserRepo.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByEmail got %s", err.Error())
		// send fake success
		helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Check your email", nil, nil)
		return
	}
	user.RecoveryCode = helper.MakeRandomString(10, true, true, true, false)
	UserRepo.SaveOrUpdate(r.Context(), user)

	fLog.Warnf("Sending email")
	mailer.Send(r.Context(), &mailer.Email{
		From:     config.Get("mailer.from"),
		FromName: config.Get("mailer.from.name"),
		To:       []string{user.Email},
		Cc:       nil,
		Bcc:      nil,
		Template: "PASSPHRASE_RECOVERY",
		Data:     user,
	})

	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Check your email", nil, nil)
}

// ResetPassphraseRequest reset passphrase struct
type ResetPassphraseRequest struct {
	ResetToken    string `json:"passphraseResetToken"`
	NewPassphrase string `json:"newPassphrase"`
}

// ResetPassphrase handler
func ResetPassphrase(w http.ResponseWriter, r *http.Request) {
	fLog := recoveryLogger.WithField("func", "ResetPassphrase").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	req := &ResetPassphraseRequest{}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fLog.Errorf("ioutil.ReadAll got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	err = json.Unmarshal(body, req)
	if err != nil {
		fLog.Errorf("json.Unmarshal got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	user, err := UserRepo.GetUserByRecoveryToken(r.Context(), req.ResetToken)
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecoveryToken got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Check your email", nil, nil)
		return
	}
	pass, err := bcrypt.GenerateFromPassword([]byte(req.NewPassphrase), 14)
	if err != nil {
		fLog.Errorf("bcrypt.GenerateFromPassword got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	user.HashedPassphrase = string(pass)
	UserRepo.SaveOrUpdate(r.Context(), user)
}

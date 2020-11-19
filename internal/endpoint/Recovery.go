package endpoint

import (
	"encoding/json"
	"fmt"
	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/constants"
	"github.com/hyperjumptech/hansip/internal/mailer"
	"github.com/hyperjumptech/hansip/internal/passphrase"
	"github.com/hyperjumptech/hansip/pkg/helper"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
)

var (
	recoveryLogger = log.WithField("go", "Recovery")
)

// RecoverPassphraseRequest hold the model for requesting passphrase recovery
type RecoverPassphraseRequest struct {
	Email string `json:"email"`
}

// RecoverPassphrase serving request for recovering passphrase
func RecoverPassphrase(w http.ResponseWriter, r *http.Request) {
	fLog := recoveryLogger.WithField("func", "RecoverPassphrase").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
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

// ResetPassphraseRequest hold data model for reseting passphrase
type ResetPassphraseRequest struct {
	ResetToken    string `json:"passphraseResetToken"`
	NewPassphrase string `json:"newPassphrase"`
}

// ResetPassphrase serving passphrase reset request
func ResetPassphrase(w http.ResponseWriter, r *http.Request) {
	fLog := recoveryLogger.WithField("func", "ResetPassphrase").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
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
	isValidPassphrase := passphrase.Validate(req.NewPassphrase, config.GetInt("security.passphrase.minchars"), config.GetInt("security.passphrase.minwords"), config.GetInt("security.passphrase.mincharsinword"))
	if !isValidPassphrase {
		fLog.Errorf("Passphrase invalid")
		invalidMsg := fmt.Sprintf("Invalid passphrase. Passphrase must at least has %d characters and %d words and for each word have minimum %d characters", config.GetInt("security.passphrase.minchars"), config.GetInt("security.passphrase.minwords"), config.GetInt("security.passphrase.mincharsinword"))
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, "invalid passphrase", nil, invalidMsg)
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
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Passphrase changed", nil, nil)
}

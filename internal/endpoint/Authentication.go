package endpoint

import (
	"encoding/json"
	"fmt"
	"github.com/hyperjumptech/hansip/pkg/helper"
	"github.com/hyperjumptech/hansip/pkg/totp"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var (

	// TokenFactory instance used for generating and validating token
	TokenFactory helper.TokenFactory

	initialized = false
)

// Request a model for authentication request.
type Request struct {
	Email      string `json:"email"`
	Passphrase string `json:"passphrase"`
}

// RequestWith2FA a model for authentication using 2fa secret key
type RequestWith2FA struct {
	Email      string `json:"email"`
	Passphrase string `json:"passphrase"`
	SecretKey  string `json:"2FA_recovery_code"`
}

// Response a model for responding successful authentication
type Response struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshResponse a model for responding successful refresh
type RefreshResponse struct {
	AccessToken string `json:"access_token"`
}

// TwoFARequest model for sending 2FA authentication
type TwoFARequest struct {
	Token string `json:"2FA_token"`
	Otp   string `json:"2FA_otp"`
}

// TwoFATestRequest model for sending 2FA authentication
type TwoFATestRequest struct {
	Email string `json:"email"`
	Otp   string `json:"2FA_otp"`
}

// TwoFATest is an endpoint handler used for testing 2FA
func TwoFATest(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	authReq := &TwoFATestRequest{}
	err = json.Unmarshal(body, authReq)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	user, err := UserRepo.GetUserByEmail(r.Context(), authReq.Email)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}

	secret := totp.SecretFromBase32(user.UserTotpSecretKey)
	valid, err := totp.Authenticate(secret, authReq.Otp, true)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if !valid {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "OTP not valid", nil, nil)
	} else {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "OTP Valid", nil, nil)
	}
	return
}

// TwoFA validate 2FA token and authenticate the user
func TwoFA(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	authReq := &TwoFARequest{}
	err = json.Unmarshal(body, authReq)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	user, err := UserRepo.GetUserBy2FAToken(r.Context(), authReq.Token)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}

	secret := totp.SecretFromBase32(user.UserTotpSecretKey)
	valid, err := totp.Authenticate(secret, authReq.Otp, true)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}

	defer UserRepo.SaveOrUpdate(r.Context(), user)

	if !valid {
		user.FailCount = user.FailCount + 1
		if user.FailCount > 3 {
			user.Suspended = true
		}
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "OTP not valid", nil, nil)
		return
	}

	// If the password is valid, reset the user's FailCount
	user.FailCount = 0

	var roles []string

	// Add user's role from direct UserRole relation.
	userRoles, _, err := UserRepo.ListAllUserRoles(r.Context(), user, &helper.PageRequest{
		No:       1,
		PageSize: 1000,
		OrderBy:  "ROLE_NAME",
		Sort:     "ASC",
	})
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	// Add user's role into Token audiences info.
	roles = make([]string, len(userRoles))
	for k, v := range userRoles {
		r, err := RoleRepo.GetRoleByRecID(r.Context(), v.RecID)
		if err == nil {
			roles[k] = r.RoleName
		}
	}

	// Set the account email into Token subject.
	subject := user.Email

	// Set the audience
	audience := roles

	access, refresh, err := TokenFactory.CreateTokenPair(subject, audience, nil)

	resp := &Response{
		AccessToken:  access,
		RefreshToken: refresh,
	}

	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Successful", nil, resp)
}

// Authentication2FA serve authentication with 2fa secret key
func Authentication2FA(w http.ResponseWriter, r *http.Request) {
	// Check content-type, make sure its application/json
	cType := r.Header.Get("Content-Type")
	if cType != "application/json" {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, "Unserviceable content type", nil, nil)
		return
	}

	// Read the body into byte array
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}

	// Parse the body into Request
	authReq := &RequestWith2FA{}
	err = json.Unmarshal(body, authReq)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}

	// Get user by said email
	user, err := UserRepo.GetUserByEmail(r.Context(), authReq.Email)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), nil, nil)
		return
	}
	user.LastLogin = time.Now()

	// Make sure chages to this user are saved.
	defer UserRepo.SaveOrUpdate(r.Context(), user)

	// Make sure the user is enabled
	if !user.Enabled {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "account disabled", nil, nil)
		return
	}

	// Make sure the user is not suspended
	if user.Suspended {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "account suspended", nil, nil)
		return
	}

	// Validate the user's password
	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPassphrase), []byte(authReq.Passphrase))
	if err != nil {
		user.FailCount++
		if user.FailCount > 3 {
			user.Suspended = true
		}
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "email or passphrase not match", nil, nil)
		return
	}

	codes, err := UserRepo.GetTOTPRecoveryCodes(r.Context(), user)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	codeCorrect := false
	for _, v := range codes {
		if v == authReq.SecretKey {
			codeCorrect = true
			break
		}
	}
	if !codeCorrect {
		user.FailCount++
		if user.FailCount > 3 {
			user.Suspended = true
		}
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "invalid secret key", nil, nil)
		return
	}

	_ = UserRepo.MarkTOTPRecoveryCodeUsed(r.Context(), user, authReq.SecretKey)

	// If the password is valid, reset the user's FailCount
	user.FailCount = 0

	var roles []string

	// Add user's role from direct UserRole relation.
	userRoles, _, err := UserRepo.ListAllUserRoles(r.Context(), user, &helper.PageRequest{
		No:       1,
		PageSize: 1000,
		OrderBy:  "ROLE_NAME",
		Sort:     "ASC",
	})
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	// Add user's role into Token audiences info.
	roles = make([]string, len(userRoles))
	for k, v := range userRoles {
		r, err := RoleRepo.GetRoleByRecID(r.Context(), v.RecID)
		if err == nil {
			roles[k] = fmt.Sprintf("%s@%s", r.RoleName, r.RoleDomain)
		}
	}

	// Set the account email into Token subject.
	subject := user.Email

	// Set the audience
	audience := roles

	access, refresh, err := TokenFactory.CreateTokenPair(subject, audience, nil)

	resp := &Response{
		AccessToken:  access,
		RefreshToken: refresh,
	}

	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Successful", nil, resp)
}

// Authentication serve normal authentication
func Authentication(w http.ResponseWriter, r *http.Request) {
	// Check content-type, make sure its application/json
	cType := r.Header.Get("Content-Type")
	if cType != "application/json" {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, "Unserviceable content type", nil, nil)
		return
	}

	// Read the body into byte array
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}

	// Parse the body into Request
	authReq := &Request{}
	err = json.Unmarshal(body, authReq)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}

	// Get user by said email
	user, err := UserRepo.GetUserByEmail(r.Context(), authReq.Email)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), nil, nil)
		return
	}
	user.LastLogin = time.Now()

	// Make sure chages to this user are saved.
	defer UserRepo.SaveOrUpdate(r.Context(), user)

	// Make sure the user is enabled
	if !user.Enabled {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "account disabled", nil, nil)
		return
	}

	// Make sure the user is not suspended
	if user.Suspended {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "account suspended", nil, nil)
		return
	}

	// Validate the user's password
	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPassphrase), []byte(authReq.Passphrase))
	if err != nil {
		user.FailCount++
		if user.FailCount > 3 {
			user.Suspended = true
		}
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "email or passphrase not match", nil, nil)
		return
	}

	if user.Enable2FactorAuth {
		user.Token2FA = helper.MakeRandomString(16, true, true, true, false)
		ret := make(map[string]string)
		ret["2FA_token"] = user.Token2FA
		helper.WriteHTTPResponse(r.Context(), w, http.StatusAccepted, "2FA needed", nil, ret)
		return
	}

	// If the password is valid, reset the user's FailCount
	user.FailCount = 0

	var roles []string

	// Add user's role from direct UserRole relation.
	userRoles, _, err := UserRepo.ListAllUserRoles(r.Context(), user, &helper.PageRequest{
		No:       1,
		PageSize: 1000,
		OrderBy:  "ROLE_NAME",
		Sort:     "ASC",
	})
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}

	// Add user's role into Token audiences info.
	roles = make([]string, len(userRoles))
	for k, v := range userRoles {
		r, err := RoleRepo.GetRoleByRecID(r.Context(), v.RecID)
		if err == nil {
			roles[k] = fmt.Sprintf("%s@%s", r.RoleName, r.RoleDomain)
		}
	}

	// Set the account email into Token subject.
	subject := user.Email

	// Set the audience
	audience := roles

	access, refresh, err := TokenFactory.CreateTokenPair(subject, audience, nil)

	resp := &Response{
		AccessToken:  access,
		RefreshToken: refresh,
	}

	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Successful", nil, resp)
}

// Refresh serves token refresh
func Refresh(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if len(auth) == 0 {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "missing authentication header", nil, nil)
	}

	// bearer
	if len(auth) < 6 || strings.ToUpper(auth[:6]) != "BEARER" {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "invalid authentication method", nil, nil)
	}

	// Token
	token := strings.TrimSpace(auth[7:])
	access, err := TokenFactory.RefreshToken(token)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, err.Error(), nil, nil)
	}

	resp := &RefreshResponse{AccessToken: access}

	helper.WriteHTTPResponse(r.Context(), w, 200, "access Token refreshed", nil, resp)
}

package auth

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/connector"
	"github.com/hyperjumptech/hansip/internal/mgmnt"
	"github.com/hyperjumptech/hansip/pkg/helper"
	"github.com/hyperjumptech/hansip/pkg/totp"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var (
	userRepo      connector.UserRepository
	userRoleRepo  connector.UserRoleRepository
	roleRepo      connector.RoleRepository
	userGroupRepo connector.UserGroupRepository
	groupRepo     connector.GroupRepository
	groupRoleRepo connector.GroupRoleRepository

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
	SecretKey  string `json:"2FA_secret_key"`
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

// InitializeAuthRouter initializes the module's repository and routing
func InitializeAuthRouter(router *mux.Router) {
	if initialized {
		return
	}
	userRepo = mgmnt.UserRepo
	userRoleRepo = mgmnt.UserRoleRepo
	roleRepo = mgmnt.RoleRepo
	userGroupRepo = mgmnt.UserGroupRepo
	groupRepo = mgmnt.GroupRepo
	groupRoleRepo = mgmnt.GroupRoleRepo

	router.HandleFunc("/api/v1/auth/authenticate", Authentication).Methods("OPTIONS", "POST")
	router.HandleFunc("/api/v1/auth/refresh", Refresh).Methods("OPTIONS", "POST")
	router.HandleFunc("/api/v1/auth/2fa", TwoFA).Methods("OPTIONS", "POST")
	router.HandleFunc("/api/v1/auth/authenticate2fa", Authentication2FA).Methods("OPTIONS", "POST")

	initialized = true
}

// TwoFARequest model for sending 2FA authentication
type TwoFARequest struct {
	Token string `json:"2FA_token"`
	Otp   string `json:"2FA_otp"`
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
	user, err := userRepo.GetUserBy2FAToken(r.Context(), authReq.Token)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	otp, err := totp.GenerateTotpWithDrift(user.UserTotpSecretKey, time.Now(), 30, 6)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}

	defer userRepo.SaveOrUpdate(r.Context(), user)

	if otp != authReq.Otp {
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

	if config.GetBoolean("setup.admin.enable") {
		roles = []string{"admin@aaa", "user@aaa"}
	} else {
		// Add user's role from direct UserRole relation.
		userRoles, _, err := userRoleRepo.ListUserRoleByUser(r.Context(), user, &helper.PageRequest{
			No:       1,
			PageSize: 1000,
		})
		if err != nil {
			helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
			return
		}
		// Add user's role into Token audiences info.
		roles = make([]string, len(userRoles))
		for k, v := range userRoles {
			r, err := roleRepo.GetRoleByRecID(r.Context(), v.RecID)
			if err == nil {
				roles[k] = r.RoleName
			}
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
	user, err := userRepo.GetUserByEmail(r.Context(), authReq.Email)
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), nil, nil)
		return
	}
	user.LastLogin = time.Now()

	// Make sure chages to this user are saved.
	defer userRepo.SaveOrUpdate(r.Context(), user)

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

	if user.UserTotpSecretKey != authReq.SecretKey {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "invalid secret key", nil, nil)
		return
	}

	// If the password is valid, reset the user's FailCount
	user.FailCount = 0

	var roles []string

	// Add user's role from direct UserRole relation.
	userRoles, _, err := userRoleRepo.ListUserRoleByUser(r.Context(), user, &helper.PageRequest{
		No:       1,
		PageSize: 1000,
	})
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	// Add user's role into Token audiences info.
	roles = make([]string, len(userRoles))
	for k, v := range userRoles {
		r, err := roleRepo.GetRoleByRecID(r.Context(), v.RecID)
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

	var user *connector.User

	if config.GetBoolean("setup.admin.enable") {
		if authReq.Email == config.Get("setup.admin.email") && authReq.Passphrase == config.Get("setup.admin.passphrase") {
			bytes, _ := bcrypt.GenerateFromPassword([]byte(authReq.Passphrase), 14)
			user = &connector.User{
				RecID:             helper.MakeRandomString(10, true, true, true, false),
				Email:             config.Get("setup.admin.email"),
				HashedPassphrase:  string(bytes),
				Enabled:           true,
				Suspended:         false,
				LastSeen:          time.Time{},
				LastLogin:         time.Time{},
				FailCount:         0,
				ActivationCode:    "",
				ActivationDate:    time.Time{},
				UserTotpSecretKey: helper.MakeRandomString(32, true, true, true, false),
				Enable2FactorAuth: false,
			}
		}
	}

	if user == nil {
		// Get user by said email
		user, err = userRepo.GetUserByEmail(r.Context(), authReq.Email)
		if err != nil {
			helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), nil, nil)
			return
		}
		user.LastLogin = time.Now()

		// Make sure chages to this user are saved.
		defer userRepo.SaveOrUpdate(r.Context(), user)
	}

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

	if config.GetBoolean("setup.admin.enable") {
		roles = []string{"admin@aaa", "user@aaa"}
	} else {
		// Add user's role from direct UserRole relation.
		userRoles, _, err := userRoleRepo.ListUserRoleByUser(r.Context(), user, &helper.PageRequest{
			No:       1,
			PageSize: 1000,
		})
		if err != nil {
			helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
			return
		}
		// Add user's role into Token audiences info.
		roles = make([]string, len(userRoles))
		for k, v := range userRoles {
			r, err := roleRepo.GetRoleByRecID(r.Context(), v.RecID)
			if err == nil {
				roles[k] = r.RoleName
			}
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

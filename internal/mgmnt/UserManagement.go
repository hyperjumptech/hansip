package mgmnt

import (
	"encoding/json"
	"fmt"
	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/constants"
	"github.com/hyperjumptech/hansip/internal/hansipcontext"
	"github.com/hyperjumptech/hansip/internal/mailer"
	"github.com/hyperjumptech/hansip/internal/passphrase"
	"github.com/hyperjumptech/hansip/pkg/helper"
	"github.com/hyperjumptech/hansip/pkg/totp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
	"time"
)

var (
	userMgmtLogger = log.WithField("go", "UserManagement")
)

func SetUserRoles(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "SetUserRoles").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/roles", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("User recID %s not found", params["userRecId"]), nil, nil)
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fLog.Errorf("ioutil.ReadAll got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	roleIds := make([]string, 0)
	err = json.Unmarshal(body, &roleIds)
	if err != nil {
		fLog.Errorf("json.Unmarshal got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}

	err = UserRoleRepo.DeleteUserRoleByUser(r.Context(), user)
	if err != nil {
		fLog.Errorf("UserRoleRepo.DeleteUserRoleByUser got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}

	counter := 0
	for _, roleId := range roleIds {
		role, err := RoleRepo.GetRoleByRecID(r.Context(), roleId)
		if err != nil {
			fLog.Warnf("RoleRepo.GetRoleByRecID got %s, this role %s will not be added to user %s role", err.Error(), roleId, user.RecID)
		} else {
			_, err := UserRoleRepo.CreateUserRole(r.Context(), user, role)
			if err != nil {
				fLog.Warnf("UserRoleRepo.CreateUserRole got %s, this role %s will not be added to user %s role", err.Error(), roleId, user.RecID)
			} else {
				counter++
			}
		}
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, fmt.Sprintf("%d roles added into user", counter), nil, nil)
}

func DeleteUserRoles(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "DeleteUserRoles").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/roles", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("User recID %s not found", params["userRecId"]), nil, nil)
		return
	}
	err = UserRoleRepo.DeleteUserRoleByUser(r.Context(), user)
	if err != nil {
		fLog.Errorf("UserRoleRepo.DeleteUserRoleByUser got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "successfuly removed all roles from user", nil, nil)
}

func SetUserGroups(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "SetUserGroups").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/groups", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("User recID %s not found", params["userRecId"]), nil, nil)
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fLog.Errorf("ioutil.ReadAll got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	groupIds := make([]string, 0)
	err = json.Unmarshal(body, &groupIds)
	if err != nil {
		fLog.Errorf("json.Unmarshal got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}

	err = UserGroupRepo.DeleteUserGroupByUser(r.Context(), user)
	if err != nil {
		fLog.Errorf("UserGroupRepo.DeleteUserGroupByUser got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}

	counter := 0
	for _, groupId := range groupIds {
		group, err := GroupRepo.GetGroupByRecID(r.Context(), groupId)
		if err != nil {
			fLog.Warnf("GroupRepo.GetGroupByRecID got %s, this group %s will not be joined by user %s", err.Error(), groupId, user.RecID)
		} else {
			_, err := UserGroupRepo.CreateUserGroup(r.Context(), user, group)
			if err != nil {
				fLog.Warnf("UserGroupRepo.CreateUserGroup got %s, this group %s will not be joined by user %s", err.Error(), groupId, user.RecID)
			} else {
				counter++
			}
		}
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, fmt.Sprintf("%d groups joined by user", counter), nil, nil)
}

func DeleteUserGroups(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "DeleteUserGroups").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/groups", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("User recID %s not found", params["userRecId"]), nil, nil)
		return
	}
	err = UserGroupRepo.DeleteUserGroupByUser(r.Context(), user)
	if err != nil {
		fLog.Errorf("UserGroupRepo.DeleteUserGroupByUser got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "user successfuly leaves all groups", nil, nil)
}

// Show2FAQrCode shows 2FA QR code. It returns a PNG image bytes.
func Show2FAQrCode(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "Show2FAQrCode").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	authCtx := r.Context().Value(constants.HansipAuthentication).(*hansipcontext.AuthenticationContext)
	user, err := UserRepo.GetUserByEmail(r.Context(), authCtx.Subject)
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByEmail got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, fmt.Sprintf("subject not found : %s. got %s", authCtx.Subject, err.Error()))
		return
	}

	user.UserTotpSecretKey = totp.MakeSecret().Base32()
	err = UserRepo.SaveOrUpdate(r.Context(), user)
	if err != nil {
		fLog.Errorf("UserRepo.SaveOrUpdate got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	fLog.Warnf("New TOTP secret is created for %s", user.Email)

	codes, err := UserRepo.RecreateTOTPRecoveryCodes(r.Context(), user)
	if err != nil {
		fLog.Errorf("UserRepo.RecreateTOTPRecoveryCodes got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	fLog.Warnf("Created %d recovery codes for %s", len(codes), user.Email)

	png, err := totp.MakeTotpQrImage(totp.SecretFromBase32(user.UserTotpSecretKey), config.Get("token.issuer"), user.Email)
	if err != nil {
		fLog.Errorf("totp.MakeTotpQrImage got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	w.Header().Add("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	w.Write(png)
}

// SimpleUser hold data model of user. showing important attributes only.
type SimpleUser struct {
	RecID     string `json:"rec_id"`
	Email     string `json:"email"`
	Enabled   bool   `json:"enabled"`
	Suspended bool   `json:"suspended"`
}

// ListAllUsers serving listing all user request
func ListAllUsers(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, "Mohomaaf ...dsb", nil, nil)
		}
	}()

	fLog := userMgmtLogger.WithField("func", "ListAllUsers").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	fLog.Trace("Listing Users")
	pageRequest, err := helper.NewPageRequestFromRequest(r)
	if err != nil {
		fLog.Errorf("helper.NewPageRequestFromRequest got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	users, page, err := UserRepo.ListUser(r.Context(), pageRequest)
	if err != nil {
		fLog.Errorf("UserRepo.ListUser got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	susers := make([]*SimpleUser, len(users))
	for i, v := range users {
		susers[i] = &SimpleUser{
			RecID:     v.RecID,
			Email:     v.Email,
			Enabled:   v.Enabled,
			Suspended: v.Suspended,
		}
	}
	ret := make(map[string]interface{})
	ret["users"] = susers
	ret["page"] = page
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "List of all user paginated", nil, ret)
}

// CreateNewUserRequest hold the data model for requesting to create new user.
type CreateNewUserRequest struct {
	Email      string `json:"email"`
	Passphrase string `json:"passphrase"`
}

// CreateNewUserResponse hold the data model for responding CreateNewUser request
type CreateNewUserResponse struct {
	RecordID    string    `json:"rec_id"`
	Email       string    `json:"email"`
	Enabled     bool      `json:"enabled"`
	Suspended   bool      `json:"suspended"`
	LastSeen    time.Time `json:"last_seen"`
	LastLogin   time.Time `json:"last_login"`
	TotpEnabled bool      `json:"enabled_2fa"`
}

// CreateNewUser handles request to create new user
func CreateNewUser(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "CreateNewUser").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	fLog.Trace("Creating new user")
	req := &CreateNewUserRequest{}
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
	isValidPassphrase := passphrase.Validate(req.Passphrase, config.GetInt("security.passphrase.minchars"), config.GetInt("security.passphrase.minwords"), config.GetInt("security.passphrase.mincharsinword"))
	if !isValidPassphrase {
		fLog.Errorf("Passphrase invalid")
		invalidMsg := fmt.Sprintf("Invalid passphrase. Passphrase must at least has %d characters and %d words and for each word have minimum %d characters", config.GetInt("security.passphrase.minchars"), config.GetInt("security.passphrase.minwords"), config.GetInt("security.passphrase.mincharsinword"))
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, "invalid passphrase", nil, invalidMsg)
		return
	}
	user, err := UserRepo.CreateUserRecord(r.Context(), req.Email, req.Passphrase)
	if err != nil {
		fLog.Errorf("UserRepo.CreateUserRecord got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	resp := &CreateNewUserResponse{
		RecordID:    user.RecID,
		Email:       user.Email,
		Enabled:     user.Enabled,
		Suspended:   user.Suspended,
		LastSeen:    user.LastSeen,
		LastLogin:   user.LastLogin,
		TotpEnabled: user.Enable2FactorAuth,
	}
	fLog.Warnf("Sending email")
	mailer.Send(r.Context(), &mailer.Email{
		From:     config.Get("mailer.from"),
		FromName: config.Get("mailer.from.name"),
		To:       []string{user.Email},
		Cc:       nil,
		Bcc:      nil,
		Template: "EMAIL_VERIFY",
		Data:     user,
	})

	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Success creating user", nil, resp)
	return
}

// ChangePassphraseRequest stores change password request
type ChangePassphraseRequest struct {
	OldPassphrase string `json:"old_passphrase"`
	NewPassphrase string `json:"new_passphrase"`
}

// ChangePassphrase handles the change password request
func ChangePassphrase(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "ChangePassphrase").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/passwd", r.URL.Path)
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fLog.Errorf("ioutil.ReadAll got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	c := &ChangePassphraseRequest{}
	err = json.Unmarshal(body, c)
	if err != nil {
		fLog.Errorf("json.Unmarshal got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, "Malformed json body", nil, nil)
		return
	}

	isValidPassphrase := passphrase.Validate(c.NewPassphrase, config.GetInt("security.passphrase.minchars"), config.GetInt("security.passphrase.minwords"), config.GetInt("security.passphrase.mincharsinword"))
	if !isValidPassphrase {
		fLog.Errorf("new passphrase invalid")
		invalidMsg := fmt.Sprintf("Invalid new passphrase. Passphrase must at least has %d characters and %d words and for each word have minimum %d characters", config.GetInt("security.passphrase.minchars"), config.GetInt("security.passphrase.minwords"), config.GetInt("security.passphrase.mincharsinword"))
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, "invalid new passphrase", nil, invalidMsg)
		return
	}

	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPassphrase), []byte(c.OldPassphrase))
	if err != nil {
		fLog.Errorf("bcrypt.CompareHashAndPassword got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotAcceptable, err.Error(), nil, nil)
		return
	}
	newHashed, err := bcrypt.GenerateFromPassword([]byte(c.NewPassphrase), 14)
	if err != nil {
		fLog.Errorf("bcrypt.GenerateFromPassword got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	user.HashedPassphrase = string(newHashed)
	err = UserRepo.SaveOrUpdate(r.Context(), user)
	if err != nil {
		fLog.Errorf("UserRepo.SaveOrUpdate got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Password changed", nil, nil)
}

// ActivateUserRequest hold request data for activating user
type ActivateUserRequest struct {
	Email           string `json:"email"`
	ActivationToken string `json:"activation_token"`
	NewPassphrase   string `json:"new_passphrase"`
}

// WhoAmIResponse holds the response structure for WhoAmI request
type WhoAmIResponse struct {
	RecordID   string          `json:"rec_id"`
	Email      string          `json:"email"`
	Enabled    bool            `json:"enabled"`
	Suspended  bool            `json:"suspended"`
	Roles      []*RoleSummary  `json:"roles"`
	Groups     []*GroupSummary `json:"groups"`
	Enabled2FA bool            `json:"enabled_2fa"`
}

// RoleSummary hold role information summay
type RoleSummary struct {
	RecordID string `json:"rec_id"`
	RoleName string `json:"role_name"`
}

// GroupSummary hold group information summay
type GroupSummary struct {
	RecordID  string         `json:"rec_id"`
	GroupName string         `json:"group_name"`
	Roles     []*RoleSummary `json:"roles"`
}

// Activate2FARequest hold request structure for activating the 2FA request
type Activate2FARequest struct {
	Token string `json:"2FA_token"`
}

// Activate2FAResponse hold response structure for activating the 2FA request
type Activate2FAResponse struct {
	Codes []string `json:"2FA_recovery_codes"`
}

// Activate2FA handle 2FA activation request
func Activate2FA(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "Activate2FA").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	authCtx := r.Context().Value(constants.HansipAuthentication).(*hansipcontext.AuthenticationContext)
	user, err := UserRepo.GetUserByEmail(r.Context(), authCtx.Subject)
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByEmail got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, fmt.Sprintf("subject not found : %s. got %s", authCtx.Subject, err.Error()))
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fLog.Errorf("ioutil.ReadAll got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	c := &Activate2FARequest{}
	err = json.Unmarshal(body, c)
	if err != nil {
		fLog.Errorf("json.Unmarshal got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, "Malformed json body", nil, nil)
		return
	}

	secret := totp.SecretFromBase32(user.UserTotpSecretKey)
	valid, err := totp.Authenticate(secret, c.Token, true)
	if err != nil {
		fLog.Errorf("totp.GenerateTotpWithDrift got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if !valid {
		fLog.Errorf("Invalid OTP token for %s", user.Email)
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, "Invalid OTP")
		return
	}
	codes, err := UserRepo.GetTOTPRecoveryCodes(r.Context(), user)
	if err != nil {
		fLog.Errorf("UserRepo.GetTOTPRecoveryCodes got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	resp := Activate2FAResponse{
		Codes: codes,
	}
	user.Enable2FactorAuth = true
	err = UserRepo.SaveOrUpdate(r.Context(), user)
	if err != nil {
		fLog.Errorf("UserRepo.SaveOrUpdate got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "2FA Activated", nil, resp)
}

// WhoAmI handles who am I inquiry request
func WhoAmI(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "WhoAmI").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	authCtx := r.Context().Value(constants.HansipAuthentication).(*hansipcontext.AuthenticationContext)
	user, err := UserRepo.GetUserByEmail(r.Context(), authCtx.Subject)
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByEmail got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, fmt.Sprintf("subject not found : %s. got %s", authCtx.Subject, err.Error()))
		return
	}
	whoami := &WhoAmIResponse{
		RecordID:   user.RecID,
		Email:      user.Email,
		Enabled:    user.Enabled,
		Suspended:  user.Suspended,
		Roles:      make([]*RoleSummary, 0),
		Groups:     make([]*GroupSummary, 0),
		Enabled2FA: user.Enable2FactorAuth,
	}
	roles, _, err := UserRoleRepo.ListUserRoleByUser(r.Context(), user, &helper.PageRequest{
		No:       1,
		PageSize: 100,
		OrderBy:  "ROLE_NAME",
		Sort:     "ASC",
	})
	if err != nil {
		fLog.Errorf("UserRoleRepo.ListUserRoleByUser got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, fmt.Sprintf("subject not found : %s. got %s", authCtx.Subject, err.Error()))
		return
	}
	for _, r := range roles {
		whoami.Roles = append(whoami.Roles, &RoleSummary{
			RecordID: r.RecID,
			RoleName: r.RoleName,
		})
	}

	groups, _, err := UserGroupRepo.ListUserGroupByUser(r.Context(), user, &helper.PageRequest{
		No:       1,
		PageSize: 100,
		OrderBy:  "GROUP_NAME",
		Sort:     "ASC",
	})
	if err != nil {
		fLog.Errorf("UserGroupRepo.ListUserGroupByUser got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, fmt.Sprintf("subject not found : %s. got %s", authCtx.Subject, err.Error()))
		return
	}
	for _, g := range groups {
		groupSummary := &GroupSummary{
			RecordID:  g.RecID,
			GroupName: g.GroupName,
			Roles:     make([]*RoleSummary, 0),
		}
		groupRole, _, err := GroupRoleRepo.ListGroupRoleByGroup(r.Context(), g, &helper.PageRequest{
			No:       1,
			PageSize: 100,
			OrderBy:  "ROLE_NAME",
			Sort:     "ASC",
		})
		if err != nil {
			fLog.Errorf("GroupRoleRepo.ListGroupRoleByGroup got %s", err.Error())
			helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, fmt.Sprintf("subject not found : %s. got %s", authCtx.Subject, err.Error()))
			return
		}
		for _, gr := range groupRole {
			groupSummary.Roles = append(groupSummary.Roles, &RoleSummary{
				RecordID: gr.RecID,
				RoleName: gr.RoleName,
			})
		}
		whoami.Groups = append(whoami.Groups, groupSummary)
	}

	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User information populated", nil, whoami)
}

// ActivateUser serve user activation process
func ActivateUser(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "ActivateUser").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fLog.Errorf("ioutil.ReadAll got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	c := &ActivateUserRequest{}
	err = json.Unmarshal(body, c)
	if err != nil {
		fLog.Errorf("json.Unmarshal got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, "Malformed json body", nil, nil)
		return
	}

	isValidPassphrase := passphrase.Validate(c.NewPassphrase, config.GetInt("security.passphrase.minchars"), config.GetInt("security.passphrase.minwords"), config.GetInt("security.passphrase.mincharsinword"))
	if !isValidPassphrase {
		fLog.Errorf("New Passphrase invalid")
		invalidMsg := fmt.Sprintf("Invalid passphrase. Passphrase must at least has %d characters and %d words and for each word have minimum %d characters", config.GetInt("security.passphrase.minchars"), config.GetInt("security.passphrase.minwords"), config.GetInt("security.passphrase.mincharsinword"))
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, "invalid passphrase", nil, invalidMsg)
		return
	}

	user, err := UserRepo.GetUserByEmail(r.Context(), c.Email)
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByEmail got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	if user.ActivationCode == c.ActivationToken {
		user.Enabled = true
		newHashed, err := bcrypt.GenerateFromPassword([]byte(c.NewPassphrase), 14)
		if err != nil {
			fLog.Errorf("bcrypt.GenerateFromPassword got %s", err.Error())
			helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
			return
		}
		user.HashedPassphrase = string(newHashed)
		err = UserRepo.SaveOrUpdate(r.Context(), user)
		if err != nil {
			fLog.Errorf("UserRepo.SaveOrUpdate got %s", err.Error())
			helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
			return
		}
		ret := make(map[string]interface{})
		ret["rec_id"] = user.RecID
		ret["email"] = user.Email
		ret["enabled"] = user.Enabled
		ret["suspended"] = user.Suspended
		ret["last_seen"] = user.LastSeen
		ret["last_login"] = user.LastLogin
		ret["enabled_2fa"] = user.Enable2FactorAuth
		helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User activated", nil, ret)
	} else {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, "Activation token and email not match", nil, nil)
	}
}

// GetUserDetail serve fetch user detail
func GetUserDetail(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "GetUserDetail").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	ret := make(map[string]interface{})
	ret["rec_id"] = user.RecID
	ret["email"] = user.Email
	ret["enabled"] = user.Enabled
	ret["suspended"] = user.Suspended
	ret["last_seen"] = user.LastSeen
	ret["last_login"] = user.LastLogin
	ret["enabled_2fa"] = user.Enable2FactorAuth
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User retrieved", nil, ret)
}

// UpdateUserRequest hold request data for requesting to update user information.
type UpdateUserRequest struct {
	Email     string `json:"email"`
	Enabled   bool   `json:"enabled"`
	Suspended bool   `json:"suspended"`
	Enable2FA bool   `json:"enabled_2fa"`
}

// UpdateUserDetail rest endpoint to update user detail
func UpdateUserDetail(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "GetUserDetail").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	req := &UpdateUserRequest{}
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

	// if email is changed and enabled = false, send email
	sendemail := false
	if user.Email != req.Email && req.Enabled == false {
		user.ActivationCode = helper.MakeRandomString(6, true, false, false, false)
		sendemail = true
	}

	if !user.Enable2FactorAuth && req.Enable2FA {
		user.UserTotpSecretKey = totp.MakeSecret().Base32()
	}

	user.Email = req.Email
	user.Enable2FactorAuth = req.Enable2FA
	user.Enabled = req.Enabled
	user.Suspended = req.Suspended

	err = UserRepo.SaveOrUpdate(r.Context(), user)
	if err != nil {
		fLog.Errorf("UserRepo.SaveOrUpdate got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}

	if sendemail {
		fLog.Warnf("Sending email")
		mailer.Send(r.Context(), &mailer.Email{
			From:     config.Get("mailer.from"),
			FromName: config.Get("mailer.from.name"),
			To:       []string{user.Email},
			Cc:       nil,
			Bcc:      nil,
			Template: "EMAIL_VERIFY",
			Data:     user,
		})
	}

	ret := make(map[string]interface{})
	ret["rec_id"] = user.RecID
	ret["email"] = user.Email
	ret["enabled"] = user.Enabled
	ret["suspended"] = user.Suspended
	ret["last_seen"] = user.LastSeen
	ret["last_login"] = user.LastLogin
	ret["enabled_2fa"] = user.Enable2FactorAuth
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User updated", nil, ret)

}

// DeleteUser serve user deletion
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "DeleteUser").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	UserRepo.DeleteUser(r.Context(), user)
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User deleted", nil, nil)
}

// SimpleRole define structure or request body used to list role
type SimpleRole struct {
	RecID    string `json:"rec_id"`
	RoleName string `json:"role_name"`
}

// ListUserRole serve listing all role that directly owned by user
func ListUserRole(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "ListUserRole").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/roles", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	pageRequest, err := helper.NewPageRequestFromRequest(r)
	if err != nil {
		fLog.Errorf("helper.NewPageRequestFromRequest got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	roles, page, err := UserRoleRepo.ListUserRoleByUser(r.Context(), user, pageRequest)
	if err != nil {
		fLog.Errorf("UserRoleRepo.ListUserRoleByUser got %s", err.Error())
	}
	sroles := make([]*SimpleRole, len(roles))
	for k, v := range roles {
		sroles[k] = &SimpleRole{
			RecID:    v.RecID,
			RoleName: v.RoleName,
		}
	}
	ret := make(map[string]interface{})
	ret["roles"] = sroles
	ret["page"] = page
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "List of roles paginated", nil, ret)
}

// ListAllUserRole serve listing of all roles belong to user, both direct or indirect
func ListAllUserRole(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "ListAllUserRole").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/all-roles", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	pageRequest, err := helper.NewPageRequestFromRequest(r)
	if err != nil {
		fLog.Errorf("helper.NewPageRequestFromRequest got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	roles, page, err := UserRepo.ListAllUserRoles(r.Context(), user, pageRequest)
	if err != nil {
		fLog.Errorf("UserRepo.ListAllUserRoles got %s", err.Error())
	}
	sroles := make([]*SimpleRole, len(roles))
	for k, v := range roles {
		sroles[k] = &SimpleRole{
			RecID:    v.RecID,
			RoleName: v.RoleName,
		}
	}
	ret := make(map[string]interface{})
	ret["roles"] = sroles
	ret["page"] = page
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "List of roles paginated", nil, ret)
}

// CreateUserRole serve a user-role relation
func CreateUserRole(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "CreateUserRole").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/role/{roleRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	_, err = UserRoleRepo.CreateUserRole(r.Context(), user, role)
	if err != nil {
		fLog.Errorf("UserRoleRepo.CreateUserRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User-Role created", nil, nil)
}

// DeleteUserRole serve the user deletion
func DeleteUserRole(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "DeleteUserRole").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/role/{roleRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	userRole, err := UserRoleRepo.GetUserRole(r.Context(), user, role)
	if err != nil {
		fLog.Errorf("UserRoleRepo.GetUserRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	err = UserRoleRepo.DeleteUserRole(r.Context(), userRole)
	if err != nil {
		fLog.Errorf("UserRoleRepo.DeleteUserRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User-Role deleted", nil, nil)
}

// ListUserGroup serve a user-group listing
func ListUserGroup(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "ListUserGroup").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/groups", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	pageRequest, err := helper.NewPageRequestFromRequest(r)
	if err != nil {
		fLog.Errorf("helper.NewPageRequestFromRequest got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	groups, page, err := UserGroupRepo.ListUserGroupByUser(r.Context(), user, pageRequest)
	if err != nil {
		fLog.Errorf("UserGroupRepo.ListUserGroupByUser got %s", err.Error())
	}
	sgroups := make([]*SimpleGroup, len(groups))
	for k, v := range groups {
		sgroups[k] = &SimpleGroup{
			RecID:     v.RecID,
			GroupName: v.GroupName,
		}
	}
	ret := make(map[string]interface{})
	ret["groups"] = sgroups
	ret["page"] = page
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "List of groups paginated", nil, ret)
}

// CreateUserGroup serve creation of user-group relation
func CreateUserGroup(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "CreateUserGroup").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/group/{groupRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	_, err = UserGroupRepo.CreateUserGroup(r.Context(), user, group)
	if err != nil {
		fLog.Errorf("UserGroupRepo.CreateUserGroup got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User-Group created", nil, nil)
}

// DeleteUserGroup serve deleting a user-group relation
func DeleteUserGroup(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "DeleteUserGroup").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/group/{groupRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	ug, err := UserGroupRepo.GetUserGroup(r.Context(), user, group)
	if err != nil {
		fLog.Errorf("UserGroupRepo.GetUserGroup got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	err = UserGroupRepo.DeleteUserGroup(r.Context(), ug)
	if err != nil {
		fLog.Errorf("UserGroupRepo.DeleteUserGroup got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User-Group deleted", nil, nil)

}

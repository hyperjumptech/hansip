package mgmnt

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/constants"
	"github.com/hyperjumptech/hansip/internal/mailer"
	"github.com/hyperjumptech/hansip/pkg/helper"
	"github.com/hyperjumptech/hansip/pkg/totp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

var (
	userMgmtLogger = log.WithField("go", "UserManagement")
)

// Show2FAQrCode shows 2FA QR code. It returns a PNG image bytes.
func Show2FAQrCode(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "Show2FAQrCode").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/2FAQR", r.URL.Path)
	if err != nil {
		fLog.Errorf("helper.ParsePathParams got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}

	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecID"])
	if err != nil || user == nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("User not found"), nil, nil)
		return
	}

	png, err := totp.MakeTotpQrImage(user.UserTotpSecretKey, fmt.Sprintf("AAA:%s", user.Email))
	if err != nil {
		fLog.Errorf("totp.MakeTotpQrImage got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	w.Header().Add("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	w.Write(png)
}

// SimpleUser struct
type SimpleUser struct {
	RecID     string `json:"rec_id"`
	Email     string `json:"email"`
	Enabled   bool   `json:"enabled"`
	Suspended bool   `json:"suspended"`
}

// ListAllUsers handler
func ListAllUsers(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "ListAllUsers").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
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

// CreateNewUserRequest email / passphrase struct
type CreateNewUserRequest struct {
	Email      string `json:"email"`
	Passphrase string `json:"passphrase"`
}

// CreateNewUserResponse struct
type CreateNewUserResponse struct {
	RecordID    string    `json:"rec_id"`
	Email       string    `json:"email"`
	Enabled     bool      `json:"enabled"`
	Suspended   bool      `json:"suspended"`
	LastSeen    time.Time `json:"last_seen"`
	LastLogin   time.Time `json:"last_login"`
	TotpEnabled bool      `json:"2fa_enabled"`
}

// CreateNewUser create new user handler
func CreateNewUser(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "CreateNewUser").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
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

// ChangePassphraseRequest old to new passphrase struct
type ChangePassphraseRequest struct {
	OldPassphrase string `json:"old_passphrase"`
	NewPassphrase string `json:"new_passphrase"`
}

// ChangePassphrase handles passphrase change
func ChangePassphrase(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "ChangePassphrase").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
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
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecID"])
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

// ActivateUserRequest user activation request struct
type ActivateUserRequest struct {
	Email           string
	ActivationToken string
}

// ActivateUser serve user activation process
func ActivateUser(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "ActivateUser").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
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
	user, err := UserRepo.GetUserByEmail(r.Context(), c.Email)
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByEmail got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	if user.ActivationCode == c.ActivationToken {
		user.Enabled = true
		err := UserRepo.SaveOrUpdate(r.Context(), user)
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
		ret["2fa_enabled"] = user.Enable2FactorAuth
		helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User activated", nil, ret)
	} else {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, "Activation token and email not match", nil, nil)
	}
}

// GetUserDetail serve fetch user detail
func GetUserDetail(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "GetUserDetail").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecID"])
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
	ret["2fa_enabled"] = user.Enable2FactorAuth
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User retrieved", nil, ret)
}

// UpdateUserRequest user update request struct
type UpdateUserRequest struct {
	Email     string `json:"email"`
	Enabled   bool   `json:"enabled"`
	Suspended bool   `json:"suspended"`
	Enable2FA bool   `json:"2fa_enabled"`
}

// UpdateUserDetail rest endpoint to update user detail
func UpdateUserDetail(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "GetUserDetail").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecID"])
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
		user.UserTotpSecretKey = totp.MakeRandomTotpKey()
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
	ret["2fa_enabled"] = user.Enable2FactorAuth
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User updated", nil, ret)

}

// DeleteUser serve user deletion
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	fLog := userMgmtLogger.WithField("func", "DeleteUser").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecID"])
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
	fLog := userMgmtLogger.WithField("func", "ListUserRole").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/roles", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecID"])
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
	fLog := userMgmtLogger.WithField("func", "ListAllUserRole").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/all-roles", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecID"])
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
	fLog := userMgmtLogger.WithField("func", "CreateUserRole").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/role/{roleRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecID"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecID"])
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
	fLog := userMgmtLogger.WithField("func", "DeleteUserRole").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/role/{roleRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecID"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecID"])
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
	fLog := userMgmtLogger.WithField("func", "ListUserGroup").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/groups", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecID"])
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
	fLog := userMgmtLogger.WithField("func", "CreateUserGroup").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/group/{groupRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecID"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecID"])
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
	fLog := userMgmtLogger.WithField("func", "DeleteUserGroup").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/user/{userRecId}/group/{groupRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecID"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecID"])
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

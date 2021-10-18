package endpoint

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hyperjumptech/hansip/internal/constants"
	"github.com/hyperjumptech/hansip/internal/hansipcontext"
	"github.com/hyperjumptech/hansip/pkg/helper"
	log "github.com/sirupsen/logrus"
)

var (
	roleMgmtLogger = log.WithField("go", "RoleManagement")
)

// SetRoleUsers Assign a Role to User
func SetRoleUsers(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "SetRoleUsers").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)

	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Error(err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if role == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recID %s not found", params["roleRecId"]), nil, nil)
		return
	}

	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.IsAdminOfDomain(role.RoleDomain) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to access this resource", nil, nil)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fLog.Errorf("ioutil.ReadAll got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	userIds := make([]string, 0)
	err = json.Unmarshal(body, &userIds)
	if err != nil {
		fLog.Errorf("json.Unmarshal got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}

	err = UserRoleRepo.DeleteUserRoleByRole(r.Context(), role)
	if err != nil {
		fLog.Errorf("UserRoleRepo.DeleteUserRoleByRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}

	counter := 0
	for _, userID := range userIds {
		user, err := UserRepo.GetUserByRecID(r.Context(), userID)
		if err != nil {
			fLog.Warnf("UserRepo.GetUserByRecID got %s, this user %s will not be added to role %s user", err.Error(), userID, role.RecID)
		} else if user == nil {
			fLog.Warnf("This user %s not exist and will not be added to role %s user", userID, role.RecID)
		} else {
			_, err := UserRoleRepo.CreateUserRole(r.Context(), user, role)
			if err != nil {
				fLog.Warnf("UserRoleRepo.CreateUserRole got %s, this role %s will not be added to user %s role", err.Error(), userID, role.RecID)
			} else {
				counter++
			}
			RevocationRepo.Revoke(r.Context(), user.Email)
		}
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, fmt.Sprintf("%d users added the role", counter), nil, nil)
}

// DeleteRoleUsers removes user from roles
func DeleteRoleUsers(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "DeleteRoleUsers").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}

	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Error(err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if role == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recID %s not found", params["roleRecId"]), nil, nil)
		return
	}

	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.IsAdminOfDomain(role.RoleDomain) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to access this resource", nil, nil)
		return
	}

	err = UserRoleRepo.DeleteUserRoleByRole(r.Context(), role)
	if err != nil {
		fLog.Errorf("UserRoleRepo.DeleteUserRoleByRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "successfuly removed role from all user", nil, nil)
}

// SetRoleGroups assignes a role to groups
func SetRoleGroups(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "SetRoleGroups").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Error(err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if role == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recID %s not found", params["roleRecId"]), nil, nil)
		return
	}

	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.IsAdminOfDomain(role.RoleDomain) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to access this resource", nil, nil)
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

	err = GroupRoleRepo.DeleteGroupRoleByRole(r.Context(), role)
	if err != nil {
		fLog.Errorf("GroupRoleRepo.DeleteGroupRoleByRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}

	counter := 0
	for _, groupID := range groupIds {
		group, err := GroupRepo.GetGroupByRecID(r.Context(), groupID)
		if err != nil {
			fLog.Warnf("UserRepo.GetUserByRecID got %s, this group %s will not be added to role %s user", err.Error(), groupID, role.RecID)
		} else if group == nil {
			fLog.Warnf("This group %s is not exist and will not be added to role %s user", groupID, role.RecID)
		} else {
			_, err := GroupRoleRepo.CreateGroupRole(r.Context(), group, role)
			if err != nil {
				fLog.Warnf("UserRoleRepo.CreateUserRole got %s, this group %s will not be added to user %s role", err.Error(), groupID, role.RecID)
			} else {
				counter++
			}
		}
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, fmt.Sprintf("%d groups added the role", counter), nil, nil)
}

// DeleteRoleGroups deletes role groups
func DeleteRoleGroups(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "DeleteRoleGroups").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)

	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Error(err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if role == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recID %s not found", params["roleRecId"]), nil, nil)
		return
	}

	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.IsAdminOfDomain(role.RoleDomain) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to access this resource", nil, nil)
		return
	}

	err = GroupRoleRepo.DeleteGroupRoleByRole(r.Context(), role)
	if err != nil {
		fLog.Errorf("GroupRoleRepo.DeleteGroupRoleByRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "successfuly removed role from all group", nil, nil)
}

// ListAllRole handling endpoint to serve Listing all roles in database.
func ListAllRole(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "ListAllRole").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)

	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/tenant/{tenantRecId}/roles", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}

	tenant, err := TenantRepo.GetTenantByRecID(r.Context(), params["tenantRecId"])
	if err != nil {
		fLog.Errorf("TenantRepo.GetTenantByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if tenant == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Tenant recID %s not found", params["tenantRecId"]), nil, nil)
		return
	}

	pageRequest, err := helper.NewPageRequestFromRequest(r)
	if err != nil {
		fLog.Errorf("helper.NewPageRequestFromRequest got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	roles, page, err := RoleRepo.ListRoles(r.Context(), tenant, pageRequest)
	if err != nil {
		fLog.Errorf("RoleRepo.ListRoles got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	ret := make(map[string]interface{})
	ret["roles"] = roles
	ret["page"] = page
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "List of all roles paginated", nil, ret)
}

// CreateRoleRequest hold dta model for requesting to create new role
type CreateRoleRequest struct {
	RoleName    string `json:"role_name"`
	RoleDomain  string `json:"role_domain"`
	Description string `json:"description"`
}

// CreateRole serve the creation new role endpoint
func CreateRole(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "CreateRole").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)

	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	req := &CreateRoleRequest{}
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
	tenant, err := TenantRepo.GetTenantByDomain(r.Context(), req.RoleDomain)
	if err != nil {
		fLog.Errorf("TenantRepo.GetTenantByDomain got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if tenant == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Tenant Domain %s not found", req.RoleDomain), nil, nil)
		return
	}

	if strings.Contains(req.RoleName, "@") || strings.Contains(req.RoleDomain, "@") {
		fLog.Errorf("RoleName or RoleDomain contains @")
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, "RoleName or RoleDomain contains @", nil, nil)
		return
	}

	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.IsAdminOfDomain(req.RoleDomain) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to create role with the specified domain", nil, nil)
		return
	}

	role, err := RoleRepo.CreateRole(r.Context(), req.RoleName, req.RoleDomain, req.Description)
	if err != nil {
		fLog.Errorf("RoleRepo.CreateRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Success creating role", nil, role)
	return
}

// UpdateRole serving request to update role detail
func UpdateRole(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "UpdateRole").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)

	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	req := &CreateRoleRequest{}
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

	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if role == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recid %s not found", params["roleRecId"]), nil, nil)
		return
	}

	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !(authCtx.IsAdminOfDomain(role.RoleDomain) && authCtx.IsAdminOfDomain(req.RoleDomain)) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, fmt.Sprintf("forbidden. you are not admin of %s and %s domain", role.RoleDomain, req.RoleDomain), nil, nil)
		return
	}

	role.RoleName = req.RoleName
	role.RoleDomain = req.RoleDomain
	role.Description = req.Description

	exRole, err := RoleRepo.GetRoleByName(r.Context(), req.RoleName, req.RoleDomain)
	if err == nil && exRole != nil && exRole.RoleName == req.RoleName && exRole.RecID != params["roleRecId"] {
		fLog.Errorf("Duplicate role name. role %s already exist", req.RoleName)
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}

	err = RoleRepo.UpdateRole(r.Context(), role)
	if err != nil {
		fLog.Errorf("RoleRepo.SaveOrUpdateRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Role updated", nil, role)
}

// GetRoleDetail serving request to get role detail
func GetRoleDetail(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "GetRoleDetail").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)

	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if role == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recid %s not found", params["roleRecId"]), nil, nil)
		return
	}

	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.IsAdminOfDomain(role.RoleDomain) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to create role with the specified domain", nil, nil)
		return
	}

	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Role fetched", nil, role)
}

// DeleteRole serving request to delete a role
func DeleteRole(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "DeleteRole").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)

	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if role == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recid %s not found", params["roleRecId"]), nil, nil)
		return
	}

	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.IsAdminOfDomain(role.RoleDomain) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to create role with the specified domain", nil, nil)
		return
	}

	RoleRepo.DeleteRole(r.Context(), role)
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Role deleted", nil, nil)
}

// ListRoleUser serving request to list user-role.
func ListRoleUser(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "ListRoleUser").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)

	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if role == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recid %s not found", params["roleRecId"]), nil, nil)
		return
	}

	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.IsAdminOfDomain(role.RoleDomain) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to create role with the specified domain", nil, nil)
		return
	}

	pageRequest, err := helper.NewPageRequestFromRequest(r)
	if err != nil {
		fLog.Errorf("helper.NewPageRequestFromRequest got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	users, page, err := UserRoleRepo.ListUserRoleByRole(r.Context(), role, pageRequest)
	if err != nil {
		fLog.Errorf("UserRoleRepo.ListUserRoleByRole got %s", err.Error())
	}
	susers := make([]*SimpleUser, len(users))
	for k, v := range users {
		susers[k] = &SimpleUser{
			RecID:     v.RecID,
			Email:     v.Email,
			Enabled:   v.Enabled,
			Suspended: v.Suspended,
		}
	}
	ret := make(map[string]interface{})
	ret["users"] = susers
	ret["page"] = page
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "List of users paginated", nil, ret)
}

// CreateRoleUser serving request to create new user-role
func CreateRoleUser(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "CreateRoleUser").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)

	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/user/{userRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if role == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recid %s not found", params["roleRecId"]), nil, nil)
		return
	}

	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.IsAdminOfDomain(role.RoleDomain) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to create role with the specified domain", nil, nil)
		return
	}

	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	if user == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("User recid %s not found", params["userRecId"]), nil, nil)
		return
	}

	_, err = UserRoleRepo.CreateUserRole(r.Context(), user, role)
	if err != nil {
		fLog.Errorf("UserRoleRepo.CreateUserRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	RevocationRepo.Revoke(r.Context(), user.Email)
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User-Role created", nil, nil)
}

// DeleteRoleUser serving request to delete user-role
func DeleteRoleUser(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "DeleteRoleUser").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)

	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/user/{userRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if role == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recid %s not found", params["roleRecId"]), nil, nil)
		return
	}

	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.IsAdminOfDomain(role.RoleDomain) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to create role with the specified domain", nil, nil)
		return
	}

	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if user == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("User recid %s not found", params["userRecId"]), nil, nil)
		return
	}

	ug, err := UserRoleRepo.GetUserRole(r.Context(), user, role)
	if err != nil {
		fLog.Errorf("UserRoleRepo.GetUserRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if ug == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, "Role is not belong to user", nil, nil)
		return
	}
	err = UserRoleRepo.DeleteUserRole(r.Context(), ug)
	if err != nil {
		fLog.Errorf("UserRoleRepo.DeleteUserRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	RevocationRepo.Revoke(r.Context(), user.Email)
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User-Role deleted", nil, nil)
}

// ListRoleGroup endpoint to serve group-role
func ListRoleGroup(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "ListRoleGroup").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)

	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if role == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recid %s not found", params["roleRecId"]), nil, nil)
		return
	}

	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.IsAdminOfDomain(role.RoleDomain) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to access role with the specified domain", nil, nil)
		return
	}

	pageRequest, err := helper.NewPageRequestFromRequest(r)
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	groups, page, err := GroupRoleRepo.ListGroupRoleByRole(r.Context(), role, pageRequest)
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

// CreateRoleGroup serving request to create new group-role
func CreateRoleGroup(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "CreateRoleGroup").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)

	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/group/{groupRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if role == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recid %s not found", params["roleRecId"]), nil, nil)
		return
	}

	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.IsAdminOfDomain(role.RoleDomain) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to manage role with the specified domain", nil, nil)
		return
	}

	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if group == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Group recid %s not found", params["groupRecId"]), nil, nil)
		return
	}

	if role.RoleDomain != group.GroupDomain {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "Role can not be added into group with different domain", nil, nil)
		return
	}

	_, err = GroupRoleRepo.CreateGroupRole(r.Context(), group, role)
	if err != nil {
		fLog.Errorf("GroupRoleRepo.CreateGroupRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Group-Role created", nil, nil)
}

// DeleteRoleGroup serving request to delete group-role
func DeleteRoleGroup(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "DeleteRoleGroup").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)

	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/group/{groupRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if role == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recid %s not found", params["roleRecId"]), nil, nil)
		return
	}

	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.IsAdminOfDomain(role.RoleDomain) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to create role with the specified domain", nil, nil)
		return
	}

	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if group == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Group recid %s not found", params["groupRecId"]), nil, nil)
		return
	}
	gr, err := GroupRoleRepo.GetGroupRole(r.Context(), group, role)
	if err != nil {
		fLog.Errorf("GroupRoleRepo.GetGroupRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	if gr == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, "Role is not belong to group", nil, nil)
		return
	}
	err = GroupRoleRepo.DeleteGroupRole(r.Context(), gr)
	if err != nil {
		fLog.Errorf("GroupRoleRepo.DeleteGroupRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User-Group deleted", nil, nil)
}

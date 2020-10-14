package mgmnt

import (
	"encoding/json"
	"fmt"
	"github.com/hyperjumptech/hansip/internal/constants"
	"github.com/hyperjumptech/hansip/pkg/helper"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

var (
	roleMgmtLogger = log.WithField("go", "RoleManagement")
)

func SetRoleUsers(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "SetRoleUsers").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recID %s not found", params["roleRecId"]), nil, nil)
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
	for _, userId := range userIds {
		user, err := UserRepo.GetUserByRecID(r.Context(), userId)
		if err != nil {
			fLog.Warnf("UserRepo.GetUserByRecID got %s, this user %s will not be added to role %s user", err.Error(), userId, role.RecID)
		} else {
			_, err := UserRoleRepo.CreateUserRole(r.Context(), user, role)
			if err != nil {
				fLog.Warnf("UserRoleRepo.CreateUserRole got %s, this role %s will not be added to user %s role", err.Error(), userId, role.RecID)
			} else {
				counter++
			}
		}
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, fmt.Sprintf("%d users added the role", counter), nil, nil)
}

func DeleteRoleUsers(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "DeleteRoleUsers").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recID %s not found", params["roleRecId"]), nil, nil)
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
func SetRoleGroups(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "SetRoleGroups").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recID %s not found", params["roleRecId"]), nil, nil)
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
	for _, groupId := range groupIds {
		group, err := GroupRepo.GetGroupByRecID(r.Context(), groupId)
		if err != nil {
			fLog.Warnf("UserRepo.GetUserByRecID got %s, this group %s will not be added to role %s user", err.Error(), groupId, role.RecID)
		} else {
			_, err := GroupRoleRepo.CreateGroupRole(r.Context(), group, role)
			if err != nil {
				fLog.Warnf("UserRoleRepo.CreateUserRole got %s, this group %s will not be added to user %s role", err.Error(), groupId, role.RecID)
			} else {
				counter++
			}
		}
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, fmt.Sprintf("%d groups added the role", counter), nil, nil)
}

func DeleteRoleGroups(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "DeleteRoleGroups").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Role recID %s not found", params["roleRecId"]), nil, nil)
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
	pageRequest, err := helper.NewPageRequestFromRequest(r)
	if err != nil {
		fLog.Errorf("helper.NewPageRequestFromRequest got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	roles, page, err := RoleRepo.ListRoles(r.Context(), pageRequest)
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
	Description string `json:"description"`
}

// CreateRole serve the creation new role endpoint
func CreateRole(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "CreateRole").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
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
	role, err := RoleRepo.CreateRole(r.Context(), req.RoleName, req.Description)
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
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	role.RoleName = req.RoleName
	role.Description = req.Description

	exRole, err := RoleRepo.GetRoleByName(r.Context(), req.RoleName)
	if err == nil && exRole.RoleName == req.RoleName && exRole.RecID != params["roleRecId"] {
		fLog.Errorf("Duplicate role name. role %s already exist", req.RoleName)
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}

	err = RoleRepo.SaveOrUpdateRole(r.Context(), role)
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
	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Role fetched", nil, role)
}

// DeleteRole serving request to delete a role
func DeleteRole(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "DeleteRole").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	RoleRepo.DeleteRole(r.Context(), role)
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Role deleted", nil, nil)
}

// ListRoleUser serving request to list user-role.
func ListRoleUser(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "ListRoleUser").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
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
	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/user/{userRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
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

// DeleteRoleUser serving request to delete user-role
func DeleteRoleUser(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "DeleteRoleUser").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/user/{userRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	ug, err := UserRoleRepo.GetUserRole(r.Context(), user, role)
	if err != nil {
		fLog.Errorf("UserRoleRepo.GetUserRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	err = UserRoleRepo.DeleteUserRole(r.Context(), ug)
	if err != nil {
		fLog.Errorf("UserRoleRepo.DeleteUserRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User-Role deleted", nil, nil)
}

// ListRoleGroup endpoint to serve group-role
func ListRoleGroup(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "ListRoleGroup").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
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
	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/group/{groupRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
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
	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/role/{roleRecId}/group/{groupRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	role, err := RoleRepo.GetRoleByRecID(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	gr, err := GroupRoleRepo.GetGroupRole(r.Context(), group, role)
	if err != nil {
		fLog.Errorf("GroupRoleRepo.GetGroupRole got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
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

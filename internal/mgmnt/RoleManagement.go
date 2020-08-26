package mgmnt

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/hyperjumptech/hansip/internal/constants"
	"github.com/hyperjumptech/hansip/pkg/helper"
	log "github.com/sirupsen/logrus"
)

var (
	roleMgmtLogger = log.WithField("go", "RoleManagement")
)

// ListAllRole handler
func ListAllRole(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "ListAllRole").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
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
	sroles := make([]*SimpleRole, len(roles))
	for k, v := range roles {
		sroles[k] = &SimpleRole{
			RecID:    v.RecId,
			RoleName: v.RoleName,
		}
	}
	ret := make(map[string]interface{})
	ret["roles"] = sroles
	ret["page"] = page
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "List of all roles paginated", nil, ret)
}

// CreateRoleRequest is role name and description
type CreateRoleRequest struct {
	RoleName    string `json:"role_name"`
	Description string `json:"description"`
}

// CreateRole handler
func CreateRole(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "CreateRole").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
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

// GetRoleDetail handler
func GetRoleDetail(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "GetRoleDetail").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/role/{roleRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecId(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecId got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Role fetched", nil, role)
}

// DeleteRole delete role handler
func DeleteRole(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "DeleteRole").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/role/{roleRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecId(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecId got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	RoleRepo.DeleteRole(r.Context(), role)
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Role deleted", nil, nil)
}

// ListRoleUser handler
func ListRoleUser(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "ListRoleUser").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/role/{roleRecId}/users", r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecId(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecId got %s", err.Error())
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
			RecID:     v.RecId,
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

// CreateRoleUser handler
func CreateRoleUser(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "CreateRoleUser").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/role/{roleRecId}/user/{userRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecId(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecId got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	user, err := UserRepo.GetUserByRecId(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecId got %s", err.Error())
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

// DeleteRoleUser handler
func DeleteRoleUser(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "DeleteRoleUser").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/role/{roleRecId}/user/{userRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecId(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecId got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	user, err := UserRepo.GetUserByRecId(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecId got %s", err.Error())
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

// ListRoleGroup handler
func ListRoleGroup(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "ListRoleGroup").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/role/{roleRecId}/groups", r.URL.Path)
	if err != nil {
		panic(err)
	}
	role, err := RoleRepo.GetRoleByRecId(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecId got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	pageRequest, err := helper.NewPageRequestFromRequest(r)
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecId got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	groups, page, err := GroupRoleRepo.ListGroupRoleByRole(r.Context(), role, pageRequest)
	sgroups := make([]*SimpleGroup, len(groups))
	for k, v := range groups {
		sgroups[k] = &SimpleGroup{
			RecID:     v.RecId,
			GroupName: v.GroupName,
		}
	}
	ret := make(map[string]interface{})
	ret["groups"] = sgroups
	ret["page"] = page
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "List of groups paginated", nil, ret)
}

// CreateRoleGroup handler
func CreateRoleGroup(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "CreateRoleGroup").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/role/{roleRecId}/group/{groupRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	group, err := GroupRepo.GetGroupByRecId(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecId got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	role, err := RoleRepo.GetRoleByRecId(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecId got %s", err.Error())
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

// DeleteRoleGroup handler
func DeleteRoleGroup(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "DeleteRoleGroup").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/role/{roleRecId}/group/{groupRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	group, err := GroupRepo.GetGroupByRecId(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecId got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	role, err := RoleRepo.GetRoleByRecId(r.Context(), params["roleRecId"])
	if err != nil {
		fLog.Errorf("RoleRepo.GetRoleByRecId got %s", err.Error())
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

package mgmnt

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/hyperjumptech/hansip/internal/constants"
	"github.com/hyperjumptech/hansip/pkg/helper"
	log "github.com/sirupsen/logrus"
)

// SimpleGroup is record id and group name pair
type SimpleGroup struct {
	RecID     string `json:"rec_id"`
	GroupName string `json:"group_name"`
}

var (
	groupMgmtLog = log.WithField("go", "GroupManagement")
)

// ListAllGroup handler
func ListAllGroup(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "ListAllGroup").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	pageRequest, err := helper.NewPageRequestFromRequest(r)
	if err != nil {
		fLog.Errorf("helper.NewPageRequestFromRequest got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	groups, page, err := GroupRepo.ListGroups(r.Context(), pageRequest)
	if err != nil {
		fLog.Errorf("GroupRepo.ListGroups got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
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
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "List of all user paginated", nil, ret)
}

// CreateGroupRequest is groupName and description
type CreateGroupRequest struct {
	GroupName   string `json:"group_name"`
	Description string `json:"description"`
}

// CreateNewGroup handler
func CreateNewGroup(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "CreateNewGroup").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	req := &CreateGroupRequest{}
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
	group, err := GroupRepo.CreateGroup(r.Context(), req.GroupName, req.Description)
	if err != nil {
		fLog.Errorf("GroupRepo.CreateGroup got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Success creating group", nil, group)
	return
}

// GetGroupDetail handler
func GetGroupDetail(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "GetGroupDetail").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/group/{groupRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Group fetched", nil, group)
}

// DeleteGroup handler
func DeleteGroup(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "DeleteGroup").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/group/{groupRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	GroupRepo.DeleteGroup(r.Context(), group)
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Group deleted", nil, nil)
}

// ListGroupUser handler
func ListGroupUser(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "ListGroupUser").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/group/{groupRecId}/users", r.URL.Path)
	if err != nil {
		panic(err)
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	pageRequest, err := helper.NewPageRequestFromRequest(r)
	if err != nil {
		fLog.Errorf("helper.NewPageRequestFromRequest got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	users, page, err := UserGroupRepo.ListUserGroupByGroup(r.Context(), group, pageRequest)
	if err != nil {
		fLog.Errorf("UserGroupRepo.ListUserGroupByGroup got %s", err.Error())
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

// CreateGroupUser handler
func CreateGroupUser(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "CreateGroupUser").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/group/{groupRecId}/user/{userRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecId got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
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

// DeleteGroupUser handler
func DeleteGroupUser(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "DeleteGroupUser").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/group/{groupRecId}/user/{userRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	user, err := UserRepo.GetUserByRecID(r.Context(), params["userRecId"])
	if err != nil {
		fLog.Errorf("UserRepo.GetUserByRecID got %s", err.Error())
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
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User-Group deleted", nil, nil)
}

// ListGroupRole handler
func ListGroupRole(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "ListGroupRole").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/group/{groupRecId}/roles", r.URL.Path)
	if err != nil {
		panic(err)
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	pageRequest, err := helper.NewPageRequestFromRequest(r)
	if err != nil {
		fLog.Errorf("helper.NewPageRequestFromRequest got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	roles, page, err := GroupRoleRepo.ListGroupRoleByGroup(r.Context(), group, pageRequest)
	if err != nil {
		fLog.Errorf("GroupRoleRepo.ListGroupRoleByGroup got %s", err.Error())
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

// CreateGroupRole handler
func CreateGroupRole(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "CreateGroupRole").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/group/{groupRecId}/role/{roleRecId}", r.URL.Path)
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

// DeleteGroupRole handler
func DeleteGroupRole(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "DeleteGroupRole").WithField("RequestId", r.Context().Value(constants.RequestId)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/group/{groupRecId}/role/{roleRecId}", r.URL.Path)
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

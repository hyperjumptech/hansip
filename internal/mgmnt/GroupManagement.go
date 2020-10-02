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

// SimpleGroup hold basic data of group
type SimpleGroup struct {
	RecID     string `json:"rec_id"`
	GroupName string `json:"group_name"`
}

var (
	groupMgmtLog = log.WithField("go", "GroupManagement")
)

func SetGroupUsers(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "SetRoleUsers").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/group/{groupRecId}/users", r.URL.Path)
	if err != nil {
		panic(err)
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Group recID %s not found", params["groupRecId"]), nil, nil)
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

	err = UserGroupRepo.DeleteUserGroupByGroup(r.Context(), group)
	if err != nil {
		fLog.Errorf("UserGroupRepo.DeleteUserGroupByGroup got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}

	counter := 0
	for _, userId := range userIds {
		user, err := UserRepo.GetUserByRecID(r.Context(), userId)
		if err != nil {
			fLog.Warnf("UserRepo.GetUserByRecID got %s, this user %s will not be added to group %s user", err.Error(), userId, group.RecID)
		} else {
			_, err := UserGroupRepo.CreateUserGroup(r.Context(), user, group)
			if err != nil {
				fLog.Warnf("UserGroupRepo.CreateUserGroup got %s, this role %s will not be added to group %s user", err.Error(), userId, group.RecID)
			} else {
				counter++
			}
		}
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, fmt.Sprintf("%d users added the group", counter), nil, nil)
}
func DeleteGroupUsers(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "SetRoleUsers").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/group/{groupRecId}/users", r.URL.Path)
	if err != nil {
		panic(err)
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Group recID %s not found", params["groupRecId"]), nil, nil)
		return
	}
	err = UserGroupRepo.DeleteUserGroupByGroup(r.Context(), group)
	if err != nil {
		fLog.Errorf("UserGroupRepo.DeleteUserGroupByGroup got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "successfuly cleared group member", nil, nil)
}
func SetGroupRoles(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "SetRoleUsers").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/group/{groupRecId}/roles", r.URL.Path)
	if err != nil {
		panic(err)
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Group recID %s not found", params["groupRecId"]), nil, nil)
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

	err = GroupRoleRepo.DeleteGroupRoleByGroup(r.Context(), group)
	if err != nil {
		fLog.Errorf("GroupRoleRepo.DeleteGroupRoleByGroup got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}

	counter := 0
	for _, roleId := range roleIds {
		role, err := RoleRepo.GetRoleByRecID(r.Context(), roleId)
		if err != nil {
			fLog.Warnf("RoleRepo.GetRoleByRecID got %s, this role %s will not be added to group %s role", err.Error(), roleId, group.RecID)
		} else {
			_, err := GroupRoleRepo.CreateGroupRole(r.Context(), group, role)
			if err != nil {
				fLog.Warnf("GroupRoleRepo.CreateGroupRole got %s, this role %s will not be added to group %s role", err.Error(), roleId, group.RecID)
			} else {
				counter++
			}
		}
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, fmt.Sprintf("%d roles added the group", counter), nil, nil)
}

func DeleteGroupRoles(w http.ResponseWriter, r *http.Request) {
	fLog := roleMgmtLogger.WithField("func", "SetRoleUsers").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/group/{groupRecId}/roles", r.URL.Path)
	if err != nil {
		panic(err)
	}
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, fmt.Sprintf("Group recID %s not found", params["groupRecId"]), nil, nil)
		return
	}
	err = GroupRoleRepo.DeleteGroupRoleByGroup(r.Context(), group)
	if err != nil {
		fLog.Errorf("GroupRoleRepo.DeleteGroupRoleByGroup got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "successfuly cleared all roles of group", nil, nil)
}

// ListAllGroup serving the listing of group request
func ListAllGroup(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "ListAllGroup").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
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
	ret := make(map[string]interface{})
	ret["groups"] = groups
	ret["page"] = page
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "List of all user paginated", nil, ret)
}

// CreateGroupRequest hold model for Create new Group.
type CreateGroupRequest struct {
	GroupName   string `json:"group_name"`
	Description string `json:"description"`
}

// CreateNewGroup serving request to create new Group
func CreateNewGroup(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "CreateNewGroup").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
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

// GetGroupDetail serving request to fetch group detail
func GetGroupDetail(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "GetGroupDetail").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/group/{groupRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}
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
	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	group.GroupName = req.GroupName
	group.Description = req.Description
	// TODO add logic to ensure no duplicate group name
	err = GroupRepo.SaveOrUpdateGroup(r.Context(), group)
	if err != nil {
		fLog.Errorf("GroupRepo.SaveOrUpdateGroup got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Group updated", nil, group)
}

// UpdateGroup serving request to update group detail
func UpdateGroup(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "UpdateGroup").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	params, err := helper.ParsePathParams("/api/v1/management/group/{groupRecId}", r.URL.Path)
	if err != nil {
		panic(err)
	}

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

	group, err := GroupRepo.GetGroupByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	group.GroupName = req.GroupName
	group.Description = req.Description

	exGroup, err := GroupRepo.GetGroupByName(r.Context(), req.GroupName)
	if err == nil && exGroup.GroupName == req.GroupName && exGroup.RecID != params["groupRecId"] {
		fLog.Errorf("Duplicate group name. group %s already exist", req.GroupName)
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}

	err = GroupRepo.SaveOrUpdateGroup(r.Context(), group)
	if err != nil {
		fLog.Errorf("GroupRepo.SaveOrUpdateGroupe got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Group updated", nil, group)

}

// DeleteGroup serving request to delete a group
func DeleteGroup(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "DeleteGroup").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
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

// ListGroupUser serving request to list Users of a group
func ListGroupUser(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "ListGroupUser").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
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

// CreateGroupUser serving request to create new User-Group
func CreateGroupUser(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "CreateGroupUser").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
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
	_, err = UserGroupRepo.CreateUserGroup(r.Context(), user, group)
	if err != nil {
		fLog.Errorf("UserGroupRepo.CreateUserGroup got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "User-Group created", nil, nil)
}

// DeleteGroupUser serving request to delete user-group
func DeleteGroupUser(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "DeleteGroupUser").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
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

// ListGroupRole serving request to list all group-role
func ListGroupRole(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "ListGroupRole").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
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

// CreateGroupRole serving reqest to create new group role
func CreateGroupRole(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "CreateGroupRole").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
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

// DeleteGroupRole serving request to delete group-role
func DeleteGroupRole(w http.ResponseWriter, r *http.Request) {
	fLog := groupMgmtLog.WithField("func", "DeleteGroupRole").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
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

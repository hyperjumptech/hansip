package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/connector"
	"github.com/hyperjumptech/hansip/internal/mailer"
	"github.com/hyperjumptech/hansip/internal/mgmnt"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var (
	dbUtil    connector.DBUtil
	apiPrefix = config.Get("api.path.prefix")
)

func pretifyJSON(sjson string) string {
	m := make(map[string]interface{})
	err := json.Unmarshal([]byte(sjson), &m)
	if err != nil {
		return "mot a json"
	}
	byt, err := json.MarshalIndent(m, "", "   ")
	if err != nil {
		return err.Error()
	}
	return string(byt)
}

func TestAll(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)
	/*
		ENVIRONMENT VARIABLE SETUP
	*/
	if testing.Short() {
		t.Log("Testing in short mode. Using in-memory database")
		config.SetConfig("setup.admin.enable", "true")
		config.SetConfig("db.type", "INMEMORY")
		config.SetConfig("mailer.type", "DUMMY")
	} else {
		t.Log("Testing in normal mode. Using local mysql database")
		config.SetConfig("setup.admin.enable", "true")
		config.SetConfig("db.type", "MYSQL")
		config.SetConfig("mailer.type", "DUMMY")
	}

	InitializeRouter()
	go mailer.Start()
	defer mailer.Stop()

	dbUtil = connector.GetMySQLDBInstance()

	err := dbUtil.DropAllTables(context.Background())
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	err = dbUtil.CreateAllTable(context.Background())
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	HealthCheckTesting(t)
	_, refreshToken := DummyAdminLoginTesting(t)
	t.Logf("Refresh token : %s", refreshToken)
	accessToken := DummyAdminRefreshTokenTesting(t, refreshToken)
	simpleUsers := ListUsersTesting(t, accessToken)
	if len(simpleUsers) != 0 {
		t.Error("User list should be empty.")
		t.FailNow()
	}
	CreateUserTesting(t, accessToken, "a.prefixed@email.com", "one two three four")
	CreateUserTesting(t, accessToken, "b.prefixed@email.com", "two three four five six")
	simpleUsers = ListUsersTesting(t, accessToken)
	if len(simpleUsers) != 2 {
		t.Error("User list should be 2.")
		t.FailNow()
	}
	if simpleUsers[0].Email != "b.prefixed@email.com" {
		t.Error("Should be sorted by email DESC.")
		t.FailNow()
	}
	user := GetUserByRecIDTesting(t, accessToken, simpleUsers[0].RecID)
	if user == nil {
		t.Error("Should not be nil")
		t.FailNow()
	} else {
		if user.Email != simpleUsers[0].Email {
			t.Errorf("Expect %s but %s", simpleUsers[0].Email, user.Email)
			t.FailNow()
		}
	}
	DeleteUserByRecIDTesting(t, accessToken, simpleUsers[0].RecID)
	CreateUserTesting(t, accessToken, "c.prefixed@email.com", "seven eight nine")
	simpleUsers = ListUsersTesting(t, accessToken)
	if len(simpleUsers) != 2 {
		t.Error("User list should be 2.")
		t.FailNow()
	}
	if simpleUsers[0].Email != "c.prefixed@email.com" {
		t.Error("Should be sorted by email DESC.")
		t.FailNow()
	}
	groups := ListGroupsTesting(t, accessToken)
	if len(groups) != 0 {
		t.Error("User list should be 0. But ", len(groups))
		t.FailNow()
	}
	roles := ListRolesTesting(t, accessToken)
	if len(roles) != 0 {
		t.Error("User list should be 0. But ", len(roles))
		t.FailNow()
	}
	for i := 0; i < 35; i++ {
		CreateUserTesting(t, accessToken, fmt.Sprintf("user-%d@email.com", i), fmt.Sprintf("this all number 00%d", i))
	}
	group1 := CreateNewGroupTesting(t, accessToken, "GroupOne")
	if group1.RecID == "" {
		t.Logf("group1 RecID empty")
		t.Fail()
	}
	role1 := CreateNewRoleTesting(t, accessToken, "RoleOne")
	if role1.RecID == "" {
		t.Logf("role1 RecID empty")
		t.Fail()
	}
	group2 := CreateNewGroupTesting(t, accessToken, "GroupTwo")
	if group2.RecID == "" {
		t.Logf("group2 RecID empty")
		t.Fail()
	}
	role2 := CreateNewRoleTesting(t, accessToken, "RoleTwo")
	if role2.RecID == "" {
		t.Logf("role2 RecID empty")
		t.Fail()
	}

	CreateUserGroupTesting(t, accessToken, simpleUsers[1].RecID, group1.RecID)
	CreateGroupUserTesting(t, accessToken, group2.RecID, simpleUsers[1].RecID)

	t.Logf("--- SipleUser[1].RecID = %s --- role1.RecID = %s", simpleUsers[1].RecID, role1.RecID)

	CreateUserRoleTesting(t, accessToken, simpleUsers[1].RecID, role1.RecID)
	CreateRoleUserTesting(t, accessToken, role2.RecID, simpleUsers[1].RecID)

	CreateGroupRoleTesting(t, accessToken, group1.RecID, role1.RecID)
	CreateRoleGroupTesting(t, accessToken, role2.RecID, group2.RecID)

	ListUserGroupByUser(t, accessToken, simpleUsers[1].RecID)
	ListUserGroupByGroup(t, accessToken, group2.RecID)

	ListUserRoleByUser(t, accessToken, simpleUsers[1].RecID)
	ListUserRoleByRole(t, accessToken, role1.RecID)

	ListGroupRoleByRole(t, accessToken, role1.RecID)
	ListGroupRoleByGroup(t, accessToken, group1.RecID)

	simpleUsers = ListUsersTesting(t, accessToken)
	if len(simpleUsers) != 10 {
		t.Error("User list should be 10.")
		t.FailNow()
	}
}

func ListUserGroupByUser(t *testing.T, accessToken, userRecID string) {
	t.Log("Testing List User-Group by User")
	recorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest("GET", fmt.Sprintf("%s/management/user/%s/groups?page_no=1&page_size=10&order_by=GROUP_NAME&sort=ASC", apiPrefix, userRecID), nil)
	createRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, createRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting ListUserGroup By User status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
	}
	t.Log(pretifyJSON(recorder.Body.String()))

}

func ListUserGroupByGroup(t *testing.T, accessToken, groupRecID string) {
	t.Log("Testing List User-Group by Group")
	recorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest("GET", fmt.Sprintf("%s/management/group/%s/users?page_no=1&page_size=10&order_by=EMAIL&sort=ASC", apiPrefix, groupRecID), nil)
	createRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, createRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting List UserGroup by Group status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
	}
	t.Log(pretifyJSON(recorder.Body.String()))

}

func ListUserRoleByUser(t *testing.T, accessToken, userRecID string) {
	t.Log("Testing List User-Role by User")
	recorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest("GET", fmt.Sprintf("%s/management/user/%s/roles?page_no=1&page_size=10&order_by=ROLE_NAME&sort=ASC", apiPrefix, userRecID), nil)
	createRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, createRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting List UserRole by User status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
	}
	t.Log(pretifyJSON(recorder.Body.String()))

}

func ListUserRoleByRole(t *testing.T, accessToken, roleRecID string) {
	t.Log("Testing List User-Role by Role")
	recorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest("GET", fmt.Sprintf("%s/management/role/%s/users?page_no=1&page_size=10&order_by=EMAIL&sort=ASC", apiPrefix, roleRecID), nil)
	createRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, createRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting List UserRole by Role status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
	}
	t.Log(pretifyJSON(recorder.Body.String()))

}

func ListGroupRoleByGroup(t *testing.T, accessToken, groupRecID string) {
	t.Log("Testing List Group-Role by Group")
	recorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest("GET", fmt.Sprintf("%s/management/group/%s/roles?page_no=1&page_size=10&order_by=ROLE_NAME&sort=ASC", apiPrefix, groupRecID), nil)
	createRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, createRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting List GroupRole by Group status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
	}
	t.Log(pretifyJSON(recorder.Body.String()))

}

func ListGroupRoleByRole(t *testing.T, accessToken, roleRecID string) {
	t.Log("Testing List Group-Role by Role")
	recorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest("GET", fmt.Sprintf("%s/management/role/%s/groups?page_no=1&page_size=10&order_by=GROUP_NAME&sort=ASC", apiPrefix, roleRecID), nil)
	createRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, createRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting List Group Role By Role status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
	}
	t.Log(pretifyJSON(recorder.Body.String()))

}

func CreateUserRoleTesting(t *testing.T, accessToken, userRecID, roleRecID string) {
	t.Log("Testing Create New UserRole")
	recorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest("PUT", fmt.Sprintf("%s/management/user/%s/role/%s", apiPrefix, userRecID, roleRecID), nil)
	createRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, createRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting create UserRole status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
	}
	t.Log(pretifyJSON(recorder.Body.String()))
}

func CreateRoleUserTesting(t *testing.T, accessToken, roleRecID, userRecID string) {
	t.Log("Testing Create New RoleUser")
	recorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest("PUT", fmt.Sprintf("%s/management/role/%s/user/%s", apiPrefix, roleRecID, userRecID), nil)
	createRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, createRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting create RoleUser status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
	}
	t.Log(pretifyJSON(recorder.Body.String()))

}

func CreateGroupRoleTesting(t *testing.T, accessToken, groupRecID, roleRecID string) {
	t.Log("Testing Create New GroupRole")
	recorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest("PUT", fmt.Sprintf("%s/management/group/%s/role/%s", apiPrefix, groupRecID, roleRecID), nil)
	createRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, createRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting create GroupRole status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
	}
	t.Log(pretifyJSON(recorder.Body.String()))

}

func CreateRoleGroupTesting(t *testing.T, accessToken, roleRecID, groupRecID string) {
	t.Log("Testing Create New RoleGroup")
	recorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest("PUT", fmt.Sprintf("%s/management/role/%s/group/%s", apiPrefix, roleRecID, groupRecID), nil)
	createRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, createRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting create RoleGroup status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
	}
	t.Log(pretifyJSON(recorder.Body.String()))
}

func CreateUserGroupTesting(t *testing.T, accessToken, userRecID, groupRecID string) {
	t.Log("Testing Create New UserGroup")
	recorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest("PUT", fmt.Sprintf("%s/management/user/%s/group/%s", apiPrefix, userRecID, groupRecID), nil)
	createRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, createRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting create UserGroup status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
	}
	t.Log(pretifyJSON(recorder.Body.String()))

}

func CreateGroupUserTesting(t *testing.T, accessToken, groupRecID, userRecID string) {
	t.Log("Testing Create New GroupUser")
	recorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest("PUT", fmt.Sprintf("%s/management/group/%s/user/%s", apiPrefix, groupRecID, userRecID), nil)
	t.Logf(createRequest.URL.Path)
	createRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, createRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting create GroupUser status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
	}
	t.Log(pretifyJSON(recorder.Body.String()))

}

func CreateNewGroupTesting(t *testing.T, accessToken, groupName string) *connector.Group {
	t.Log("Testing Create New Group")
	recorder := httptest.NewRecorder()
	body := map[string]string{
		"group_name":  groupName,
		"description": "passphrase",
	}
	sbody, _ := json.Marshal(body)
	createRequest := httptest.NewRequest("POST", fmt.Sprintf("%s/management/group", apiPrefix), bytes.NewReader(sbody))
	createRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	createRequest.Header.Add("Content-Type", "application/json")
	Router.ServeHTTP(recorder, createRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting delete user status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
		return nil
	}
	t.Log(pretifyJSON(recorder.Body.String()))
	jObj := make(map[string]interface{})
	_ = json.Unmarshal(recorder.Body.Bytes(), &jObj)
	data := jObj["data"].(map[string]interface{})
	ret := &connector.Group{
		RecID:       data["rec_id"].(string),
		GroupName:   data["group_name"].(string),
		Description: data["description"].(string),
	}
	return ret
}

func CreateNewRoleTesting(t *testing.T, accessToken, roleName string) *connector.Role {
	t.Log("Testing Create New Role")
	recorder := httptest.NewRecorder()
	body := map[string]string{
		"role_name":   roleName,
		"description": "passphrase",
	}
	sbody, _ := json.Marshal(body)
	createRequest := httptest.NewRequest("POST", fmt.Sprintf("%s/management/role", apiPrefix), bytes.NewReader(sbody))
	createRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	createRequest.Header.Add("Content-Type", "application/json")
	Router.ServeHTTP(recorder, createRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting delete user status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
		return nil
	}
	t.Log(pretifyJSON(recorder.Body.String()))
	jObj := make(map[string]interface{})
	_ = json.Unmarshal(recorder.Body.Bytes(), &jObj)
	data := jObj["data"].(map[string]interface{})
	ret := &connector.Role{
		RecID:       data["rec_id"].(string),
		RoleName:    data["role_name"].(string),
		Description: data["description"].(string),
	}
	return ret
}

func DeleteUserByRecIDTesting(t *testing.T, accessToken, recID string) {
	t.Log("Testing Delete User by RecID")
	recorder := httptest.NewRecorder()
	deleteUserRequest := httptest.NewRequest("DELETE", fmt.Sprintf("%s/management/user/%s", apiPrefix, recID), nil)
	deleteUserRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, deleteUserRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting delete user status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
	}
}

func GetUserByRecIDTesting(t *testing.T, accessToken, recID string) *SimpleUser {
	t.Log("Testing Get User by RecID")
	recorder := httptest.NewRecorder()
	getUserRequest := httptest.NewRequest("GET", fmt.Sprintf("%s/management/user/%s", apiPrefix, recID), nil)
	getUserRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, getUserRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting get user status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
		return nil
	}
	t.Log(pretifyJSON(recorder.Body.String()))
	jObj := make(map[string]interface{})
	_ = json.Unmarshal(recorder.Body.Bytes(), &jObj)
	data := jObj["data"].(map[string]interface{})
	ret := &SimpleUser{
		Email:     data["email"].(string),
		Enabled:   data["enabled"].(bool),
		RecID:     data["rec_id"].(string),
		Suspended: data["suspended"].(bool),
	}
	return ret
}

func CreateUserTesting(t *testing.T, accessToken, email, passphrase string) {
	t.Log("Testing Creating User. Pass : ", passphrase)
	recorder := httptest.NewRecorder()
	body := map[string]string{
		"email":      email,
		"passphrase": passphrase,
	}
	sbody, _ := json.Marshal(body)
	userCreateRequest := httptest.NewRequest("POST", fmt.Sprintf("%s/management/user", apiPrefix), bytes.NewReader(sbody))
	userCreateRequest.Header.Add("Content-Type", "application/json")
	userCreateRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, userCreateRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting user create status 200 but %d. Body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
	} else {
		t.Log(pretifyJSON(recorder.Body.String()))
		time.Sleep(200 * time.Millisecond)
		mailer := mgmnt.EmailSender.(*connector.DummyMailSender)
		if mailer.LastSentMail == nil || mailer.LastSentMail.To != email {
			t.Error("Email not sent to ", email)
		} else {
			t.Logf("Email To %s Subject: \"%s\". Body: \n-BOF-\n%s\n-EOF-", email, mailer.LastSentMail.Subject, mailer.LastSentMail.Body)
		}
	}
}

type SimpleUser struct {
	Email     string
	Enabled   bool
	RecID     string
	Suspended bool
}

type SimpleGroup struct {
	RecID     string
	GroupName string
}

type SimpleRole struct {
	RecID    string
	RoleName string
}

func ListGroupsTesting(t *testing.T, accessToken string) []*SimpleGroup {
	t.Log("Testing Listing Group")
	recorder := httptest.NewRecorder()
	userListRequest := httptest.NewRequest("GET", fmt.Sprintf("%s/management/groups?page_no=1&page_size=10&order_by=GROUP_NAME&sort=DESC", apiPrefix), nil)
	userListRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, userListRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting group listing status 200 but %d. body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
		return nil
	}
	t.Log(pretifyJSON(recorder.Body.String()))
	jObj := make(map[string]interface{})
	_ = json.Unmarshal(recorder.Body.Bytes(), &jObj)
	ret := make([]*SimpleGroup, 0)
	usrArr := jObj["data"].(map[string]interface{})["groups"].([]interface{})
	for _, v := range usrArr {
		row := v.(map[string]interface{})
		name := row["group_name"].(string)
		recid := row["rec_id"].(string)
		ret = append(ret, &SimpleGroup{
			GroupName: name,
			RecID:     recid,
		})
	}
	return ret
}

func ListRolesTesting(t *testing.T, accessToken string) []*SimpleRole {
	t.Log("Testing Listing Roles")
	recorder := httptest.NewRecorder()
	userListRequest := httptest.NewRequest("GET", fmt.Sprintf("%s/management/roles?page_no=1&page_size=10&order_by=ROLE_NAME&sort=DESC", apiPrefix), nil)
	userListRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, userListRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting role listing status 200 but %d. body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
		return nil
	}
	t.Log(pretifyJSON(recorder.Body.String()))
	jObj := make(map[string]interface{})
	_ = json.Unmarshal(recorder.Body.Bytes(), &jObj)
	ret := make([]*SimpleRole, 0)
	usrArr := jObj["data"].(map[string]interface{})["roles"].([]interface{})
	for _, v := range usrArr {
		row := v.(map[string]interface{})
		name := row["role_name"].(string)
		recid := row["rec_id"].(string)
		ret = append(ret, &SimpleRole{
			RoleName: name,
			RecID:    recid,
		})
	}
	return ret
}

func ListUsersTesting(t *testing.T, accessToken string) []*SimpleUser {
	t.Log("Testing Listing User")
	recorder := httptest.NewRecorder()
	userListRequest := httptest.NewRequest("GET", fmt.Sprintf("%s/management/users?page_no=1&page_size=10&order_by=EMAIL&sort=DESC", apiPrefix), nil)
	userListRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", accessToken))
	Router.ServeHTTP(recorder, userListRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting user listing status 200 but %d", recorder.Code)
		t.FailNow()
		return nil
	}
	t.Log(pretifyJSON(recorder.Body.String()))
	jObj := make(map[string]interface{})
	_ = json.Unmarshal(recorder.Body.Bytes(), &jObj)
	ret := make([]*SimpleUser, 0)
	usrArr := jObj["data"].(map[string]interface{})["users"].([]interface{})
	for _, v := range usrArr {
		row := v.(map[string]interface{})
		email := row["email"].(string)
		enabled := row["enabled"].(bool)
		recid := row["rec_id"].(string)
		suspended := row["suspended"].(bool)
		ret = append(ret, &SimpleUser{
			Email:     email,
			Enabled:   enabled,
			RecID:     recid,
			Suspended: suspended,
		})
	}
	return ret
}

func HealthCheckTesting(t *testing.T) {
	t.Log("Testing HealthCheck")
	recorder := httptest.NewRecorder()
	healthRequest := httptest.NewRequest("GET", "/health", nil)
	Router.ServeHTTP(recorder, healthRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting healthcheck status 200 but %d", recorder.Code)
		t.FailNow()
	} else {
		t.Log(pretifyJSON(recorder.Body.String()))
	}
}

func DummyAdminLoginTesting(t *testing.T) (string, string) {
	t.Log("Testing Dummy Admin Authentication")
	recorder := httptest.NewRecorder()
	body := map[string]string{
		"email":      "admin@hansip",
		"passphrase": "this must be change in the production",
	}
	sbody, _ := json.Marshal(body)
	authenticationRequest := httptest.NewRequest("POST", fmt.Sprintf("%s/auth/authenticate", apiPrefix), bytes.NewReader(sbody))
	authenticationRequest.Header.Add("Content-Type", "application/json")
	Router.ServeHTTP(recorder, authenticationRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting admin login status 200 but %d", recorder.Code)
		t.FailNow()
		return "", ""
	}
	t.Log(pretifyJSON(recorder.Body.String()))
	ret := make(map[string]interface{})
	err := json.Unmarshal(recorder.Body.Bytes(), &ret)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}
	if _, ok := ret["status"]; ok {
		if ret["status"].(string) != "SUCCESS" {
			t.Errorf("Expecting SUCCESS but %s", ret["status"].(string))
			t.FailNow()
		}
	} else {
		t.Errorf("data not exist")
		t.FailNow()
		return "", ""
	}
	data := ret["data"].(map[string]interface{})
	return data["access_token"].(string), data["refresh_token"].(string)

}

func DummyAdminRefreshTokenTesting(t *testing.T, refreshToken string) string {
	t.Log("Testing Refreshing access token")
	recorder := httptest.NewRecorder()
	refreshRequest := httptest.NewRequest("POST", fmt.Sprintf("%s/auth/refresh", apiPrefix), nil)
	refreshRequest.Header.Add("Authorization", fmt.Sprintf("BEARER %s", refreshToken))
	time.Sleep(2 * time.Second)
	t.Log("sleep 2 second for time drift")
	Router.ServeHTTP(recorder, refreshRequest)
	if recorder.Code != http.StatusOK {
		t.Errorf("expecting admin refresh token status 200 but %d. body %s", recorder.Code, recorder.Body.String())
		t.FailNow()
		return ""
	}
	t.Log(pretifyJSON(recorder.Body.String()))
	ret := make(map[string]interface{})
	json.Unmarshal(recorder.Body.Bytes(), &ret)
	if ret["status"].(string) != "SUCCESS" {
		t.Errorf("Expecting SUCCESS but %s", ret["status"].(string))
	}
	data := ret["data"].(map[string]interface{})
	return data["access_token"].(string)

}

package endpoint

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/hyperjumptech/hansip/api"
	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/connector"
)

var (
	// UserRepo is a user Repository instance
	UserRepo connector.UserRepository
	// GroupRepo is a group repository instance
	GroupRepo connector.GroupRepository
	// RoleRepo is a role repository instance
	RoleRepo connector.RoleRepository
	// UserGroupRepo is a user group repository instance
	UserGroupRepo connector.UserGroupRepository
	// UserRoleRepo is a user role repository instance
	UserRoleRepo connector.UserRoleRepository
	// GroupRoleRepo is a group role repository instance
	GroupRoleRepo connector.GroupRoleRepository
	// EmailSender is email sender instance
	EmailSender connector.EmailSender

	apiPrefix = config.Get("api.path.prefix")

	Endpoints []*Endpoint
)

func init() {

	if len(apiPrefix) == 0 {
		panic("API prefix is not configured. please configure variable 'api.path.prefix' or AAA_API_PATH_PREFIX env variable")
	}
	Endpoints = []*Endpoint{
		{"/docs/**/*", GetMethod, true, nil, api.ServeStatic},
		{"/health", GetMethod, true, nil, HealthCheck},
		{fmt.Sprintf("%s/auth/authenticate", apiPrefix), OptionMethod | PostMethod, true, nil, Authentication},
		{fmt.Sprintf("%s/auth/refresh", apiPrefix), OptionMethod | PostMethod, true, nil, Refresh},
		{fmt.Sprintf("%s/auth/2fa", apiPrefix), OptionMethod | PostMethod, true, nil, TwoFA},
		{fmt.Sprintf("%s/auth/2fatest", apiPrefix), OptionMethod | PostMethod, false, nil, TwoFATest},
		{fmt.Sprintf("%s/auth/authenticate2fa", apiPrefix), OptionMethod | PostMethod, false, nil, Authentication2FA},

		{fmt.Sprintf("%s/management/users", apiPrefix), OptionMethod | GetMethod, false, nil, ListAllUsers},
		{fmt.Sprintf("%s/management/user", apiPrefix), OptionMethod | PostMethod, false, nil, CreateNewUser},
		{fmt.Sprintf("%s/management/user/{userRecId}/passwd", apiPrefix), OptionMethod | PostMethod, false, nil, ChangePassphrase},
		{fmt.Sprintf("%s/management/user/activate", apiPrefix), OptionMethod | PostMethod, true, nil, ActivateUser},
		{fmt.Sprintf("%s/management/user/whoami", apiPrefix), OptionMethod | GetMethod, false, nil, WhoAmI},
		{fmt.Sprintf("%s/management/user/2FAQR", apiPrefix), OptionMethod | GetMethod, false, nil, Show2FAQrCode},
		{fmt.Sprintf("%s/management/user/activate2FA", apiPrefix), OptionMethod | PostMethod, false, nil, Activate2FA},
		{fmt.Sprintf("%s/management/user/{userRecId}", apiPrefix), OptionMethod | GetMethod, false, nil, GetUserDetail},
		{fmt.Sprintf("%s/management/user/{userRecId}", apiPrefix), OptionMethod | PutMethod, false, nil, UpdateUserDetail},
		{fmt.Sprintf("%s/management/user/{userRecId}", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteUser},
		{fmt.Sprintf("%s/management/user/{userRecId}/roles", apiPrefix), OptionMethod | GetMethod, false, nil, ListUserRole},
		{fmt.Sprintf("%s/management/user/{userRecId}/roles", apiPrefix), OptionMethod | PutMethod, false, nil, SetUserRoles},
		{fmt.Sprintf("%s/management/user/{userRecId}/roles", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteUserRoles},
		{fmt.Sprintf("%s/management/user/{userRecId}/all-roles", apiPrefix), OptionMethod | GetMethod, false, nil, ListAllUserRole},
		{fmt.Sprintf("%s/management/user/{userRecId}/role/{roleRecId}", apiPrefix), OptionMethod | PutMethod, false, nil, CreateUserRole},
		{fmt.Sprintf("%s/management/user/{userRecId}/role/{roleRecId}", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteUserRole},
		{fmt.Sprintf("%s/management/user/{userRecId}/groups", apiPrefix), OptionMethod | GetMethod, false, nil, ListUserGroup},
		{fmt.Sprintf("%s/management/user/{userRecId}/groups", apiPrefix), OptionMethod | PutMethod, false, nil, SetUserGroups},
		{fmt.Sprintf("%s/management/user/{userRecId}/groups", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteUserGroups},
		{fmt.Sprintf("%s/management/user/{userRecId}/group/{groupRecId}", apiPrefix), OptionMethod | PutMethod, false, nil, CreateUserGroup},
		{fmt.Sprintf("%s/management/user/{userRecId}/group/{groupRecId}", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteUserGroup},

		{fmt.Sprintf("%s/management/groups", apiPrefix), OptionMethod | GetMethod, false, nil, ListAllGroup},
		{fmt.Sprintf("%s/management/group", apiPrefix), OptionMethod | PostMethod, false, nil, CreateNewGroup},
		{fmt.Sprintf("%s/management/group/{groupRecId}", apiPrefix), OptionMethod | GetMethod, false, nil, GetGroupDetail},
		{fmt.Sprintf("%s/management/group/{groupRecId}", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteGroup},
		{fmt.Sprintf("%s/management/group/{groupRecId}", apiPrefix), OptionMethod | PutMethod, false, nil, UpdateGroup},
		{fmt.Sprintf("%s/management/group/{groupRecId}/users", apiPrefix), OptionMethod | GetMethod, false, nil, ListGroupUser},
		{fmt.Sprintf("%s/management/group/{groupRecId}/users", apiPrefix), OptionMethod | PutMethod, false, nil, SetGroupUsers},
		{fmt.Sprintf("%s/management/group/{groupRecId}/users", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteGroupUsers},
		{fmt.Sprintf("%s/management/group/{groupRecId}/user/{userRecId}", apiPrefix), OptionMethod | PutMethod, false, nil, CreateGroupUser},
		{fmt.Sprintf("%s/management/group/{groupRecId}/user/{userRecId}", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteGroupUser},
		{fmt.Sprintf("%s/management/group/{groupRecId}/roles", apiPrefix), OptionMethod | GetMethod, false, nil, ListGroupRole},
		{fmt.Sprintf("%s/management/group/{groupRecId}/roles", apiPrefix), OptionMethod | PutMethod, false, nil, SetGroupRoles},
		{fmt.Sprintf("%s/management/group/{groupRecId}/roles", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteGroupRoles},
		{fmt.Sprintf("%s/management/group/{groupRecId}/role/{roleRecId}", apiPrefix), OptionMethod | PutMethod, false, nil, CreateGroupRole},
		{fmt.Sprintf("%s/management/group/{groupRecId}/role/{roleRecId}", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteGroupRole},

		{fmt.Sprintf("%s/management/roles", apiPrefix), OptionMethod | GetMethod, false, nil, ListAllRole},
		{fmt.Sprintf("%s/management/role", apiPrefix), OptionMethod | PostMethod, false, nil, CreateRole},
		{fmt.Sprintf("%s/management/role/{roleRecId}", apiPrefix), OptionMethod | GetMethod, false, nil, GetRoleDetail},
		{fmt.Sprintf("%s/management/role/{roleRecId}", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteRole},
		{fmt.Sprintf("%s/management/role/{roleRecId}", apiPrefix), OptionMethod | PutMethod, false, nil, UpdateRole},
		{fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), OptionMethod | GetMethod, false, nil, ListRoleUser},
		{fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), OptionMethod | PutMethod, false, nil, SetRoleUsers},
		{fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteRoleUsers},
		{fmt.Sprintf("%s/management/role/{roleRecId}/user/{userRecId}", apiPrefix), OptionMethod | PutMethod, false, nil, CreateRoleUser},
		{fmt.Sprintf("%s/management/role/{roleRecId}/user/{userRecId}", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteRoleUser},
		{fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), OptionMethod | GetMethod, false, nil, ListRoleGroup},
		{fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), OptionMethod | PutMethod, false, nil, SetRoleGroups},
		{fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteRoleGroups},
		{fmt.Sprintf("%s/management/role/{roleRecId}/group/{groupRecId}", apiPrefix), OptionMethod | PutMethod, false, nil, CreateRoleGroup},
		{fmt.Sprintf("%s/management/role/{roleRecId}/group/{GroupRecID}", apiPrefix), OptionMethod | DeleteMethod, false, nil, DeleteRoleGroup},

		{fmt.Sprintf("%s/recovery/recoverPassphrase", apiPrefix), OptionMethod | PostMethod, true, nil, RecoverPassphrase},
		{fmt.Sprintf("%s/recovery/resetPassphrase", apiPrefix), OptionMethod | PostMethod, true, nil, ResetPassphrase},
	}
}

// InitializeRouter will initialize router to execute management endpoints
func InitializeRouter(router *mux.Router) {
	for _, ep := range Endpoints {
		router.HandleFunc(ep.PathPattern, ep.HandleFunction).Methods(FlagToListMethod(ep.AllowedMethodFlag)...)
	}
}

package endpoint

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/hyperjumptech/hansip/api"
	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/connector"
)

var (
	// TenantRepo is a user Repository instance
	TenantRepo connector.TenantRepository
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

	hansipAdmin := fmt.Sprintf("%s@%s", config.Get("hansip.admin"), config.Get("hansip.domain"))
	anyUser := "*@*"
	adminUser := fmt.Sprintf("%s@*", config.Get("hansip.admin"))

	Endpoints = []*Endpoint{
		{"/docs/**/*", GetMethod, true, nil, api.ServeStatic},
		{"/health", GetMethod, true, nil, HealthCheck},
		{fmt.Sprintf("%s/auth/authenticate", apiPrefix), OptionMethod | PostMethod, true, nil, Authentication},
		{fmt.Sprintf("%s/auth/refresh", apiPrefix), OptionMethod | PostMethod, false, []string{anyUser}, Refresh},
		{fmt.Sprintf("%s/auth/2fa", apiPrefix), OptionMethod | PostMethod, true, nil, TwoFA},
		{fmt.Sprintf("%s/auth/2fatest", apiPrefix), OptionMethod | PostMethod, false, []string{anyUser}, TwoFATest},
		{fmt.Sprintf("%s/auth/authenticate2fa", apiPrefix), OptionMethod | PostMethod, false, nil, Authentication2FA},

		{fmt.Sprintf("%s/management/tenants", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, ListAllTenants},
		{fmt.Sprintf("%s/management/tenant", apiPrefix), OptionMethod | PostMethod, false, []string{hansipAdmin}, CreateNewTenant},
		{fmt.Sprintf("%s/management/tenant/{tenantRecId}", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, GetTenantDetail},
		{fmt.Sprintf("%s/management/tenant/{tenantRecId}", apiPrefix), OptionMethod | PutMethod, false, []string{hansipAdmin}, UpdateTenantDetail},
		{fmt.Sprintf("%s/management/tenant/{tenantRecId}", apiPrefix), OptionMethod | DeleteMethod, false, []string{hansipAdmin}, DeleteTenant},

		{fmt.Sprintf("%s/management/users", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, ListAllUsers},
		{fmt.Sprintf("%s/management/user", apiPrefix), OptionMethod | PostMethod, false, []string{adminUser}, CreateNewUser},
		{fmt.Sprintf("%s/management/user/{userRecId}/passwd", apiPrefix), OptionMethod | PostMethod, false, nil, ChangePassphrase},
		{fmt.Sprintf("%s/management/user/activate", apiPrefix), OptionMethod | PostMethod, true, []string{adminUser}, ActivateUser},
		{fmt.Sprintf("%s/management/user/whoami", apiPrefix), OptionMethod | GetMethod, false, []string{anyUser}, WhoAmI},
		{fmt.Sprintf("%s/management/user/2FAQR", apiPrefix), OptionMethod | GetMethod, false, nil, Show2FAQrCode},
		{fmt.Sprintf("%s/management/user/activate2FA", apiPrefix), OptionMethod | PostMethod, false, nil, Activate2FA},
		{fmt.Sprintf("%s/management/user/{userRecId}", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, GetUserDetail},
		{fmt.Sprintf("%s/management/user/{userRecId}", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, UpdateUserDetail},
		{fmt.Sprintf("%s/management/user/{userRecId}", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteUser},
		{fmt.Sprintf("%s/management/user/{userRecId}/roles", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, ListUserRole},
		{fmt.Sprintf("%s/management/user/{userRecId}/roles", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, SetUserRoles},
		{fmt.Sprintf("%s/management/user/{userRecId}/roles", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteUserRoles},
		{fmt.Sprintf("%s/management/user/{userRecId}/all-roles", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, ListAllUserRole},
		{fmt.Sprintf("%s/management/user/{userRecId}/role/{roleRecId}", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, CreateUserRole},
		{fmt.Sprintf("%s/management/user/{userRecId}/role/{roleRecId}", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteUserRole},
		{fmt.Sprintf("%s/management/user/{userRecId}/groups", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, ListUserGroup},
		{fmt.Sprintf("%s/management/user/{userRecId}/groups", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, SetUserGroups},
		{fmt.Sprintf("%s/management/user/{userRecId}/groups", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteUserGroups},
		{fmt.Sprintf("%s/management/user/{userRecId}/group/{groupRecId}", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, CreateUserGroup},
		{fmt.Sprintf("%s/management/user/{userRecId}/group/{groupRecId}", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteUserGroup},

		{fmt.Sprintf("%s/management/tenant/{tenantRecId}/groups", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, ListAllGroup},
		{fmt.Sprintf("%s/management/group", apiPrefix), OptionMethod | PostMethod, false, []string{adminUser}, CreateNewGroup},
		{fmt.Sprintf("%s/management/group/{groupRecId}", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, GetGroupDetail},
		{fmt.Sprintf("%s/management/group/{groupRecId}", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteGroup},
		{fmt.Sprintf("%s/management/group/{groupRecId}", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, UpdateGroup},
		{fmt.Sprintf("%s/management/group/{groupRecId}/users", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, ListGroupUser},
		{fmt.Sprintf("%s/management/group/{groupRecId}/users", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, SetGroupUsers},
		{fmt.Sprintf("%s/management/group/{groupRecId}/users", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteGroupUsers},
		{fmt.Sprintf("%s/management/group/{groupRecId}/user/{userRecId}", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, CreateGroupUser},
		{fmt.Sprintf("%s/management/group/{groupRecId}/user/{userRecId}", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteGroupUser},
		{fmt.Sprintf("%s/management/group/{groupRecId}/roles", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, ListGroupRole},
		{fmt.Sprintf("%s/management/group/{groupRecId}/roles", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, SetGroupRoles},
		{fmt.Sprintf("%s/management/group/{groupRecId}/roles", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteGroupRoles},
		{fmt.Sprintf("%s/management/group/{groupRecId}/role/{roleRecId}", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, CreateGroupRole},
		{fmt.Sprintf("%s/management/group/{groupRecId}/role/{roleRecId}", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteGroupRole},

		{fmt.Sprintf("%s/management/tenant/{tenantRecId}/roles", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, ListAllRole},
		{fmt.Sprintf("%s/management/role", apiPrefix), OptionMethod | PostMethod, false, []string{adminUser}, CreateRole},
		{fmt.Sprintf("%s/management/role/{roleRecId}", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, GetRoleDetail},
		{fmt.Sprintf("%s/management/role/{roleRecId}", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteRole},
		{fmt.Sprintf("%s/management/role/{roleRecId}", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, UpdateRole},
		{fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, ListRoleUser},
		{fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, SetRoleUsers},
		{fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteRoleUsers},
		{fmt.Sprintf("%s/management/role/{roleRecId}/user/{userRecId}", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, CreateRoleUser},
		{fmt.Sprintf("%s/management/role/{roleRecId}/user/{userRecId}", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteRoleUser},
		{fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), OptionMethod | GetMethod, false, []string{adminUser}, ListRoleGroup},
		{fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, SetRoleGroups},
		{fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteRoleGroups},
		{fmt.Sprintf("%s/management/role/{roleRecId}/group/{groupRecId}", apiPrefix), OptionMethod | PutMethod, false, []string{adminUser}, CreateRoleGroup},
		{fmt.Sprintf("%s/management/role/{roleRecId}/group/{GroupRecID}", apiPrefix), OptionMethod | DeleteMethod, false, []string{adminUser}, DeleteRoleGroup},

		{fmt.Sprintf("%s/recovery/recoverPassphrase", apiPrefix), OptionMethod | PostMethod, true, nil, RecoverPassphrase},
		{fmt.Sprintf("%s/recovery/resetPassphrase", apiPrefix), OptionMethod | PostMethod, true, nil, ResetPassphrase},
	}
}

// InitializeRouter will initialize router to execute management endpoints
func InitializeRouter(router *mux.Router) {
	for path, _ := range api.StaticResources {
		router.HandleFunc(path, api.ServeStatic).Methods("GET")
	}
	for _, ep := range Endpoints {
		router.HandleFunc(ep.PathPattern, ep.HandleFunction).Methods(FlagToListMethod(ep.AllowedMethodFlag)...)
	}
}

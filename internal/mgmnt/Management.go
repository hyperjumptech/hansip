package mgmnt

import (
	"fmt"
	"github.com/gorilla/mux"
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
)

// InitializeRouter will initialize router to execute management endpoints
func InitializeRouter(router *mux.Router) {
	if len(apiPrefix) == 0 {
		panic("API prefix is not configured. please configure variable 'api.path.prefix' or AAA_API_PATH_PREFIX env variable")
	}
	router.HandleFunc(fmt.Sprintf("%s/management/users", apiPrefix), ListAllUsers).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/user", apiPrefix), CreateNewUser).Methods("OPTIONS", "POST")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}/passwd", apiPrefix), ChangePassphrase).Methods("OPTIONS", "POST")
	router.HandleFunc(fmt.Sprintf("%s/management/user/activate", apiPrefix), ActivateUser).Methods("OPTIONS", "POST")
	router.HandleFunc(fmt.Sprintf("%s/management/user/whoami", apiPrefix), WhoAmI).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/user/2FAQR", apiPrefix), Show2FAQrCode).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/user/activate2FA", apiPrefix), Activate2FA).Methods("OPTIONS", "POST")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}", apiPrefix), GetUserDetail).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}", apiPrefix), UpdateUserDetail).Methods("PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}", apiPrefix), DeleteUser).Methods("DELETE")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}/roles", apiPrefix), ListUserRole).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}/roles", apiPrefix), SetUserRoles).Methods("PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}/roles", apiPrefix), DeleteUserRoles).Methods("DELETE")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}/all-roles", apiPrefix), ListAllUserRole).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}/role/{roleRecId}", apiPrefix), CreateUserRole).Methods("OPTIONS", "PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}/role/{roleRecId}", apiPrefix), DeleteUserRole).Methods("DELETE")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}/groups", apiPrefix), ListUserGroup).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}/groups", apiPrefix), SetUserGroups).Methods("PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}/groups", apiPrefix), DeleteUserGroups).Methods("DELETE")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}/group/{groupRecId}", apiPrefix), CreateUserGroup).Methods("OPTIONS", "PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/user/{userRecId}/group/{groupRecId}", apiPrefix), DeleteUserGroup).Methods("DELETE")

	router.HandleFunc(fmt.Sprintf("%s/management/groups", apiPrefix), ListAllGroup).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/group", apiPrefix), CreateNewGroup).Methods("OPTIONS", "POST")
	router.HandleFunc(fmt.Sprintf("%s/management/group/{groupRecId}", apiPrefix), GetGroupDetail).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/group/{groupRecId}", apiPrefix), DeleteGroup).Methods("DELETE")
	router.HandleFunc(fmt.Sprintf("%s/management/group/{groupRecId}", apiPrefix), UpdateGroup).Methods("PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/group/{groupRecId}/users", apiPrefix), ListGroupUser).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/group/{groupRecId}/users", apiPrefix), SetGroupUsers).Methods("PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/group/{groupRecId}/users", apiPrefix), DeleteGroupUsers).Methods("DELETE")
	router.HandleFunc(fmt.Sprintf("%s/management/group/{groupRecId}/user/{userRecId}", apiPrefix), CreateGroupUser).Methods("OPTIONS", "PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/group/{groupRecId}/user/{userRecId}", apiPrefix), DeleteGroupUser).Methods("DELETE")
	router.HandleFunc(fmt.Sprintf("%s/management/group/{groupRecId}/roles", apiPrefix), ListGroupRole).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/group/{groupRecId}/roles", apiPrefix), SetGroupRoles).Methods("PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/group/{groupRecId}/roles", apiPrefix), DeleteGroupRoles).Methods("DELETE")
	router.HandleFunc(fmt.Sprintf("%s/management/group/{groupRecId}/role/{roleRecId}", apiPrefix), CreateGroupRole).Methods("OPTIONS", "PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/group/{groupRecId}/role/{roleRecId}", apiPrefix), DeleteGroupRole).Methods("DELETE")

	router.HandleFunc(fmt.Sprintf("%s/management/roles", apiPrefix), ListAllRole).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/role", apiPrefix), CreateRole).Methods("OPTIONS", "POST")
	router.HandleFunc(fmt.Sprintf("%s/management/role/{roleRecId}", apiPrefix), GetRoleDetail).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/role/{roleRecId}", apiPrefix), DeleteRole).Methods("DELETE")
	router.HandleFunc(fmt.Sprintf("%s/management/role/{roleRecId}", apiPrefix), UpdateRole).Methods("PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), ListRoleUser).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), SetRoleUsers).Methods("PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/role/{roleRecId}/users", apiPrefix), DeleteRoleUsers).Methods("DELETE")
	router.HandleFunc(fmt.Sprintf("%s/management/role/{roleRecId}/user/{userRecId}", apiPrefix), CreateRoleUser).Methods("OPTIONS", "PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/role/{roleRecId}/user/{userRecId}", apiPrefix), DeleteRoleUser).Methods("DELETE")
	router.HandleFunc(fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), ListRoleGroup).Methods("OPTIONS", "GET")
	router.HandleFunc(fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), SetRoleGroups).Methods("PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/role/{roleRecId}/groups", apiPrefix), DeleteRoleGroups).Methods("DELETE")
	router.HandleFunc(fmt.Sprintf("%s/management/role/{roleRecId}/group/{groupRecId}", apiPrefix), CreateRoleGroup).Methods("OPTIONS", "PUT")
	router.HandleFunc(fmt.Sprintf("%s/management/role/{roleRecId}/group/{GroupRecID}", apiPrefix), DeleteRoleGroup).Methods("DELETE")

	router.HandleFunc(fmt.Sprintf("%s/recovery/recoverPassphrase", apiPrefix), RecoverPassphrase).Methods("OPTIONS", "POST")
	router.HandleFunc(fmt.Sprintf("%s/recovery/resetPassphrase", apiPrefix), ResetPassphrase).Methods("OPTIONS", "POST")
}

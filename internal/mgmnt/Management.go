package mgmnt

import (
	"github.com/gorilla/mux"
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
)

// InitializeRouter will initialize router to execute management endpoints
func InitializeRouter(router *mux.Router) {
	router.HandleFunc("/api/v1/management/users", ListAllUsers).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/user", CreateNewUser).Methods("OPTIONS", "POST")
	router.HandleFunc("/api/v1/management/user/{userRecId}/passwd", ChangePassphrase).Methods("OPTIONS", "POST")
	router.HandleFunc("/api/v1/management/user/activate", ActivateUser).Methods("OPTIONS", "POST")
	router.HandleFunc("/api/v1/management/user/whoami", WhoAmI).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/user/2FAQR", Show2FAQrCode).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/user/activate2FA", Activate2FA).Methods("OPTIONS", "POST")
	router.HandleFunc("/api/v1/management/user/{userRecId}", GetUserDetail).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/user/{userRecId}", UpdateUserDetail).Methods("PUT")
	router.HandleFunc("/api/v1/management/user/{userRecId}", DeleteUser).Methods("DELETE")
	router.HandleFunc("/api/v1/management/user/{userRecId}/roles", ListUserRole).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/user/{userRecId}/roles", SetUserRoles).Methods("PUT")
	router.HandleFunc("/api/v1/management/user/{userRecId}/roles", DeleteUserRoles).Methods("DELETE")
	router.HandleFunc("/api/v1/management/user/{userRecId}/all-roles", ListAllUserRole).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/user/{userRecId}/role/{roleRecId}", CreateUserRole).Methods("OPTIONS", "PUT")
	router.HandleFunc("/api/v1/management/user/{userRecId}/role/{roleRecId}", DeleteUserRole).Methods("DELETE")
	router.HandleFunc("/api/v1/management/user/{userRecId}/groups", ListUserGroup).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/user/{userRecId}/groups", SetUserGroups).Methods("PUT")
	router.HandleFunc("/api/v1/management/user/{userRecId}/groups", DeleteUserGroups).Methods("DELETE")
	router.HandleFunc("/api/v1/management/user/{userRecId}/group/{groupRecId}", CreateUserGroup).Methods("OPTIONS", "PUT")
	router.HandleFunc("/api/v1/management/user/{userRecId}/group/{groupRecId}", DeleteUserGroup).Methods("DELETE")

	router.HandleFunc("/api/v1/management/groups", ListAllGroup).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/group", CreateNewGroup).Methods("OPTIONS", "POST")
	router.HandleFunc("/api/v1/management/group/{groupRecId}", GetGroupDetail).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/group/{groupRecId}", DeleteGroup).Methods("DELETE")
	router.HandleFunc("/api/v1/management/group/{groupRecId}", UpdateGroup).Methods("PUT")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/users", ListGroupUser).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/users", SetGroupUsers).Methods("PUT")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/users", DeleteGroupUsers).Methods("DELETE")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/user/{userRecId}", CreateGroupUser).Methods("OPTIONS", "PUT")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/user/{userRecId}", DeleteGroupUser).Methods("DELETE")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/roles", ListGroupRole).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/roles", SetGroupRoles).Methods("PUT")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/roles", DeleteGroupRoles).Methods("DELETE")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/role/{roleRecId}", CreateGroupRole).Methods("OPTIONS", "PUT")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/role/{roleRecId}", DeleteGroupRole).Methods("DELETE")

	router.HandleFunc("/api/v1/management/roles", ListAllRole).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/role", CreateRole).Methods("OPTIONS", "POST")
	router.HandleFunc("/api/v1/management/role/{roleRecId}", GetRoleDetail).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/role/{roleRecId}", DeleteRole).Methods("DELETE")
	router.HandleFunc("/api/v1/management/role/{roleRecId}", UpdateRole).Methods("PUT")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/users", ListRoleUser).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/users", SetRoleUsers).Methods("PUT")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/users", DeleteRoleUsers).Methods("DELETE")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/user/{userRecId}", CreateRoleUser).Methods("OPTIONS", "PUT")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/user/{userRecId}", DeleteRoleUser).Methods("DELETE")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/groups", ListRoleGroup).Methods("OPTIONS", "GET")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/groups", SetRoleGroups).Methods("PUT")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/groups", DeleteRoleGroups).Methods("DELETE")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/group/{groupRecId}", CreateRoleGroup).Methods("OPTIONS", "PUT")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/group/{GroupRecID}", DeleteRoleGroup).Methods("DELETE")

	router.HandleFunc("/api/v1/recovery/recoverPassphrase", RecoverPassphrase).Methods("OPTIONS", "POST")
	router.HandleFunc("/api/v1/recovery/resetPassphrase", ResetPassphrase).Methods("OPTIONS", "POST")
}

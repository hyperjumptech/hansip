package mgmnt

import (
	"github.com/gorilla/mux"
	"github.com/hyperjumptech/hansip/internal/connector"
)

var (
	UserRepo      connector.UserRepository
	GroupRepo     connector.GroupRepository
	RoleRepo      connector.RoleRepository
	UserGroupRepo connector.UserGroupRepository
	UserRoleRepo  connector.UserRoleRepository
	GroupRoleRepo connector.GroupRoleRepository
	EmailSender   connector.EmailSender
)

// InitializeRouter will initialize router to execute management endpoints
func InitializeRouter(router *mux.Router) {
	router.HandleFunc("/api/v1/management/users", ListAllUsers).Methods("GET")
	router.HandleFunc("/api/v1/management/user", CreateNewUser).Methods("POST")
	router.HandleFunc("/api/v1/management/user/{userRecId}/passwd", ChangePassphrase).Methods("POST")
	router.HandleFunc("/api/v1/management/user/activate", ActivateUser).Methods("POST")
	router.HandleFunc("/api/v1/management/user/{userRecId}", GetUserDetail).Methods("GET")
	router.HandleFunc("/api/v1/management/user/{userRecId}", UpdateUserDetail).Methods("PUT")
	router.HandleFunc("/api/v1/management/user/{userRecId}", DeleteUser).Methods("DELETE")
	router.HandleFunc("/api/v1/management/user/{userRecId}/roles", ListUserRole).Methods("GET")
	router.HandleFunc("/api/v1/management/user/{userRecId}/all-roles", ListAllUserRole).Methods("GET")
	router.HandleFunc("/api/v1/management/user/{userRecId}/role/{roleRecId}", CreateUserRole).Methods("PUT")
	router.HandleFunc("/api/v1/management/user/{userRecId}/role/{roleRecId}", DeleteUserRole).Methods("DELETE")
	router.HandleFunc("/api/v1/management/user/{userRecId}/groups", ListUserGroup).Methods("GET")
	router.HandleFunc("/api/v1/management/user/{userRecId}/group/{groupRecId}", CreateUserGroup).Methods("PUT")
	router.HandleFunc("/api/v1/management/user/{userRecId}/group/{groupRecId}", DeleteUserGroup).Methods("DELETE")
	router.HandleFunc("/management/user/{userRecId}/2FAQR", Show2FAQrCode).Methods("GET")

	router.HandleFunc("/api/v1/management/groups", ListAllGroup).Methods("GET")
	router.HandleFunc("/api/v1/management/group", CreateNewGroup).Methods("POST")
	router.HandleFunc("/api/v1/management/group/{groupRecId}", GetGroupDetail).Methods("GET")
	router.HandleFunc("/api/v1/management/group/{groupRecId}", DeleteGroup).Methods("DELETE")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/users", ListGroupUser).Methods("GET")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/user/{userRecId}", CreateGroupUser).Methods("PUT")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/user/{userRecId}", DeleteGroupUser).Methods("DELETE")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/roles", ListGroupRole).Methods("GET")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/role/{roleRecId}", CreateGroupRole).Methods("PUT")
	router.HandleFunc("/api/v1/management/group/{groupRecId}/role/{roleRecId}", DeleteGroupRole).Methods("DELETE")

	router.HandleFunc("/api/v1/management/roles", ListAllRole).Methods("GET")
	router.HandleFunc("/api/v1/management/role", CreateRole).Methods("POST")
	router.HandleFunc("/api/v1/management/role/{roleRecId}", GetRoleDetail).Methods("GET")
	router.HandleFunc("/api/v1/management/role/{roleRecId}", DeleteRole).Methods("DELETE")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/users", ListRoleUser).Methods("GET")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/user/{userRecId}", CreateRoleUser).Methods("PUT")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/user/{userRecId}", DeleteRoleUser).Methods("DELETE")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/groups", ListRoleGroup).Methods("GET")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/group/{groupRecId}", CreateRoleGroup).Methods("PUT")
	router.HandleFunc("/api/v1/management/role/{roleRecId}/group/{GroupRecId}", DeleteRoleGroup).Methods("DELETE")

	router.HandleFunc("/api/v1/recovery/recoverPassphrase", RecoverPassphrase).Methods("GET")
	router.HandleFunc("/api/v1/recovery/resetPassphrase", ResetPassphrase).Methods("POST")
}

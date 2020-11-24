package connector

import (
	"context"
	"github.com/hyperjumptech/hansip/pkg/helper"
	"time"
)

// DBUtil is interface to help working with table create and drop
type DBUtil interface {
	// DropAllTables will drop all existing table
	DropAllTables(ctx context.Context) error

	// CreateAllTable will create tables needed for the Apps if not exist
	CreateAllTable(ctx context.Context) error
}

// TenantRepository manage tenant table
type TenantRepository interface {
	// GetTenantByDomain return a tenant record
	GetTenantByDomain(ctx context.Context, tenantDomain string) (*Tenant, error)

	// GetTenantByRecID return a tenant record
	GetTenantByRecID(ctx context.Context, recID string) (*Tenant, error)

	// CreateTenantRecord Create new tenant
	CreateTenantRecord(ctx context.Context, tenantName, tenantDomain, description string) (*Tenant, error)

	// DeleteTenant removes a tenant entity from table
	DeleteTenant(ctx context.Context, tenant *Tenant) error

	// SaveOrUpdate a tenant entity into table tenant
	SaveOrUpdateTenant(ctx context.Context, tenant *Tenant) error

	// ListTenant from database with pagination
	ListTenant(ctx context.Context, request *helper.PageRequest) ([]*Tenant, *helper.Page, error)
}

// UserRepository manage User table
type UserRepository interface {
	// GetUserByRecID return a user record
	GetUserByRecID(ctx context.Context, recID string) (*User, error)

	// CreateUserRecord in the User table
	CreateUserRecord(ctx context.Context, email, passphrase string) (*User, error)

	// GetUserByEmail return a user record
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// GetUserBy2FAToken return a user record
	GetUserBy2FAToken(ctx context.Context, token string) (*User, error)

	// GetUserByRecoveryToken return user record
	GetUserByRecoveryToken(ctx context.Context, token string) (*User, error)

	// DeleteUser removes a user entity from table
	DeleteUser(ctx context.Context, user *User) error

	// SaveOrUpdate a user entity into table user
	SaveOrUpdate(ctx context.Context, user *User) error

	// ListUser from database with pagination
	ListUser(ctx context.Context, request *helper.PageRequest) ([]*User, *helper.Page, error)

	// Count all user entity in table
	Count(ctx context.Context) (int, error)

	// ListAllUserRoles will list all roles owned by a particular user
	ListAllUserRoles(ctx context.Context, user *User, request *helper.PageRequest) ([]*Role, *helper.Page, error)

	// GetTOTPRecoveryCodes retrieves all valid/not used TOTP recovery codes.
	GetTOTPRecoveryCodes(ctx context.Context, user *User) ([]string, error)

	// RecreateTOTPRecoveryCodes recreates 16 new recovery codes.
	RecreateTOTPRecoveryCodes(ctx context.Context, user *User) ([]string, error)

	// MarkTOTPRecoveryCodeUsed will mark the specific recovery code as used and thus can not be used anymore.
	MarkTOTPRecoveryCodeUsed(ctx context.Context, user *User, code string) error
}

// GroupRepository manage Group table
type GroupRepository interface {
	// GetGroupByRecID return a group record
	GetGroupByRecID(ctx context.Context, recID string) (*Group, error)

	// GetGroupByName return a group record
	GetGroupByName(ctx context.Context, groupName, groupDomain string) (*Group, error)

	// CreateGroup into the Group table
	CreateGroup(ctx context.Context, groupName, groupDomain, description string) (*Group, error)

	// ListGroup from the Group table
	ListGroups(ctx context.Context, tenant *Tenant, request *helper.PageRequest) ([]*Group, *helper.Page, error)

	// DeleteGroup from Group table
	DeleteGroup(ctx context.Context, group *Group) error

	// CreateUserGroup into Group table
	SaveOrUpdateGroup(ctx context.Context, group *Group) error
}

// UserGroupRepository manage UserGroup table
type UserGroupRepository interface {
	// GetUserGroup returns existing UserGroup
	GetUserGroup(ctx context.Context, user *User, group *Group) (*UserGroup, error)

	// CreateUserGroup into UserGroup table
	CreateUserGroup(ctx context.Context, user *User, group *Group) (*UserGroup, error)

	// ListUserGroupByEmail from the UserGroup table
	ListUserGroupByUser(ctx context.Context, user *User, request *helper.PageRequest) ([]*Group, *helper.Page, error)

	// ListUserGroupByGroupName from the UserGroup table
	ListUserGroupByGroup(ctx context.Context, group *Group, request *helper.PageRequest) ([]*User, *helper.Page, error)

	// DeleteUserGroup from the UserGroup table
	DeleteUserGroup(ctx context.Context, userGroup *UserGroup) error

	// DeleteUserGroupByEmail from the UserGroup table
	DeleteUserGroupByUser(ctx context.Context, user *User) error

	// DeleteUserGroupByGroupName from the UserGroup table
	DeleteUserGroupByGroup(ctx context.Context, group *Group) error
}

// UserRoleRepository manage UserRole table
type UserRoleRepository interface {
	// GetUserRole returns existing user role
	GetUserRole(ctx context.Context, user *User, role *Role) (*UserRole, error)

	// CreateUserRole into UserRole table
	CreateUserRole(ctx context.Context, user *User, role *Role) (*UserRole, error)

	// ListUserRoleByEmail from UserRole table
	ListUserRoleByUser(ctx context.Context, user *User, request *helper.PageRequest) ([]*Role, *helper.Page, error)

	// ListUserRoleByRoleName from UserRole table
	ListUserRoleByRole(ctx context.Context, role *Role, request *helper.PageRequest) ([]*User, *helper.Page, error)

	// DeleteUserRole from UserRole table
	DeleteUserRole(ctx context.Context, userRole *UserRole) error

	// DeleteUserRoleByEmail from UserRole table
	DeleteUserRoleByUser(ctx context.Context, user *User) error

	// DeleteUserRoleByRoleName from UserRole table
	DeleteUserRoleByRole(ctx context.Context, role *Role) error
}

// GroupRoleRepository manage GroupRole table
type GroupRoleRepository interface {

	// GetGroupRole return existing group role
	GetGroupRole(ctx context.Context, group *Group, role *Role) (*GroupRole, error)

	// CreateGroupRole into GroupRole table
	CreateGroupRole(ctx context.Context, group *Group, role *Role) (*GroupRole, error)

	// ListGroupRoleByGroupName from GroupRole table
	ListGroupRoleByGroup(ctx context.Context, group *Group, request *helper.PageRequest) ([]*Role, *helper.Page, error)

	// ListGroupRoleByRoleName from GroupRole table
	ListGroupRoleByRole(ctx context.Context, role *Role, request *helper.PageRequest) ([]*Group, *helper.Page, error)

	// DeleteGroupRole from GroupRole table
	DeleteGroupRole(ctx context.Context, groupRole *GroupRole) error

	// DeleteGroupRoleByEmail from GroupRole table
	DeleteGroupRoleByGroup(ctx context.Context, group *Group) error

	// DeleteGroupRoleByRoleName from GroupRole table
	DeleteGroupRoleByRole(ctx context.Context, role *Role) error
}

// RoleRepository manage Role table
type RoleRepository interface {
	// GetRoleByRecID return an existing role
	GetRoleByRecID(ctx context.Context, recID string) (*Role, error)

	// GetRoleByName return a role record
	GetRoleByName(ctx context.Context, roleName, roleDomain string) (*Role, error)

	// CreateRole into Role table
	CreateRole(ctx context.Context, roleName, roleDomain, description string) (*Role, error)

	// ListRoles from Role table
	ListRoles(ctx context.Context, tenant *Tenant, request *helper.PageRequest) ([]*Role, *helper.Page, error)

	// DeleteRole from Role table
	DeleteRole(ctx context.Context, role *Role) error

	// SaveOrUpdateRole into Role table
	SaveOrUpdateRole(ctx context.Context, role *Role) error
}

// Tenant record entity
type Tenant struct {
	// RecID. Primary key
	RecID string `json:"rec_id"`

	// TenantName is the tenant name
	Name string `json:"name"`

	// Description of the group
	Description string `json:"description"`

	// TenantAdminRole role needed to manage users under this tenant
	Domain string `json:"domain"`
}

// User record entity
type User struct {
	// RecID. Primary key
	RecID string `json:"rec_id"`

	// Email address. unique
	Email string `json:"email"`

	// HashedPassphrase bcrypt hashed passphrase
	HashedPassphrase string `json:"hashed_passphrase"`

	// Enabled status of the user
	Enabled bool `json:"enabled"`

	// Suspended status of the user
	Suspended bool `json:"suspended"`

	// LastSeen time of the user
	LastSeen time.Time `json:"last_seen"`

	// LastLogin time of the user
	LastLogin time.Time `json:"last_login"`

	// FailCount of login attempt
	FailCount int `json:"fail_count"`

	// ActivationCode for activating/enabling the user
	ActivationCode string `json:"activation_code"`

	// ActivationDate time of the user
	ActivationDate time.Time `json:"activation_date"`

	// UserTotpSecretKey for 2 factor authentication
	UserTotpSecretKey string `json:"user_totp_secret_key"`

	// Enable2FactorAuth used for enabling 2 factor auth
	Enable2FactorAuth bool `json:"enable_2_factor_auth"`

	// Token2FA used to authenticate back using 2FA
	Token2FA string `json:"token_2_fa"`

	// RecoveryCode used to recover lost passphrase
	RecoveryCode string `json:"recovery_code"`

	// The tenant owner
	TenantRecId string `json:"tenant_rec_id"`
}

// TOTPRecoveryCode used to login the user if the user lost his TOTP code due to lost of 2FE token device.
type TOTPRecoveryCode struct {
	// RecID. Primary Key
	RecID string `json:"rec_id"`

	// The 8 digit key used once code. No dash separator. Only upper A-Z and 0-9
	Code string `json:"code"`

	// The used flag. If true, this token can not be used anymore.
	Used bool `json:"used"`

	// The owner of this code.
	UserRecID string `json:"user_rec_id"`
}

// Group record entity
type Group struct {
	// RecID. Primary key
	RecID string `json:"rec_id"`

	// GroupName of the group, Primary Key
	GroupName string `json:"group_name"`

	// GroupDomain domain of the group, Primary Key
	GroupDomain string `json:"group_domain"`

	// Description of the group
	Description string `json:"description"`

	// The tenant owner
	TenantRecId string `json:"tenant_rec_id"`
}

// UserGroup record entity
type UserGroup struct {
	// Email composite key to User
	UserRecID string `json:"user_rec_id"`

	// GroupName composite key to Group
	GroupRecID string `json:"group_rec_id"`
}

// UserRole record entity
type UserRole struct {
	// Email composite key to User
	UserRecID string `json:"user_rec_id"`

	// RoleName composite key to Role
	RoleRecID string `json:"role_rec_id"`
}

// GroupRole record entity
type GroupRole struct {
	// GroupName composite key to Group
	GroupRecID string `json:"group_rec_id"`

	// RoleName composite key to Role
	RoleRecID string `json:"role_rec_id"`
}

// Role record entity
type Role struct {
	// RecID. Primary key
	RecID string `json:"rec_id"`

	// RoleName of the role, Unique
	RoleName string `json:"role_name"`

	// RoleDomain domain of the role, Unique
	RoleDomain string `json:"role_domain"`

	// Description of the role
	Description string `json:"description"`

	// The tenant owner
	TenantRecId string `json:"tenant_rec_id"`
}

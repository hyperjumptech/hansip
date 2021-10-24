package connector

import (
	"context"
	"fmt"
	"github.com/hyperjumptech/hansip/pkg/helper"
	log "github.com/sirupsen/logrus"
	"sort"
)

type RevocationInMemTable []*Revocation

func (rimt RevocationInMemTable) Clear() {
	rimt = make(RevocationInMemTable, 0)
}
func (rimt RevocationInMemTable) Delete(index int) {
	rimt = append(rimt[:index], rimt[index+1:]...)
}

type TenantInMemTable map[string]*Tenant

func (timt TenantInMemTable) Clear() {
	timt = make(TenantInMemTable)
}

type UserInMemTable map[string]*User

func (uimt UserInMemTable) Clear() {
	uimt = make(UserInMemTable)
}

type TOTPRecoveryCodeInMemTable map[string]*TOTPRecoveryCode

func (trcimt TOTPRecoveryCodeInMemTable) Clear() {
	trcimt = make(TOTPRecoveryCodeInMemTable, 0)
}

type GroupInMemTable map[string]*Group

func (gimt GroupInMemTable) Clear() {
	gimt = make(GroupInMemTable)
}

type UserGroupInMemTable []*UserGroup

func (ugimt UserGroupInMemTable) Clear() {
	ugimt = make(UserGroupInMemTable, 0)
}
func (ugimt UserGroupInMemTable) Delete(index int) {
	ugimt = append(ugimt[:index], ugimt[index+1:]...)
}
func (ugimt UserGroupInMemTable) DeleteByUser(userRowID string) {
	todel := make([]int, 0)
	for i, row := range ugimt {
		if row.UserRecID == userRowID {
			todel = append(todel, i)
		}
	}
	if len(todel) > 0 {
		sort.Slice(todel, func(i, j int) bool {
			return todel[i] > todel[j]
		})
		for _, idel := range todel {
			ugimt.Delete(idel)
		}
	}
}
func (ugimt UserGroupInMemTable) DeleteByGroup(groupRowID string) {
	todel := make([]int, 0)
	for i, row := range ugimt {
		if row.GroupRecID == groupRowID {
			todel = append(todel, i)
		}
	}
	if len(todel) > 0 {
		sort.Slice(todel, func(i, j int) bool {
			return todel[i] > todel[j]
		})
		for _, idel := range todel {
			ugimt.Delete(idel)
		}
	}
}

type UserRoleInMemTable []*UserRole

func (urimt UserRoleInMemTable) Clear() {
	urimt = make(UserRoleInMemTable, 0)
}
func (urimt UserRoleInMemTable) Delete(index int) {
	urimt = append(urimt[:index], urimt[index+1:]...)
}
func (urimt UserRoleInMemTable) DeleteByUser(userRowID string) {
	todel := make([]int, 0)
	for i, row := range urimt {
		if row.UserRecID == userRowID {
			todel = append(todel, i)
		}
	}
	if len(todel) > 0 {
		sort.Slice(todel, func(i, j int) bool {
			return todel[i] > todel[j]
		})
		for _, idel := range todel {
			urimt.Delete(idel)
		}
	}
}
func (urimt UserRoleInMemTable) DeleteByRole(roleRowID string) {
	todel := make([]int, 0)
	for i, row := range urimt {
		if row.RoleRecID == roleRowID {
			todel = append(todel, i)
		}
	}
	if len(todel) > 0 {
		sort.Slice(todel, func(i, j int) bool {
			return todel[i] > todel[j]
		})
		for _, idel := range todel {
			urimt.Delete(idel)
		}
	}
}

type GroupRoleInMemTable []*GroupRole

func (grimt GroupRoleInMemTable) Clear() {
	grimt = make(GroupRoleInMemTable, 0)
}
func (grimt GroupRoleInMemTable) Delete(index int) {
	grimt = append(grimt[:index], grimt[index+1:]...)
}
func (grimt GroupRoleInMemTable) DeleteByRole(roleRowID string) {
	todel := make([]int, 0)
	for i, row := range grimt {
		if row.RoleRecID == roleRowID {
			todel = append(todel, i)
		}
	}
	if len(todel) > 0 {
		sort.Slice(todel, func(i, j int) bool {
			return todel[i] > todel[j]
		})
		for _, idel := range todel {
			grimt.Delete(idel)
		}
	}
}
func (grimt GroupRoleInMemTable) DeleteByGroup(groupRowID string) {
	todel := make([]int, 0)
	for i, row := range grimt {
		if row.GroupRecID == groupRowID {
			todel = append(todel, i)
		}
	}
	if len(todel) > 0 {
		sort.Slice(todel, func(i, j int) bool {
			return todel[i] > todel[j]
		})
		for _, idel := range todel {
			grimt.Delete(idel)
		}
	}
}

type RoleInMemTable map[string]*Role

func (rimt RoleInMemTable) Clear() {
	rimt = make(RoleInMemTable)
}

func NewInMemoryDB() *InMemoryDB {
	return &InMemoryDB{
		tenantTable:       make(TenantInMemTable),
		userTable:         make(UserInMemTable),
		groupTable:        make(GroupInMemTable),
		roleTable:         make(RoleInMemTable),
		userGroupTable:    make(UserGroupInMemTable, 0),
		userRoleTable:     make(UserRoleInMemTable, 0),
		groupRoleTable:    make(GroupRoleInMemTable, 0),
		revocationTable:   make(RevocationInMemTable, 0),
		totpRecoveryTable: make(TOTPRecoveryCodeInMemTable),
	}
}

type InMemoryDB struct {
	tenantTable       TenantInMemTable
	userTable         UserInMemTable
	groupTable        GroupInMemTable
	roleTable         RoleInMemTable
	userGroupTable    UserGroupInMemTable
	userRoleTable     UserRoleInMemTable
	groupRoleTable    GroupRoleInMemTable
	revocationTable   RevocationInMemTable
	totpRecoveryTable TOTPRecoveryCodeInMemTable
}

// DropAllTables will drop all existing table
func (idb *InMemoryDB) DropAllTables(ctx context.Context) error {
	idb.tenantTable.Clear()
	idb.userTable.Clear()
	idb.groupTable.Clear()
	idb.roleTable.Clear()
	idb.userGroupTable.Clear()
	idb.userRoleTable.Clear()
	idb.groupRoleTable.Clear()
	idb.revocationTable.Clear()
	idb.totpRecoveryTable.Clear()
	return nil
}

// CreateAllTable will create tables needed for the Apps if not exist
func (idb *InMemoryDB) CreateAllTable(ctx context.Context) error {
	idb.tenantTable.Clear()
	idb.userTable.Clear()
	idb.groupTable.Clear()
	idb.roleTable.Clear()
	idb.userGroupTable.Clear()
	idb.userRoleTable.Clear()
	idb.groupRoleTable.Clear()
	idb.revocationTable.Clear()
	idb.totpRecoveryTable.Clear()
	return nil
}

var (
	inmemoryLog = log.WithField("go", "InMemoryDbConnector")
)

// GetTenantByDomain return a tenant record
func (idb *InMemoryDB) GetTenantByDomain(ctx context.Context, tenantDomain string) (*Tenant, error) {
	// fLog := inmemoryLog.WithField("func", "GetTenantByDomain").WithField("RequestID", ctx.Value(constants.RequestID))
	for _, t := range idb.tenantTable {
		if t.Domain == tenantDomain {
			return t, nil
		}
	}
	return nil, nil
}

// GetTenantByRecID return a tenant record
func (idb *InMemoryDB) GetTenantByRecID(ctx context.Context, recID string) (*Tenant, error) {
	if t, ok := idb.tenantTable[recID]; ok {
		return t, nil
	}
	return nil, nil
}

// CreateTenantRecord Create new tenant
func (idb *InMemoryDB) CreateTenantRecord(ctx context.Context, tenantName, tenantDomain, description string) (*Tenant, error) {
	if len(tenantName) == 0 {
		return nil, fmt.Errorf("tenant name is empty")
	}
	for _, t := range idb.tenantTable {
		if t.Name == tenantName {
			return nil, &ErrDBExecuteError{
				Wrapped: fmt.Errorf("duplicated tenant name"),
				Message: "Error CreateTenantRecord",
				SQL:     "N/A",
			}
		}
	}
	newTenant := &Tenant{
		RecID:       helper.MakeRandomString(10, true, true, true, false),
		Name:        tenantName,
		Description: description,
		Domain:      tenantDomain,
	}
	idb.tenantTable[newTenant.RecID] = newTenant
	return newTenant, nil
}

// DeleteTenant removes a tenant entity from table
func (idb *InMemoryDB) DeleteTenant(ctx context.Context, tenant *Tenant) error {
	delete(idb.tenantTable, tenant.RecID)
	domainToDelete := tenant.Domain
	todels := make([]string, 0)

	for _, role := range idb.roleTable {
		if role.RoleDomain == domainToDelete {
			todels = append(todels, role.RecID)
			idb.groupRoleTable.DeleteByRole(role.RecID)
			idb.userRoleTable.DeleteByRole(role.RecID)
		}
	}
	for _, k := range todels {
		delete(idb.roleTable, k)
	}
	todels = make([]string, 0)

	for _, group := range idb.groupTable {
		if group.GroupDomain == domainToDelete {
			todels = append(todels, group.RecID)
			idb.groupRoleTable.DeleteByGroup(group.RecID)
			idb.userGroupTable.DeleteByGroup(group.RecID)
		}
	}
	for _, k := range todels {
		delete(idb.groupTable, k)
	}
	todels = make([]string, 0)
}

// UpdateTenant a tenant entity into table tenant
func (idb *InMemoryDB) UpdateTenant(ctx context.Context, tenant *Tenant) error {
	if _, exist := idb.tenantTable[tenant.RecID]; !exist {
		return ErrNotFound
	}
	idb.tenantTable[tenant.RecID] = tenant
	return nil
}

// ListTenant from database with pagination
func (idb *InMemoryDB) ListTenant(ctx context.Context, request *helper.PageRequest) ([]*Tenant, *helper.Page, error) {

}

// GetUserByRecID return a user record
func (idb *InMemoryDB) GetUserByRecID(ctx context.Context, recID string) (*User, error) {

}

// CreateUserRecord in the User table
func (idb *InMemoryDB) CreateUserRecord(ctx context.Context, email, passphrase string) (*User, error) {

}

// GetUserByEmail return a user record
func (idb *InMemoryDB) GetUserByEmail(ctx context.Context, email string) (*User, error) {

}

// GetUserBy2FAToken return a user record
func (idb *InMemoryDB) GetUserBy2FAToken(ctx context.Context, token string) (*User, error) {

}

// GetUserByRecoveryToken return user record
func (idb *InMemoryDB) GetUserByRecoveryToken(ctx context.Context, token string) (*User, error) {

}

// DeleteUser removes a user entity from table
func (idb *InMemoryDB) DeleteUser(ctx context.Context, user *User) error {

}

// SaveOrUpdate a user entity into table user
func (idb *InMemoryDB) UpdateUser(ctx context.Context, user *User) error {

}

// ListUser from database with pagination
func (idb *InMemoryDB) ListUser(ctx context.Context, request *helper.PageRequest) ([]*User, *helper.Page, error) {

}

// Count all user entity in table
func (idb *InMemoryDB) Count(ctx context.Context) (int, error) {

}

// ListAllUserRoles will list all roles owned by a particular user
func (idb *InMemoryDB) ListAllUserRoles(ctx context.Context, user *User, request *helper.PageRequest) ([]*Role, *helper.Page, error) {

}

// GetTOTPRecoveryCodes retrieves all valid/not used TOTP recovery codes.
func (idb *InMemoryDB) GetTOTPRecoveryCodes(ctx context.Context, user *User) ([]string, error) {

}

// RecreateTOTPRecoveryCodes recreates 16 new recovery codes.
func (idb *InMemoryDB) RecreateTOTPRecoveryCodes(ctx context.Context, user *User) ([]string, error) {

}

// MarkTOTPRecoveryCodeUsed will mark the specific recovery code as used and thus can not be used anymore.
func (idb *InMemoryDB) MarkTOTPRecoveryCodeUsed(ctx context.Context, user *User, code string) error {

}

// GetGroupByRecID return a group record
func (idb *InMemoryDB) GetGroupByRecID(ctx context.Context, recID string) (*Group, error) {

}

// GetGroupByName return a group record
func (idb *InMemoryDB) GetGroupByName(ctx context.Context, groupName, groupDomain string) (*Group, error) {

}

// CreateGroup into the Group table
func (idb *InMemoryDB) CreateGroup(ctx context.Context, groupName, groupDomain, description string) (*Group, error) {

}

// ListGroup from the Group table
func (idb *InMemoryDB) ListGroups(ctx context.Context, tenant *Tenant, request *helper.PageRequest) ([]*Group, *helper.Page, error) {

}

// DeleteGroup from Group table
func (idb *InMemoryDB) DeleteGroup(ctx context.Context, group *Group) error {

}

// CreateUserGroup into Group table
func (idb *InMemoryDB) UpdateGroup(ctx context.Context, group *Group) error {

}

// GetUserGroup returns existing UserGroup
func (idb *InMemoryDB) GetUserGroup(ctx context.Context, user *User, group *Group) (*UserGroup, error) {

}

// CreateUserGroup into UserGroup table
func (idb *InMemoryDB) CreateUserGroup(ctx context.Context, user *User, group *Group) (*UserGroup, error) {

}

// ListUserGroupByEmail from the UserGroup table
func (idb *InMemoryDB) ListUserGroupByUser(ctx context.Context, user *User, request *helper.PageRequest) ([]*Group, *helper.Page, error) {

}

// ListUserGroupByGroupName from the UserGroup table
func (idb *InMemoryDB) ListUserGroupByGroup(ctx context.Context, group *Group, request *helper.PageRequest) ([]*User, *helper.Page, error) {

}

// DeleteUserGroup from the UserGroup table
func (idb *InMemoryDB) DeleteUserGroup(ctx context.Context, userGroup *UserGroup) error {

}

// DeleteUserGroupByEmail from the UserGroup table
func (idb *InMemoryDB) DeleteUserGroupByUser(ctx context.Context, user *User) error {

}

// DeleteUserGroupByGroupName from the UserGroup table
func (idb *InMemoryDB) DeleteUserGroupByGroup(ctx context.Context, group *Group) error {

}

// GetUserRole returns existing user role
func (idb *InMemoryDB) GetUserRole(ctx context.Context, user *User, role *Role) (*UserRole, error) {

}

// CreateUserRole into UserRole table
func (idb *InMemoryDB) CreateUserRole(ctx context.Context, user *User, role *Role) (*UserRole, error) {

}

// ListUserRoleByEmail from UserRole table
func (idb *InMemoryDB) ListUserRoleByUser(ctx context.Context, user *User, request *helper.PageRequest) ([]*Role, *helper.Page, error) {

}

// ListUserRoleByRoleName from UserRole table
func (idb *InMemoryDB) ListUserRoleByRole(ctx context.Context, role *Role, request *helper.PageRequest) ([]*User, *helper.Page, error) {

}

// DeleteUserRole from UserRole table
func (idb *InMemoryDB) DeleteUserRole(ctx context.Context, userRole *UserRole) error {

}

// DeleteUserRoleByEmail from UserRole table
func (idb *InMemoryDB) DeleteUserRoleByUser(ctx context.Context, user *User) error {

}

// DeleteUserRoleByRoleName from UserRole table
func (idb *InMemoryDB) DeleteUserRoleByRole(ctx context.Context, role *Role) error {

}

// GetGroupRole return existing group role
func (idb *InMemoryDB) GetGroupRole(ctx context.Context, group *Group, role *Role) (*GroupRole, error) {

}

// CreateGroupRole into GroupRole table
func (idb *InMemoryDB) CreateGroupRole(ctx context.Context, group *Group, role *Role) (*GroupRole, error) {

}

// ListGroupRoleByGroupName from GroupRole table
func (idb *InMemoryDB) ListGroupRoleByGroup(ctx context.Context, group *Group, request *helper.PageRequest) ([]*Role, *helper.Page, error) {

}

// ListGroupRoleByRoleName from GroupRole table
func (idb *InMemoryDB) ListGroupRoleByRole(ctx context.Context, role *Role, request *helper.PageRequest) ([]*Group, *helper.Page, error) {

}

// DeleteGroupRole from GroupRole table
func (idb *InMemoryDB) DeleteGroupRole(ctx context.Context, groupRole *GroupRole) error {

}

// DeleteGroupRoleByEmail from GroupRole table
func (idb *InMemoryDB) DeleteGroupRoleByGroup(ctx context.Context, group *Group) error {

}

// DeleteGroupRoleByRoleName from GroupRole table
func (idb *InMemoryDB) DeleteGroupRoleByRole(ctx context.Context, role *Role) error {

}

// GetRoleByRecID return an existing role
func (idb *InMemoryDB) GetRoleByRecID(ctx context.Context, recID string) (*Role, error) {

}

// GetRoleByName return a role record
func (idb *InMemoryDB) GetRoleByName(ctx context.Context, roleName, roleDomain string) (*Role, error) {

}

// CreateRole into Role table
func (idb *InMemoryDB) CreateRole(ctx context.Context, roleName, roleDomain, description string) (*Role, error) {

}

// ListRoles from Role table
func (idb *InMemoryDB) ListRoles(ctx context.Context, tenant *Tenant, request *helper.PageRequest) ([]*Role, *helper.Page, error) {

}

// DeleteRole from Role table
func (idb *InMemoryDB) DeleteRole(ctx context.Context, role *Role) error {

}

// SaveOrUpdateRole into Role table
func (idb *InMemoryDB) UpdateRole(ctx context.Context, role *Role) error {

}

// Revoke a subject
func (idb *InMemoryDB) Revoke(ctx context.Context, subject string) error {

}

// UnRevoke a subject
func (idb *InMemoryDB) UnRevoke(ctx context.Context, subject string) error {

}

// IsRevoked validate if a subject is revoked
func (idb *InMemoryDB) IsRevoked(ctx context.Context, subject string) (bool, error) {

}

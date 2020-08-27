package connector

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/hyperjumptech/hansip/pkg/helper"
	"github.com/hyperjumptech/hansip/pkg/totp"
	"golang.org/x/crypto/bcrypt"
)

var (
	inMemoryInstance *InMemoryDb
)

// GetInMemoryDbInstance returns memory instance
func GetInMemoryDbInstance() *InMemoryDb {
	if inMemoryInstance == nil {
		inMemoryInstance = &InMemoryDb{
			UserTable:      make(map[string]*User),
			UserRoleTable:  make(map[string]*UserRole),
			RoleTable:      make(map[string]*Role),
			GroupTable:     make(map[string]*Group),
			GroupRoleTable: make(map[string]*GroupRole),
			UserGroupTable: make(map[string]*UserGroup),
		}
	}
	return inMemoryInstance
}

// InMemoryDb used when no external DB is used.
type InMemoryDb struct {
	UserTable      map[string]*User
	UserRoleTable  map[string]*UserRole
	RoleTable      map[string]*Role
	GroupTable     map[string]*Group
	GroupRoleTable map[string]*GroupRole
	UserGroupTable map[string]*UserGroup
}

func (mem *InMemoryDb) cloneUser(u *User) *User {
	return &User{
		RecID:             u.RecID,
		Email:             u.Email,
		HashedPassphrase:  u.HashedPassphrase,
		Enabled:           u.Enabled,
		Suspended:         u.Suspended,
		LastSeen:          u.LastSeen,
		LastLogin:         u.LastLogin,
		FailCount:         u.FailCount,
		ActivationCode:    u.ActivationCode,
		ActivationDate:    u.ActivationDate,
		UserTotpSecretKey: u.UserTotpSecretKey,
		Enable2FactorAuth: u.Enable2FactorAuth,
		Token2FA:          u.Token2FA,
		RecoveryCode:      u.RecoveryCode,
	}
}

// DropAllTables used by hansip
func (mem *InMemoryDb) DropAllTables(ctx context.Context) error {
	// do nothing
	return nil
}

// CreateAllTable creates internal tables used by Hansip
func (mem *InMemoryDb) CreateAllTable(ctx context.Context) error {
	for k := range mem.UserTable {
		delete(mem.UserTable, k)
	}
	for k := range mem.GroupTable {
		delete(mem.GroupTable, k)
	}
	for k := range mem.RoleTable {
		delete(mem.RoleTable, k)
	}
	for k := range mem.UserRoleTable {
		delete(mem.UserRoleTable, k)
	}
	for k := range mem.GroupRoleTable {
		delete(mem.GroupRoleTable, k)
	}
	for k := range mem.UserGroupTable {
		delete(mem.UserGroupTable, k)
	}
	return nil
}

// GetUserByRecID returns user by record ID
func (mem *InMemoryDb) GetUserByRecID(ctx context.Context, recID string) (*User, error) {
	if u, ok := mem.UserTable[recID]; ok {
		return u, nil
	}
	return nil, fmt.Errorf("not found")
}

// CreateUserRecord creates a user record
func (mem *InMemoryDb) CreateUserRecord(ctx context.Context, email, passphrase string) (*User, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(passphrase), 14)
	if err != nil {
		return nil, err
	}
	if _, ok := mem.UserTable[email]; !ok {
		user := &User{
			RecID:             helper.MakeRandomString(10, true, true, true, false),
			Email:             email,
			HashedPassphrase:  string(bytes),
			Enabled:           false,
			Suspended:         false,
			LastSeen:          time.Now(),
			LastLogin:         time.Now(),
			FailCount:         0,
			ActivationCode:    helper.MakeRandomString(6, true, false, false, false),
			ActivationDate:    time.Now(),
			Enable2FactorAuth: false,
			UserTotpSecretKey: totp.MakeRandomTotpKey(),
		}
		mem.UserTable[user.RecID] = user
		return user, nil
	}
	return nil, fmt.Errorf("duplicate user email")
}

// GetUserByEmail returns a user record by email
func (mem *InMemoryDb) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	for _, u := range mem.UserTable {
		if u.Email == email {
			return mem.cloneUser(u), nil
		}
	}
	return nil, fmt.Errorf("email not found")
}

// GetUserBy2FAToken get user record from token.
func (mem *InMemoryDb) GetUserBy2FAToken(ctx context.Context, token string) (*User, error) {
	for _, u := range mem.UserTable {
		if u.Token2FA == token {
			return mem.cloneUser(u), nil
		}
	}
	return nil, fmt.Errorf("token not found")
}

// GetUserByRecoveryToken returns user record from recovery token
func (mem *InMemoryDb) GetUserByRecoveryToken(ctx context.Context, token string) (*User, error) {
	for _, u := range mem.UserTable {
		if u.RecoveryCode == token {
			return mem.cloneUser(u), nil
		}
	}
	return nil, fmt.Errorf("token not found")
}

// DeleteUser kill user in database
func (mem *InMemoryDb) DeleteUser(ctx context.Context, user *User) error {
	if _, ok := mem.UserTable[user.RecID]; ok {
		delete(mem.UserTable, user.RecID)
		return nil
	}
	return fmt.Errorf("user not found")
}

// SaveOrUpdate save user record
func (mem *InMemoryDb) SaveOrUpdate(ctx context.Context, user *User) error {
	if u, err := mem.GetUserByEmail(ctx, user.Email); err != nil {
		if user.RecID != u.RecID {
			return fmt.Errorf("duplicate")
		}
	}
	mem.UserTable[user.RecID] = user
	return nil
}

// ListUser lists user records
func (mem *InMemoryDb) ListUser(ctx context.Context, request *helper.PageRequest) ([]*User, *helper.Page, error) {
	userList := make([]*User, 0)
	for _, v := range mem.UserTable {
		userList = append(userList, v)
	}
	if request.OrderBy == "EMAIL" {
		if request.Sort == "ASC" {
			sort.SliceStable(userList, func(i, j int) bool {
				return userList[i].Email < userList[j].Email
			})
		} else if request.Sort == "DESC" {
			sort.SliceStable(userList, func(i, j int) bool {
				return userList[i].Email > userList[j].Email
			})
		}
	}

	page := helper.NewPage(request, uint(len(userList)))
	retList := userList[page.OffsetStart:page.OffsetEnd]

	return retList, page, nil
}

// Count user entries in internal db
func (mem *InMemoryDb) Count(ctx context.Context) (int, error) {
	return len(mem.UserTable), nil
}

// ListAllUserRoles lists all roles assigned to user
func (mem *InMemoryDb) ListAllUserRoles(ctx context.Context, user *User, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	retMap := make(map[string]*Role)
	for _, v := range mem.UserRoleTable {
		if v.UserRecID == user.RecID {
			retMap[v.RoleRecID] = mem.RoleTable[v.RoleRecID]
		}
	}
	for _, ug := range mem.UserGroupTable {
		if ug.UserRecID == user.RecID {
			for _, gr := range mem.GroupRoleTable {
				if ug.GroupRecID == gr.GroupRecID {
					retMap[gr.RoleRecID] = mem.RoleTable[gr.RoleRecID]
				}
			}
		}
	}

	roles := make([]*Role, 0)
	for _, v := range retMap {
		roles = append(roles, v)
	}

	if request.OrderBy == "RoleName" {
		if request.Sort == "ASC" {
			sort.SliceStable(roles, func(i, j int) bool {
				return roles[i].RoleName < roles[j].RoleName
			})
		} else if request.Sort == "DESC" {
			sort.SliceStable(roles, func(i, j int) bool {
				return roles[i].RoleName > roles[j].RoleName
			})
		}
	}

	page := helper.NewPage(request, uint(len(roles)))
	return roles[page.OffsetStart:page.OffsetEnd], page, nil
}

// GetUserRole returns user role
func (mem *InMemoryDb) GetUserRole(ctx context.Context, user *User, role *Role) (*UserRole, error) {
	key := fmt.Sprintf("%s%s", user.RecID, role.RecID)
	if val, ok := mem.UserRoleTable[key]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("not found")
}

// CreateUserRole assign role to user
func (mem *InMemoryDb) CreateUserRole(ctx context.Context, user *User, role *Role) (*UserRole, error) {
	key := fmt.Sprintf("%s%s", user.RecID, role.RecID)
	if _, ok := mem.UserRoleTable[key]; ok {
		return nil, fmt.Errorf("duplicate")
	}
	urole := &UserRole{
		UserRecID: user.RecID,
		RoleRecID: role.RecID,
	}
	mem.UserRoleTable[key] = urole
	return urole, nil
}

// ListUserRoleByUser return all roles owned/assigned by User
func (mem *InMemoryDb) ListUserRoleByUser(ctx context.Context, user *User, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	ret := make([]*Role, 0)
	for _, v := range mem.UserRoleTable {
		if v.UserRecID == user.RecID {
			ret = append(ret, mem.RoleTable[v.RoleRecID])
		}
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}

// ListUserRoleByRole list all users that has the Role
func (mem *InMemoryDb) ListUserRoleByRole(ctx context.Context, role *Role, request *helper.PageRequest) ([]*User, *helper.Page, error) {
	ret := make([]*User, 0)
	for _, v := range mem.UserRoleTable {
		if v.RoleRecID == role.RecID {
			ret = append(ret, mem.UserTable[v.UserRecID])
		}
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}

// DeleteUserRole remove user role
func (mem *InMemoryDb) DeleteUserRole(ctx context.Context, userRole *UserRole) error {
	key := fmt.Sprintf("%s%s", userRole.UserRecID, userRole.RoleRecID)
	delete(mem.UserRoleTable, key)
	return nil
}

// DeleteUserRoleByUser deletes all roles owned/assigned by User
func (mem *InMemoryDb) DeleteUserRoleByUser(ctx context.Context, user *User) error {
	todel := make([]string, 0)
	for k, v := range mem.UserRoleTable {
		if v.UserRecID == user.RecID {
			todel = append(todel, k)
		}
	}
	for _, v := range todel {
		delete(mem.UserRoleTable, v)
	}
	return nil
}

// DeleteUserRoleByRole remove all user with this Role
func (mem *InMemoryDb) DeleteUserRoleByRole(ctx context.Context, role *Role) error {
	todel := make([]string, 0)
	for k, v := range mem.UserRoleTable {
		if v.RoleRecID == role.RecID {
			todel = append(todel, k)
		}
	}
	for _, v := range todel {
		delete(mem.UserRoleTable, v)
	}
	return nil
}

// GetRoleByRecID returns a role from a record ID
func (mem *InMemoryDb) GetRoleByRecID(ctx context.Context, recID string) (*Role, error) {
	if r, ok := mem.RoleTable[recID]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("not founD")
}

// CreateRole create role entry
func (mem *InMemoryDb) CreateRole(ctx context.Context, roleName, description string) (*Role, error) {
	if _, ok := mem.RoleTable[roleName]; ok {
		return nil, fmt.Errorf("duplicate")
	}
	role := &Role{
		RecID:       helper.MakeRandomString(10, true, true, true, false),
		RoleName:    roleName,
		Description: description,
	}
	mem.RoleTable[role.RecID] = role
	return role, nil
}

// ListRoles list all roles in internal memory
func (mem *InMemoryDb) ListRoles(ctx context.Context, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	ret := make([]*Role, 0)
	for _, v := range mem.RoleTable {
		ret = append(ret, v)
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}

// DeleteRole deletes role
func (mem *InMemoryDb) DeleteRole(ctx context.Context, role *Role) error {
	delete(mem.RoleTable, role.RecID)
	return nil
}

// SaveOrUpdateRole updates a role (or save if not exist)
func (mem *InMemoryDb) SaveOrUpdateRole(ctx context.Context, role *Role) error {
	mem.RoleTable[role.RoleName] = role
	return nil
}

// GetGroupByRecID returns group from record id
func (mem *InMemoryDb) GetGroupByRecID(ctx context.Context, recID string) (*Group, error) {
	if g, ok := mem.GroupTable[recID]; ok {
		return g, nil
	}
	return nil, fmt.Errorf("not found")
}

// CreateGroup create group entry
func (mem *InMemoryDb) CreateGroup(ctx context.Context, groupName, description string) (*Group, error) {
	for _, v := range mem.GroupTable {
		if v.GroupName == groupName {
			return nil, fmt.Errorf("duplicate")
		}
	}
	group := &Group{
		RecID:       helper.MakeRandomString(10, true, true, true, false),
		GroupName:   groupName,
		Description: description,
	}
	mem.GroupTable[group.RecID] = group
	return group, nil
}

// ListGroups lists all groups
func (mem *InMemoryDb) ListGroups(ctx context.Context, request *helper.PageRequest) ([]*Group, *helper.Page, error) {
	ret := make([]*Group, 0)
	for _, v := range mem.GroupTable {
		ret = append(ret, v)
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}

// DeleteGroup deletes group
func (mem *InMemoryDb) DeleteGroup(ctx context.Context, group *Group) error {
	delete(mem.GroupTable, group.RecID)
	return nil
}

// SaveOrUpdateGroup update group
func (mem *InMemoryDb) SaveOrUpdateGroup(ctx context.Context, group *Group) error {
	for _, v := range mem.GroupTable {
		if v.GroupName == group.GroupName && v.RecID != group.RecID {
			return fmt.Errorf("duplicate")
		}
	}
	mem.GroupTable[group.RecID] = group
	return nil
}

// GetGroupRole returns group role
func (mem *InMemoryDb) GetGroupRole(ctx context.Context, group *Group, role *Role) (*GroupRole, error) {
	key := fmt.Sprintf("%s%s", group.RecID, role.RecID)
	if g, ok := mem.GroupRoleTable[key]; ok {
		return g, nil
	}
	return nil, fmt.Errorf("not found")
}

// CreateGroupRole creates group role
func (mem *InMemoryDb) CreateGroupRole(ctx context.Context, group *Group, role *Role) (*GroupRole, error) {
	key := fmt.Sprintf("%s%s", group.RecID, role.RecID)
	if _, ok := mem.GroupRoleTable[key]; ok {
		return nil, fmt.Errorf("duplicate")
	}
	grole := &GroupRole{
		GroupRecID: group.RecID,
		RoleRecID:  role.RecID,
	}
	mem.GroupRoleTable[key] = grole
	return grole, nil
}

// ListGroupRoleByGroup list all roles owned by group
func (mem *InMemoryDb) ListGroupRoleByGroup(ctx context.Context, group *Group, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	ret := make([]*Role, 0)
	for _, v := range mem.GroupRoleTable {
		if v.GroupRecID == group.RecID {
			ret = append(ret, mem.RoleTable[v.RoleRecID])
		}
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}

// ListGroupRoleByRole lists all group-roles by role
func (mem *InMemoryDb) ListGroupRoleByRole(ctx context.Context, role *Role, request *helper.PageRequest) ([]*Group, *helper.Page, error) {
	ret := make([]*Group, 0)
	for _, v := range mem.GroupRoleTable {
		if v.RoleRecID == role.RecID {
			ret = append(ret, mem.GroupTable[v.GroupRecID])
		}
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}

// DeleteGroupRole delete group-role
func (mem *InMemoryDb) DeleteGroupRole(ctx context.Context, groupRole *GroupRole) error {
	delete(mem.GroupRoleTable, groupRole.GroupRecID)
	return nil
}

// DeleteGroupRoleByGroup delete group-role by group
func (mem *InMemoryDb) DeleteGroupRoleByGroup(ctx context.Context, group *Group) error {
	todel := make([]string, 0)
	for k, v := range mem.GroupRoleTable {
		if v.GroupRecID == group.RecID {
			todel = append(todel, k)
		}
	}
	for _, v := range todel {
		delete(mem.GroupRoleTable, v)
	}
	return nil
}

// DeleteGroupRoleByRole deletes group role by role
func (mem *InMemoryDb) DeleteGroupRoleByRole(ctx context.Context, role *Role) error {
	todel := make([]string, 0)
	for k, v := range mem.GroupRoleTable {
		if v.RoleRecID == role.RecID {
			todel = append(todel, k)
		}
	}
	for _, v := range todel {
		delete(mem.GroupRoleTable, v)
	}
	return nil
}

// GetUserGroup get user group
func (mem *InMemoryDb) GetUserGroup(ctx context.Context, user *User, group *Group) (*UserGroup, error) {
	key := fmt.Sprintf("%s%s", user.RecID, group.RecID)
	if g, ok := mem.UserGroupTable[key]; ok {
		return g, nil
	}
	return nil, fmt.Errorf("not found")
}

// CreateUserGroup creates user-group
func (mem *InMemoryDb) CreateUserGroup(ctx context.Context, user *User, group *Group) (*UserGroup, error) {
	key := fmt.Sprintf("%s%s", user.RecID, group.RecID)
	if _, ok := mem.UserGroupTable[key]; ok {
		return nil, fmt.Errorf("duplicate")
	}
	ugroup := &UserGroup{
		UserRecID:  user.RecID,
		GroupRecID: group.RecID,
	}
	mem.UserGroupTable[key] = ugroup
	return ugroup, nil
}

// ListUserGroupByUser list user-group by user
func (mem *InMemoryDb) ListUserGroupByUser(ctx context.Context, user *User, request *helper.PageRequest) ([]*Group, *helper.Page, error) {
	ret := make([]*Group, 0)
	for _, v := range mem.UserGroupTable {
		if v.UserRecID == user.RecID {
			ret = append(ret, mem.GroupTable[v.GroupRecID])
		}
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}

// ListUserGroupByGroup lists user-group by group
func (mem *InMemoryDb) ListUserGroupByGroup(ctx context.Context, group *Group, request *helper.PageRequest) ([]*User, *helper.Page, error) {
	ret := make([]*User, 0)
	for _, v := range mem.UserGroupTable {
		if v.GroupRecID == group.RecID {
			ret = append(ret, mem.UserTable[v.UserRecID])
		}
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}

// DeleteUserGroup delete user-group
func (mem *InMemoryDb) DeleteUserGroup(ctx context.Context, userGroup *UserGroup) error {
	key := fmt.Sprintf("%s%s", userGroup.UserRecID, userGroup.GroupRecID)
	delete(mem.UserGroupTable, key)
	return nil
}

// DeleteUserGroupByUser delete user-group assinged to user
func (mem *InMemoryDb) DeleteUserGroupByUser(ctx context.Context, user *User) error {
	todel := make([]string, 0)
	for k, v := range mem.UserGroupTable {
		if v.UserRecID == user.RecID {
			todel = append(todel, k)
		}
	}
	for _, v := range todel {
		delete(mem.UserGroupTable, v)
	}
	return nil
}

// DeleteUserGroupByGroup deletes user-group by group
func (mem *InMemoryDb) DeleteUserGroupByGroup(ctx context.Context, group *Group) error {
	todel := make([]string, 0)
	for k, v := range mem.UserGroupTable {
		if v.GroupRecID == group.RecID {
			todel = append(todel, k)
		}
	}
	for _, v := range todel {
		delete(mem.UserGroupTable, v)
	}
	return nil
}

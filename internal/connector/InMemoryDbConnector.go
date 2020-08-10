package connector

import (
	"context"
	"fmt"
	"github.com/hyperjumptech/hansip/pkg/helper"
	"github.com/hyperjumptech/hansip/pkg/totp"
	"golang.org/x/crypto/bcrypt"
	"sort"
	"time"
)

var (
	inMemoryInstance *InMemoryDb
)

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
		RecId:             u.RecId,
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

func (mem *InMemoryDb) DropAllTables(ctx context.Context) error {
	// do nothing
	return nil
}
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

func (mem *InMemoryDb) GetUserByRecId(ctx context.Context, recID string) (*User, error) {
	if u, ok := mem.UserTable[recID]; ok {
		return u, nil
	}
	return nil, fmt.Errorf("not found")
}

func (mem *InMemoryDb) CreateUserRecord(ctx context.Context, email, passphrase string) (*User, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(passphrase), 14)
	if err != nil {
		return nil, err
	}
	if _, ok := mem.UserTable[email]; !ok {
		user := &User{
			RecId:             helper.MakeRandomString(10, true, true, true, false),
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
		mem.UserTable[user.RecId] = user
		return user, nil
	}
	return nil, fmt.Errorf("duplicate user email")
}
func (mem *InMemoryDb) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	for _, u := range mem.UserTable {
		if u.Email == email {
			return mem.cloneUser(u), nil
		}
	}
	return nil, fmt.Errorf("email not found")
}
func (mem *InMemoryDb) GetUserBy2FAToken(ctx context.Context, token string) (*User, error) {
	for _, u := range mem.UserTable {
		if u.Token2FA == token {
			return mem.cloneUser(u), nil
		}
	}
	return nil, fmt.Errorf("token not found")
}
func (mem *InMemoryDb) GetUserByRecoveryToken(ctx context.Context, token string) (*User, error) {
	for _, u := range mem.UserTable {
		if u.RecoveryCode == token {
			return mem.cloneUser(u), nil
		}
	}
	return nil, fmt.Errorf("token not found")
}
func (mem *InMemoryDb) DeleteUser(ctx context.Context, user *User) error {
	if _, ok := mem.UserTable[user.RecId]; ok {
		delete(mem.UserTable, user.RecId)
		return nil
	}
	return fmt.Errorf("user not found")
}
func (mem *InMemoryDb) SaveOrUpdate(ctx context.Context, user *User) error {
	if u, err := mem.GetUserByEmail(ctx, user.Email); err != nil {
		if user.RecId != u.RecId {
			return fmt.Errorf("duplicate")
		}
	}
	mem.UserTable[user.RecId] = user
	return nil
}
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
func (mem *InMemoryDb) Count(ctx context.Context) (int, error) {
	return len(mem.UserTable), nil
}

func (mem *InMemoryDb) ListAllUserRoles(ctx context.Context, user *User, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	retMap := make(map[string]*Role)
	for _, v := range mem.UserRoleTable {
		if v.UserRecId == user.RecId {
			retMap[v.RoleRecId] = mem.RoleTable[v.RoleRecId]
		}
	}
	for _, ug := range mem.UserGroupTable {
		if ug.UserRecId == user.RecId {
			for _, gr := range mem.GroupRoleTable {
				if ug.GroupRecId == gr.GroupRecId {
					retMap[gr.RoleRecId] = mem.RoleTable[gr.RoleRecId]
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

func (mem *InMemoryDb) GetUserRole(ctx context.Context, user *User, role *Role) (*UserRole, error) {
	key := fmt.Sprintf("%s%s", user.RecId, role.RecId)
	if val, ok := mem.UserRoleTable[key]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("not found")
}
func (mem *InMemoryDb) CreateUserRole(ctx context.Context, user *User, role *Role) (*UserRole, error) {
	key := fmt.Sprintf("%s%s", user.RecId, role.RecId)
	if _, ok := mem.UserRoleTable[key]; ok {
		return nil, fmt.Errorf("duplicate")
	}
	urole := &UserRole{
		UserRecId: user.RecId,
		RoleRecId: role.RecId,
	}
	mem.UserRoleTable[key] = urole
	return urole, nil
}
func (mem *InMemoryDb) ListUserRoleByUser(ctx context.Context, user *User, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	ret := make([]*Role, 0)
	for _, v := range mem.UserRoleTable {
		if v.UserRecId == user.RecId {
			ret = append(ret, mem.RoleTable[v.RoleRecId])
		}
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}
func (mem *InMemoryDb) ListUserRoleByRole(ctx context.Context, role *Role, request *helper.PageRequest) ([]*User, *helper.Page, error) {
	ret := make([]*User, 0)
	for _, v := range mem.UserRoleTable {
		if v.RoleRecId == role.RecId {
			ret = append(ret, mem.UserTable[v.UserRecId])
		}
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}
func (mem *InMemoryDb) DeleteUserRole(ctx context.Context, userRole *UserRole) error {
	key := fmt.Sprintf("%s%s", userRole.UserRecId, userRole.RoleRecId)
	delete(mem.UserRoleTable, key)
	return nil
}
func (mem *InMemoryDb) DeleteUserRoleByUser(ctx context.Context, user *User) error {
	todel := make([]string, 0)
	for k, v := range mem.UserRoleTable {
		if v.UserRecId == user.RecId {
			todel = append(todel, k)
		}
	}
	for _, v := range todel {
		delete(mem.UserRoleTable, v)
	}
	return nil
}
func (mem *InMemoryDb) DeleteUserRoleByRole(ctx context.Context, role *Role) error {
	todel := make([]string, 0)
	for k, v := range mem.UserRoleTable {
		if v.RoleRecId == role.RecId {
			todel = append(todel, k)
		}
	}
	for _, v := range todel {
		delete(mem.UserRoleTable, v)
	}
	return nil
}
func (mem *InMemoryDb) GetRoleByRecId(ctx context.Context, recId string) (*Role, error) {
	if r, ok := mem.RoleTable[recId]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("not found")
}
func (mem *InMemoryDb) CreateRole(ctx context.Context, roleName, description string) (*Role, error) {
	if _, ok := mem.RoleTable[roleName]; ok {
		return nil, fmt.Errorf("duplicate")
	}
	role := &Role{
		RecId:       helper.MakeRandomString(10, true, true, true, false),
		RoleName:    roleName,
		Description: description,
	}
	mem.RoleTable[role.RecId] = role
	return role, nil
}
func (mem *InMemoryDb) ListRoles(ctx context.Context, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	ret := make([]*Role, 0)
	for _, v := range mem.RoleTable {
		ret = append(ret, v)
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}
func (mem *InMemoryDb) DeleteRole(ctx context.Context, role *Role) error {
	delete(mem.RoleTable, role.RecId)
	return nil
}
func (mem *InMemoryDb) SaveOrUpdateRole(ctx context.Context, role *Role) error {
	mem.RoleTable[role.RoleName] = role
	return nil
}
func (mem *InMemoryDb) GetGroupByRecId(ctx context.Context, recId string) (*Group, error) {
	if g, ok := mem.GroupTable[recId]; ok {
		return g, nil
	}
	return nil, fmt.Errorf("not found")
}
func (mem *InMemoryDb) CreateGroup(ctx context.Context, groupName, description string) (*Group, error) {
	for _, v := range mem.GroupTable {
		if v.GroupName == groupName {
			return nil, fmt.Errorf("duplicate")
		}
	}
	group := &Group{
		RecId:       helper.MakeRandomString(10, true, true, true, false),
		GroupName:   groupName,
		Description: description,
	}
	mem.GroupTable[group.RecId] = group
	return group, nil
}
func (mem *InMemoryDb) ListGroups(ctx context.Context, request *helper.PageRequest) ([]*Group, *helper.Page, error) {
	ret := make([]*Group, 0)
	for _, v := range mem.GroupTable {
		ret = append(ret, v)
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}
func (mem *InMemoryDb) DeleteGroup(ctx context.Context, group *Group) error {
	delete(mem.GroupTable, group.RecId)
	return nil
}
func (mem *InMemoryDb) SaveOrUpdateGroup(ctx context.Context, group *Group) error {
	for _, v := range mem.GroupTable {
		if v.GroupName == group.GroupName && v.RecId != group.RecId {
			return fmt.Errorf("duplicate")
		}
	}
	mem.GroupTable[group.RecId] = group
	return nil
}
func (mem *InMemoryDb) GetGroupRole(ctx context.Context, group *Group, role *Role) (*GroupRole, error) {
	key := fmt.Sprintf("%s%s", group.RecId, role.RecId)
	if g, ok := mem.GroupRoleTable[key]; ok {
		return g, nil
	}
	return nil, fmt.Errorf("not found")
}
func (mem *InMemoryDb) CreateGroupRole(ctx context.Context, group *Group, role *Role) (*GroupRole, error) {
	key := fmt.Sprintf("%s%s", group.RecId, role.RecId)
	if _, ok := mem.GroupRoleTable[key]; ok {
		return nil, fmt.Errorf("duplicate")
	}
	grole := &GroupRole{
		GroupRecId: group.RecId,
		RoleRecId:  role.RecId,
	}
	mem.GroupRoleTable[key] = grole
	return grole, nil
}
func (mem *InMemoryDb) ListGroupRoleByGroup(ctx context.Context, group *Group, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	ret := make([]*Role, 0)
	for _, v := range mem.GroupRoleTable {
		if v.GroupRecId == group.RecId {
			ret = append(ret, mem.RoleTable[v.RoleRecId])
		}
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}
func (mem *InMemoryDb) ListGroupRoleByRole(ctx context.Context, role *Role, request *helper.PageRequest) ([]*Group, *helper.Page, error) {
	ret := make([]*Group, 0)
	for _, v := range mem.GroupRoleTable {
		if v.RoleRecId == role.RecId {
			ret = append(ret, mem.GroupTable[v.GroupRecId])
		}
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}
func (mem *InMemoryDb) DeleteGroupRole(ctx context.Context, groupRole *GroupRole) error {
	delete(mem.GroupRoleTable, groupRole.GroupRecId)
	return nil
}
func (mem *InMemoryDb) DeleteGroupRoleByGroup(ctx context.Context, group *Group) error {
	todel := make([]string, 0)
	for k, v := range mem.GroupRoleTable {
		if v.GroupRecId == group.RecId {
			todel = append(todel, k)
		}
	}
	for _, v := range todel {
		delete(mem.GroupRoleTable, v)
	}
	return nil
}
func (mem *InMemoryDb) DeleteGroupRoleByRole(ctx context.Context, role *Role) error {
	todel := make([]string, 0)
	for k, v := range mem.GroupRoleTable {
		if v.RoleRecId == role.RecId {
			todel = append(todel, k)
		}
	}
	for _, v := range todel {
		delete(mem.GroupRoleTable, v)
	}
	return nil
}

func (mem *InMemoryDb) GetUserGroup(ctx context.Context, user *User, group *Group) (*UserGroup, error) {
	key := fmt.Sprintf("%s%s", user.RecId, group.RecId)
	if g, ok := mem.UserGroupTable[key]; ok {
		return g, nil
	}
	return nil, fmt.Errorf("not found")
}

func (mem *InMemoryDb) CreateUserGroup(ctx context.Context, user *User, group *Group) (*UserGroup, error) {
	key := fmt.Sprintf("%s%s", user.RecId, group.RecId)
	if _, ok := mem.UserGroupTable[key]; ok {
		return nil, fmt.Errorf("duplicate")
	}
	ugroup := &UserGroup{
		UserRecId:  user.RecId,
		GroupRecId: group.RecId,
	}
	mem.UserGroupTable[key] = ugroup
	return ugroup, nil
}
func (mem *InMemoryDb) ListUserGroupByUser(ctx context.Context, user *User, request *helper.PageRequest) ([]*Group, *helper.Page, error) {
	ret := make([]*Group, 0)
	for _, v := range mem.UserGroupTable {
		if v.UserRecId == user.RecId {
			ret = append(ret, mem.GroupTable[v.GroupRecId])
		}
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}
func (mem *InMemoryDb) ListUserGroupByGroup(ctx context.Context, group *Group, request *helper.PageRequest) ([]*User, *helper.Page, error) {
	ret := make([]*User, 0)
	for _, v := range mem.UserGroupTable {
		if v.GroupRecId == group.RecId {
			ret = append(ret, mem.UserTable[v.UserRecId])
		}
	}
	page := helper.NewPage(request, uint(len(ret)))
	return ret[page.OffsetStart:page.OffsetEnd], page, nil
}
func (mem *InMemoryDb) DeleteUserGroup(ctx context.Context, userGroup *UserGroup) error {
	key := fmt.Sprintf("%s%s", userGroup.UserRecId, userGroup.GroupRecId)
	delete(mem.UserGroupTable, key)
	return nil
}
func (mem *InMemoryDb) DeleteUserGroupByUser(ctx context.Context, user *User) error {
	todel := make([]string, 0)
	for k, v := range mem.UserGroupTable {
		if v.UserRecId == user.RecId {
			todel = append(todel, k)
		}
	}
	for _, v := range todel {
		delete(mem.UserGroupTable, v)
	}
	return nil
}
func (mem *InMemoryDb) DeleteUserGroupByGroup(ctx context.Context, group *Group) error {
	todel := make([]string, 0)
	for k, v := range mem.UserGroupTable {
		if v.GroupRecId == group.RecId {
			todel = append(todel, k)
		}
	}
	for _, v := range todel {
		delete(mem.UserGroupTable, v)
	}
	return nil
}

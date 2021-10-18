package connector

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/constants"
	"github.com/hyperjumptech/hansip/pkg/helper"
	"github.com/hyperjumptech/hansip/pkg/totp"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"regexp"
	"sort"
	"time"
)

const (
	// DropAllSqlite contains SQL to drop all existing table for hansip
	DropAllSqlite = `DROP TABLE IF EXISTS HANSIP_REVOCATION, HANSIP_TOTP_RECOVERY_CODES, HANSIP_USER_GROUP, HANSIP_USER_ROLE, HANSIP_GROUP_ROLE, HANSIP_USER, HANSIP_GROUP, HANSIP_ROLE, HANSIP_TENANT;`

	// CreateTenantSqlite contains SQL to create HANSIP_ROLE table
	CreateTenantSqlite = `CREATE TABLE IF NOT EXISTS HANSIP_TENANT (
    REC_ID VARCHAR(32) NOT NULL UNIQUE,
    TENANT_NAME VARCHAR(128) NOT NULL UNIQUE,
    TENANT_DOMAIN VARCHAR(255),
    DESCRIPTION VARCHAR(255),
    PRIMARY KEY (REC_ID)
)`

	// CreateUserSqlite will create HANSIP_USER table
	CreateUserSqlite = `CREATE TABLE IF NOT EXISTS HANSIP_USER (
    REC_ID VARCHAR(32) NOT NULL UNIQUE,
    EMAIL VARCHAR(128)  NOT NULL UNIQUE,
    HASHED_PASSPHRASE VARCHAR(128),
    ENABLED BOOLEAN  DEFAULT 0,
    SUSPENDED BOOLEAN DEFAULT 0,
    LAST_SEEN FLOAT,
    LAST_LOGIN FLOAT,
    FAIL_COUNT INTEGER DEFAULT 0,
    ACTIVATION_CODE VARCHAR(32),
    ACTIVATION_DATE FLOAT,
    TOTP_KEY VARCHAR(64),
    ENABLE_2FE BOOLEAN DEFAULT 0,
    TOKEN_2FE VARCHAR(10),
    RECOVERY_CODE VARCHAR (20),
    PRIMARY KEY (REC_ID)
)`
	// CreateGroupSqlite contains SQL to  create HANSIP_GROUP
	CreateGroupSqlite = `CREATE TABLE IF NOT EXISTS HANSIP_GROUP (
    REC_ID VARCHAR(32) NOT NULL UNIQUE,
    GROUP_NAME VARCHAR(128) NOT NULL,
    GROUP_DOMAIN VARCHAR(128) NOT NULL,
    DESCRIPTION VARCHAR(255),
    UNIQUE (GROUP_NAME, GROUP_DOMAIN),
    PRIMARY KEY (REC_ID)
)`
	// CreateRoleSqlite contains SQL to create HANSIP_ROLE table
	CreateRoleSqlite = `CREATE TABLE IF NOT EXISTS HANSIP_ROLE (
    REC_ID VARCHAR(32) NOT NULL UNIQUE,
    ROLE_NAME VARCHAR(128) NOT NULL,
    ROLE_DOMAIN VARCHAR(128) NOT NULL,
    DESCRIPTION VARCHAR(255),
    UNIQUE (ROLE_NAME, ROLE_DOMAIN),
    PRIMARY KEY (REC_ID)
)`
	// CreateUserRoleSqlite contains SQL to create HANSIP_USER_ROLE table
	CreateUserRoleSqlite = `CREATE TABLE IF NOT EXISTS HANSIP_USER_ROLE (
    USER_REC_ID VARCHAR(32) NOT NULL,
    ROLE_REC_ID VARCHAR(32) NOT NULL,
    PRIMARY KEY (USER_REC_ID,ROLE_REC_ID),
    FOREIGN KEY (USER_REC_ID) REFERENCES HANSIP_USER(REC_ID) ON DELETE CASCADE,
    FOREIGN KEY (ROLE_REC_ID) REFERENCES HANSIP_ROLE(REC_ID) ON DELETE CASCADE
)`
	// CreateUserGroupSqlite contains SQL to create HANSIP_USER_GROUP
	CreateUserGroupSqlite = `CREATE TABLE IF NOT EXISTS HANSIP_USER_GROUP (
    USER_REC_ID VARCHAR(32) NOT NULL,
    GROUP_REC_ID VARCHAR(32) NOT NULL,
    PRIMARY KEY (USER_REC_ID,GROUP_REC_ID),
    FOREIGN KEY (USER_REC_ID) REFERENCES HANSIP_USER(REC_ID) ON DELETE CASCADE,
    FOREIGN KEY (GROUP_REC_ID) REFERENCES HANSIP_GROUP(REC_ID) ON DELETE CASCADE
)`
	// CreateGroupRoleSqlite contains SQL to create HANSIP_GROUP_ROLE table
	CreateGroupRoleSqlite = `CREATE TABLE IF NOT EXISTS HANSIP_GROUP_ROLE (
    GROUP_REC_ID VARCHAR(32) NOT NULL,
    ROLE_REC_ID VARCHAR(32) NOT NULL,
    PRIMARY KEY (GROUP_REC_ID,ROLE_REC_ID),
    FOREIGN KEY (GROUP_REC_ID) REFERENCES HANSIP_GROUP(REC_ID) ON DELETE CASCADE,
    FOREIGN KEY (ROLE_REC_ID) REFERENCES HANSIP_ROLE(REC_ID) ON DELETE CASCADE
)`
	// CreateTOTPRecoveryCodeSqlite contains SQL to create HANSIP_TOTP_RECOVERY_CODES table
	CreateTOTPRecoveryCodeSqlite = `CREATE TABLE IF NOT EXISTS HANSIP_TOTP_RECOVERY_CODES (
    REC_ID VARCHAR(32) NOT NULL,
    RECOVERY_CODE VARCHAR(8) NOT NULL,
    USED_FLAG BOOLEAN DEFAULT 0,
    USER_REC_ID VARCHAR(32) NOT NULL,
    PRIMARY KEY (REC_ID),
    FOREIGN KEY (USER_REC_ID) REFERENCES HANSIP_USER(REC_ID) ON DELETE CASCADE
)`
	// CreateRevocationSqlite contains SQL to create HANSIP_REVOCATION table
	CreateRevocationSqlite = `CREATE TABLE IF NOT EXISTS HANSIP_REVOCATION (
    SUBJECT VARCHAR(128) NOT NULL UNIQUE,
    ACTIVATION_DATE DATETIME,
    PRIMARY KEY (SUBJECT)
)`
)

var (
	sqliteLog        = log.WithField("go", "SqliteDbConnector")
	sqliteDBInstance *SqliteDB
)

// GetSqliteDBInstance will obtain the singleton instance to SqliteDB
func GetSqliteDBInstance() *SqliteDB {
	if sqliteDBInstance == nil {
		db, err := sql.Open("sqlite3", "file::memory:?cache=shared")
		if err != nil {
			sqliteLog.WithField("func", "GetSqliteDBInstance").Fatalf("sql.Open got %s", err.Error())
		}

		//		db.SetMaxOpenConns(config.GetInt("db.pool.maxopen"))
		db.SetMaxOpenConns(1)
		//db.SetMaxIdleConns(config.GetInt("db.pool.maxidle"))

		timedCtx, closer := context.WithTimeout(context.Background(), 10*time.Second)
		defer func() {
			if timedCtx.Err() == nil {
				closer()
			}
		}()

		sqliteDBInstance = &SqliteDB{
			instance: db,
		}
		err = sqliteDBInstance.InitDB(timedCtx)
		if err != nil {
			sqliteLog.WithField("func", "GetSqliteDBInstance").Fatalf("sqliteDBInstance.InitDB got %s", err.Error())
		}
	}
	return sqliteDBInstance
}

// SqliteDB is a struct to hold sql.DB pointer
type SqliteDB struct {
	instance *sql.DB
}

// InitDB will initialize this connector.
func (db *SqliteDB) InitDB(ctx context.Context) error {
	fLog := sqliteLog.WithField("func", "InitDB")

	fLog.Infof("Checking table HANSIP_TENANT")
	exist, err := db.isTableExist(ctx, "HANSIP_TENANT")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_TENANT")
		_, err := db.instance.ExecContext(ctx, CreateTenantSqlite)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_TENANT Got %s. SQL = %s", err.Error(), CreateTenantSqlite)
		}
	}

	fLog.Infof("Checking table HANSIP_USER")
	exist, err = db.isTableExist(ctx, "HANSIP_USER")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_USER")
		_, err := db.instance.ExecContext(ctx, CreateUserSqlite)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_USER Got %s. SQL = %s", err.Error(), CreateUserSqlite)
		}
	}

	fLog.Infof("Checking table HANSIP_GROUP")
	exist, err = db.isTableExist(ctx, "HANSIP_GROUP")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_GROUP")
		_, err := db.instance.ExecContext(ctx, CreateGroupSqlite)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_GROUP Got %s. SQL = %s", err.Error(), CreateGroupSqlite)
		}
	}

	fLog.Infof("Checking table HANSIP_ROLE")
	exist, err = db.isTableExist(ctx, "HANSIP_ROLE")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_ROLE")
		_, err := db.instance.ExecContext(ctx, CreateRoleSqlite)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_ROLE Got %s. SQL = %s", err.Error(), CreateRoleSqlite)
		}
	}

	fLog.Infof("Checking table HANSIP_USER_ROLE")
	exist, err = db.isTableExist(ctx, "HANSIP_USER_ROLE")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_USER_ROLE")
		_, err := db.instance.ExecContext(ctx, CreateUserRoleSqlite)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_USER_ROLE Got %s. SQL = %s", err.Error(), CreateUserRoleSqlite)
		}
	}

	fLog.Infof("Checking table HANSIP_USER_GROUP")
	exist, err = db.isTableExist(ctx, "HANSIP_USER_GROUP")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_USER_GROUP")
		_, err := db.instance.ExecContext(ctx, CreateUserGroupSqlite)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_USER_GROUP Got %s. SQL = %s", err.Error(), CreateUserGroupSqlite)
		}
	}

	fLog.Infof("Checking table HANSIP_GROUP_ROLE")
	exist, err = db.isTableExist(ctx, "HANSIP_GROUP_ROLE")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_GROUP_ROLE")
		_, err := db.instance.ExecContext(ctx, CreateGroupRoleSqlite)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_GROUP_ROLE Got %s. SQL = %s", err.Error(), CreateGroupRoleSqlite)
		}
	}

	fLog.Infof("Checking table HANSIP_TOTP_RECOVERY_CODES")
	exist, err = db.isTableExist(ctx, "HANSIP_TOTP_RECOVERY_CODES")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_TOTP_RECOVERY_CODES")
		_, err := db.instance.ExecContext(ctx, CreateTOTPRecoveryCodeSqlite)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_TOTP_RECOVERY_CODES Got %s. SQL = %s", err.Error(), CreateTOTPRecoveryCodeSqlite)
		}
	}

	fLog.Infof("Checking table HANSIP_REVOCATION")
	exist, err = db.isTableExist(ctx, "HANSIP_REVOCATION")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_REVOCATION")
		_, err := db.instance.ExecContext(ctx, CreateRevocationSqlite)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_REVOCATION Got %s. SQL = %s", err.Error(), CreateRevocationSqlite)
		}
	}

	hansipDomain := config.Get("hansip.domain")
	handipAdmin := config.Get("hansip.admin")

	// Create built-in tenant.
	fLog.Infof("Checking built-in tenant")
	tenant, err := db.GetTenantByDomain(ctx, hansipDomain)
	if err == nil && tenant == nil {
		fLog.Infof("Creating built-in tenant")
		_, err = db.CreateTenantRecord(ctx, "Hansip System", "hansip", "Hansip built in tenant")
		if err != nil {
			fLog.Errorf("db.CreateTenantRecord Got %s", err.Error())
		}
	}

	// Create built-in group
	fLog.Infof("Checking built-in group")
	group, err := db.GetGroupByName(ctx, "admins", hansipDomain)
	if err == nil && group == nil {
		fLog.Infof("Creating built-in group")
		group, err = db.CreateGroup(ctx, "admins", hansipDomain, "Hansip built in group")
		if err != nil {
			fLog.Errorf(" db.CreateGroup Got %s", err.Error())
		}
	}

	// Create built-in roles
	fLog.Infof("Checking built-in roles")
	role, err := db.GetRoleByName(ctx, handipAdmin, hansipDomain)
	if err == nil && role == nil {
		fLog.Infof("Create built-in roles")
		role, err = db.CreateRole(ctx, handipAdmin, hansipDomain, "Hansip admin role")
		if err != nil {
			fLog.Errorf("db.CreateRole Got %s", err.Error())
		}
	}

	// Adding role into group
	fLog.Infof("Making sure built-in group contains built-in role")
	gr, err := db.GetGroupRole(ctx, group, role)
	if err == nil || gr == nil {
		fLog.Infof("Adding built-in role to built-in group")
		_, err := db.CreateGroupRole(ctx, group, role)
		if err != nil {
			fLog.Errorf("db.CreateGroupRole Got %s", err.Error())
		}
	}

	// Create setup user
	fLog.Infof("Checking setup user")
	user, err := db.GetUserByEmail(ctx, "setup@hansip")
	if err == nil && user == nil {
		fLog.Warnf("Creating setup user. This setup user must be disabled in production. Setup user passphrase is `this user must be disabled on production`")
		user, err = db.CreateUserRecord(ctx, "setup@hansip", "this user must be disabled on production")
		if err != nil {
			fLog.Errorf("db.CreateRole Got %s", err.Error())
		} else {
			if !user.Enabled {
				fLog.Infof("Enabling setup user")
				user.Enabled = true
				err = db.UpdateUser(ctx, user)
				if err != nil {
					fLog.Errorf("db.UpdateUser Got %s", err.Error())
				}
			}
		}
	}

	// Create setup user
	fLog.Infof("Make sure that setup user is in built-in group")
	ug, err := db.GetUserGroup(ctx, user, group)
	if err == nil || ug == nil {
		fLog.Infof("Adding setup user to built-in group")
		_, err = db.CreateUserGroup(ctx, user, group)
		if err != nil {
			fLog.Errorf("db.CreateUserGroup Got %s", err.Error())
		}
	}

	return nil
}

func (db *SqliteDB) isTableExist(ctx context.Context, tableName string) (bool, error) {
	fLog := sqliteLog.WithField("func", "isTableExist")
	q := "SELECT COUNT(*) AS CNT FROM sqlite_master WHERE type='table' AND name=?;"
	rows, err := db.instance.QueryContext(ctx, q, tableName)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return false, &ErrDBQueryError{
			Wrapped: err,
			Message: "db.instance.QueryContext returns error",
			SQL:     q,
		}
	}
	defer rows.Close()
	if rows.Next() {
		count := 0
		err := rows.Scan(&count)
		if err != nil {
			return false, &ErrDBScanError{
				Wrapped: err,
				Message: "rows.Scan returns error",
				SQL:     q,
			}
		}
		return count > 0, nil
	}
	return false, err
}

// DropAllTables will drop all tables used by Hansip
func (db *SqliteDB) DropAllTables(ctx context.Context) error {
	_, err := db.instance.ExecContext(ctx, DropAllSqlite)
	if err != nil {
		sqliteLog.WithField("func", "DropAllTables").WithField("RequestID", ctx.Value(constants.RequestID)).Errorf("got %s, SQL = %s", err.Error(), DropAllSqlite)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error while trying to drop all table",
			SQL:     DropAllSqlite,
		}
	}
	return nil
}

// CreateAllTable creates all table used by Hansip
func (db *SqliteDB) CreateAllTable(ctx context.Context) error {
	fLog := sqliteLog.WithField("func", "CreateAllTable").WithField("RequestID", ctx.Value(constants.RequestID))

	hansipDomain := config.Get("hansip.domain")
	hansipAdmin := config.Get("hansip.admin")

	_, err := db.instance.ExecContext(ctx, CreateTenantSqlite)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_TENANT Got %s. SQL = %s", err.Error(), CreateTenantSqlite)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error while trying to create table HANSIP_TENANT",
			SQL:     CreateTenantSqlite,
		}
	}
	_, err = db.CreateTenantRecord(ctx, "Hansip System", "hansip", "Hansip built in tenant")
	if err != nil {
		fLog.Errorf("db.CreateTenantRecord Got %s", err.Error())
		return err
	}
	_, err = db.instance.ExecContext(ctx, CreateUserSqlite)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_USER Got %s. SQL = %s", err.Error(), CreateUserSqlite)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error while trying to create table HANSIP_USER",
			SQL:     CreateUserSqlite,
		}
	}
	_, err = db.instance.ExecContext(ctx, CreateGroupSqlite)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_GROUP Got %s. SQL = %s", err.Error(), CreateGroupSqlite)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error while trying to create table HANSIP_GROUP",
			SQL:     CreateGroupSqlite,
		}
	}
	_, err = db.instance.ExecContext(ctx, CreateRoleSqlite)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_ROLE Got %s. SQL = %s", err.Error(), CreateRoleSqlite)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error while trying to create table HANSIP_ROLE",
			SQL:     CreateRoleSqlite,
		}
	}
	_, err = db.instance.ExecContext(ctx, CreateUserRoleSqlite)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_USER_ROLE Got %s. SQL = %s", err.Error(), CreateUserRoleSqlite)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error while trying to create table HANSIP_USER_ROLE",
			SQL:     CreateUserRoleSqlite,
		}
	}
	_, err = db.instance.ExecContext(ctx, CreateUserGroupSqlite)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_USER_GROUP Got %s. SQL = %s", err.Error(), CreateUserGroupSqlite)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error while trying to create table HANSIP_USER_GROUP",
			SQL:     CreateUserGroupSqlite,
		}
	}
	_, err = db.instance.ExecContext(ctx, CreateGroupRoleSqlite)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_GROUP_ROLE Got %s. SQL = %s", err.Error(), CreateGroupRoleSqlite)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error while trying to create table HANSIP_GROUP_ROLE",
			SQL:     CreateGroupRoleSqlite,
		}
	}
	_, err = db.instance.ExecContext(ctx, CreateTOTPRecoveryCodeSqlite)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_TOTP_RECOVERY_CODES Got %s. SQL = %s", err.Error(), CreateTOTPRecoveryCodeSqlite)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error while trying to create table HANSIP_TOTP_RECOVERY_CODES",
			SQL:     CreateTOTPRecoveryCodeSqlite,
		}
	}
	_, err = db.instance.ExecContext(ctx, CreateRevocationSqlite)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_REVOCATION Got %s. SQL = %s", err.Error(), CreateRevocationSqlite)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error while trying to create table HANSIP_REVOCATION",
			SQL:     CreateRevocationSqlite,
		}
	}
	_, err = db.CreateRole(ctx, hansipAdmin, hansipDomain, "Administrator role")
	if err != nil {
		fLog.Errorf("db.CreateRole Got %s", err.Error())
		return err
	}
	return nil
}

// GetTenantByDomain return a tenant record
func (db *SqliteDB) GetTenantByDomain(ctx context.Context, tenantDomain string) (*Tenant, error) {
	fLog := sqliteLog.WithField("func", "GetTenantByDomain").WithField("RequestID", ctx.Value(constants.RequestID))
	tenant := &Tenant{}
	q := "SELECT REC_ID, TENANT_NAME,TENANT_DOMAIN,DESCRIPTION FROM HANSIP_TENANT WHERE TENANT_DOMAIN = ?"
	row := db.instance.QueryRowContext(ctx, q, tenantDomain)
	err := row.Scan(&tenant.RecID, &tenant.Name, &tenant.Domain, &tenant.Description)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		fLog.Errorf("row.Scan got %s", err.Error())
		return nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error GetTenantByDomain",
			SQL:     q,
		}
	}
	return tenant, nil
}

// GetTenantByRecID return a tenant record
func (db *SqliteDB) GetTenantByRecID(ctx context.Context, recID string) (*Tenant, error) {
	fLog := sqliteLog.WithField("func", "GetTenantByRecID").WithField("RequestID", ctx.Value(constants.RequestID))
	tenant := &Tenant{}
	q := "SELECT REC_ID, TENANT_NAME,TENANT_DOMAIN,DESCRIPTION FROM HANSIP_TENANT WHERE REC_ID = ?"
	row := db.instance.QueryRowContext(ctx, q, recID)
	err := row.Scan(&tenant.RecID, &tenant.Name, &tenant.Domain, &tenant.Description)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		fLog.Errorf("row.Scan got %s", err.Error())
		return nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error GetTenantByRecID",
			SQL:     q,
		}
	}
	return tenant, nil
}

// CreateTenantRecord Create new tenant
func (db *SqliteDB) CreateTenantRecord(ctx context.Context, tenantName, tenantDomain, description string) (*Tenant, error) {
	fLog := sqliteLog.WithField("func", "CreateTenantRecord").WithField("RequestID", ctx.Value(constants.RequestID))
	tenant := &Tenant{
		RecID:       helper.MakeRandomString(10, true, true, true, false),
		Name:        tenantName,
		Domain:      tenantDomain,
		Description: description,
	}

	q := "INSERT INTO HANSIP_TENANT(REC_ID,TENANT_NAME, TENANT_DOMAIN, DESCRIPTION) VALUES(?,?,?,?)"

	_, err := db.instance.ExecContext(ctx, q,
		tenant.RecID, tenant.Name, tenant.Domain, tenant.Description)

	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return nil, &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error CreateTenantRecord",
			SQL:     q,
		}
	}

	return tenant, nil
}

// DeleteTenant removes a tenant entity from table
func (db *SqliteDB) DeleteTenant(ctx context.Context, tenant *Tenant) error {
	fLog := sqliteLog.WithField("func", "DeleteTenant").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "DELETE FROM HANSIP_TENANT WHERE REC_ID=?"
	_, err := db.instance.ExecContext(ctx, q, tenant.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteTenant",
			SQL:     q,
		}
	}

	domainToDelete := tenant.Domain

	// delete all user-roles ...
	q = "DELETE FROM HANSIP_USER_ROLE WHERE HANSIP_USER_ROLE.ROLE_REC_ID = HANSIP_ROLE.REC_ID AND HANSIP_ROLE.ROLE_DOMAIN = ?"
	_, err = db.instance.ExecContext(ctx, q, domainToDelete)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteTenant",
			SQL:     q,
		}
	}

	// delete all group-roles ...
	q = "DELETE FROM HANSIP_GROUP_ROLE WHERE HANSIP_GROUP_ROLE.GROUP_REC_ID = HANSIP_GROUP.REC_ID AND HANSIP_GROUP.GROUP_DOMAIN = ?"
	_, err = db.instance.ExecContext(ctx, q, domainToDelete)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteTenant",
			SQL:     q,
		}
	}

	// delete all user-groups ...
	q = "DELETE FROM HANSIP_USER_GROUP WHERE HANSIP_USER_GROUP.GROUP_REC_ID = HANSIP_GROUP.REC_ID AND HANSIP_GROUP.GROUP_DOMAIN = ?"
	_, err = db.instance.ExecContext(ctx, q, domainToDelete)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteTenant",
			SQL:     q,
		}
	}

	// delete all groups ...
	q = "DELETE FROM HANSIP_GROUP WHERE HANSIP_GROUP.GROUP_DOMAIN = ?"
	_, err = db.instance.ExecContext(ctx, q, domainToDelete)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteTenant",
			SQL:     q,
		}
	}

	// delete all roles ...
	q = "DELETE FROM HANSIP_ROLE WHERE HANSIP_ROLE.ROLE_DOMAIN = ?"
	_, err = db.instance.ExecContext(ctx, q, domainToDelete)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteTenant",
			SQL:     q,
		}
	}

	return err
}

// UpdateTenant a tenant entity into table tenant
func (db *SqliteDB) UpdateTenant(ctx context.Context, tenant *Tenant) error {
	fLog := sqliteLog.WithField("func", "UpdateTenant").WithField("RequestID", ctx.Value(constants.RequestID))

	exist, err := db.IsTenantRecIDExist(ctx, tenant.RecID)
	if err != nil {
		return err
	}
	if !exist {
		return ErrNotFound
	}

	origin, err := db.GetTenantByRecID(ctx, tenant.RecID)
	if err != nil {
		return err
	}
	domainChanged := origin.Domain != tenant.Domain

	q := "UPDATE HANSIP_TENANT SET TENANT_NAME=?, TENANT_DOMAIN=?, DESCRIPTION=? WHERE REC_ID=?"
	_, err = db.instance.ExecContext(ctx, q,
		tenant.Name, tenant.Domain, tenant.Description, tenant.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error UpdateTenant",
			SQL:     q,
		}
	}

	if domainChanged {
		q = "UPDATE HANSIP_ROLE SET ROLE_DOMAIN=? WHERE ROLE_DOMAIN=?"
		_, err = db.instance.ExecContext(ctx, q,
			tenant.Domain, origin.Domain)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext got  %s. SQL = %s", err.Error(), q)
			return &ErrDBExecuteError{
				Wrapped: err,
				Message: "Error UpdateTenant",
				SQL:     q,
			}
		}

		q = "UPDATE HANSIP_GROUP SET GROUP_DOMAIN=? WHERE GROUP_DOMAIN=?"
		_, err = db.instance.ExecContext(ctx, q,
			tenant.Domain, origin.Domain)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext got  %s. SQL = %s", err.Error(), q)
			return &ErrDBExecuteError{
				Wrapped: err,
				Message: "Error UpdateTenant",
				SQL:     q,
			}
		}
	}

	return nil
}

// IsUserRecIDExist check if a specific user recId is exist in database
func (db *SqliteDB) IsTenantRecIDExist(ctx context.Context, recID string) (bool, error) {
	fLog := sqliteLog.WithField("func", "IsTenantRecIDExist").WithField("RequestID", ctx.Value(constants.RequestID))

	q := "SELECT COUNT(*) AS CNT FROM HANSIP_TENANT WHERE REC_ID=?"

	rows, err := db.instance.QueryContext(ctx, q, recID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return false, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error IsTenantRecIDExist",
			SQL:     q,
		}
	}
	defer rows.Close()
	if rows.Next() {
		count := 0
		err := rows.Scan(&count)
		if err != nil {
			fLog.Errorf("db.instance.IsTenantRecIDExist cant scan")
			return false, &ErrDBScanError{
				Wrapped: err,
				Message: "Error IsTenantRecIDExist",
				SQL:     q,
			}
		}
		return count > 0, nil
	}
	return false, nil
}

// ListTenant from database with pagination
func (db *SqliteDB) ListTenant(ctx context.Context, request *helper.PageRequest) ([]*Tenant, *helper.Page, error) {
	fLog := sqliteLog.WithField("func", "GetUserByRecID").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) AS CNT FROM HANSIP_TENANT"
	ret := make([]*Tenant, 0)
	row := db.instance.QueryRowContext(ctx, q)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return ret, helper.NewPage(request, uint(count)), nil
		}
		fLog.Errorf("db.instance.QueryRowContext got  %s", err.Error())
		return nil, nil, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error ListTenant",
			SQL:     q,
		}
	}
	page := helper.NewPage(request, uint(count))
	q = fmt.Sprintf("SELECT REC_ID, TENANT_NAME, TENANT_DOMAIN, DESCRIPTION FROM HANSIP_TENANT ORDER BY TENANT_NAME %s LIMIT %d, %d", request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	rows, err := db.instance.QueryContext(ctx, q)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s. SQL = %s", err.Error(), q)
		return nil, nil, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error ListTenant",
			SQL:     q,
		}
	}
	defer rows.Close()
	for rows.Next() {
		t := &Tenant{}
		err := rows.Scan(&t.RecID, &t.Name, &t.Domain, &t.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
			return nil, nil, &ErrDBScanError{
				Wrapped: err,
				Message: "Error ListTenant",
				SQL:     q,
			}
		} else {
			ret = append(ret, t)
		}
	}
	return ret, page, nil
}

var (
	coreEpoch = time.Date(2001, time.January, 1, 0, 0, 0, 0, time.UTC)
)

// GetUserByRecID get user data by its RecID
func (db *SqliteDB) GetUserByRecID(ctx context.Context, recID string) (*User, error) {
	fLog := sqliteLog.WithField("func", "GetUserByRecID").WithField("RequestID", ctx.Value(constants.RequestID))
	user := &User{}
	var enabled, suspended, enable2fa int
	var lastSeen, lastLogin, activationDate float64
	q := "SELECT REC_ID, EMAIL,HASHED_PASSPHRASE,ENABLED, SUSPENDED,LAST_SEEN,LAST_LOGIN,FAIL_COUNT,ACTIVATION_CODE,ACTIVATION_DATE,TOTP_KEY,ENABLE_2FE,TOKEN_2FE,RECOVERY_CODE FROM HANSIP_USER WHERE REC_ID = ?"
	row := db.instance.QueryRowContext(ctx, q, recID)
	err := row.Scan(&user.RecID, &user.Email, &user.HashedPassphrase, &enabled, &suspended, &lastSeen, &lastLogin, &user.FailCount, &user.ActivationCode,
		&activationDate, &user.UserTotpSecretKey, &enable2fa, &user.Token2FA, &user.RecoveryCode)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		fLog.Errorf("row.Scan got %s", err.Error())
		return nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error GetUserByRecID",
			SQL:     q,
		}
	}
	user.LastSeen = coreEpoch.Add(time.Duration(lastSeen * float64(time.Second)))
	user.LastLogin = coreEpoch.Add(time.Duration(lastLogin * float64(time.Second)))
	user.ActivationDate = coreEpoch.Add(time.Duration(activationDate * float64(time.Second)))
	if enabled == 1 {
		user.Enabled = true
	}
	if suspended == 1 {
		user.Suspended = true
	}
	if enable2fa == 1 {
		user.Enable2FactorAuth = true
	}
	return user, nil
}

// CreateUserRecord create a new user
func (db *SqliteDB) CreateUserRecord(ctx context.Context, email, passphrase string) (*User, error) {
	fLog := sqliteLog.WithField("func", "CreateUserRecord").WithField("RequestID", ctx.Value(constants.RequestID))
	bytes, err := bcrypt.GenerateFromPassword([]byte(passphrase), 14)
	if err != nil {
		fLog.Errorf("bcrypt.GenerateFromPassword got %s", err.Error())
		return nil, &ErrLibraryCallError{
			Wrapped:     err,
			Message:     "Error CreateUserRecord",
			LibraryName: "bcrypt",
		}
	}
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
		UserTotpSecretKey: totp.MakeSecret().Base32(),
		Token2FA:          helper.MakeRandomString(6, true, false, false, false),
		RecoveryCode:      helper.MakeRandomString(6, true, false, false, false),
	}

	q := "INSERT INTO HANSIP_USER(REC_ID,EMAIL,HASHED_PASSPHRASE,ENABLED, SUSPENDED,LAST_SEEN,LAST_LOGIN,FAIL_COUNT,ACTIVATION_CODE,ACTIVATION_DATE,TOTP_KEY,ENABLE_2FE,TOKEN_2FE,RECOVERY_CODE) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"

	_, err = db.instance.ExecContext(ctx, q,
		user.RecID, user.Email, user.HashedPassphrase, 0, 0, user.LastSeen, user.LastLogin, user.FailCount, user.ActivationCode,
		user.ActivationDate, user.UserTotpSecretKey, user.Enable2FactorAuth, user.Token2FA, user.RecoveryCode)

	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return nil, &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error CreateUserRecord",
			SQL:     q,
		}
	}

	return user, nil
}

// GetTOTPRecoveryCodes retrieves all valid/not used TOTP recovery codes.
func (db *SqliteDB) GetTOTPRecoveryCodes(ctx context.Context, user *User) ([]string, error) {
	fLog := sqliteLog.WithField("func", "GetTOTPRecoveryCodes").WithField("RequestID", ctx.Value(constants.RequestID))

	ret := make([]string, 0)
	q := "SELECT RECOVERY_CODE FROM HANSIP_TOTP_RECOVERY_CODES WHERE USER_REC_ID = ? && USED_FLAG = ?"
	rows, err := db.instance.QueryContext(ctx, q, user.RecID, 0)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got %s. SQL = %s", err.Error(), q)
		return nil, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error GetTOTPRecoveryCodes",
			SQL:     q,
		}
	}
	defer rows.Close()
	for rows.Next() {
		code := ""
		err = rows.Scan(&code)
		if err != nil {
			fLog.Errorf("rows.Scan got %s", err.Error())
			return nil, &ErrDBScanError{
				Wrapped: err,
				Message: "Error GetTOTPRecoveryCodes",
				SQL:     q,
			}
		} else {
			ret = append(ret, code)
		}
	}
	return ret, nil
}

// RecreateTOTPRecoveryCodes recreates 16 new recovery codes.
func (db *SqliteDB) RecreateTOTPRecoveryCodes(ctx context.Context, user *User) ([]string, error) {
	fLog := sqliteLog.WithField("func", "RecreateTOTPRecoveryCodes").WithField("RequestID", ctx.Value(constants.RequestID))

	// first we clear out all existing codes.
	q := "DELETE FROM HANSIP_TOTP_RECOVERY_CODES WHERE USER_REC_ID = ?"
	_, err := db.instance.ExecContext(ctx, q, user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return nil, &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error RecreateTOTPRecoveryCodes",
			SQL:     q,
		}
	}

	// Now lets recreate all new records.
	ret := make([]string, 0)
	for i := 0; i < 16; i++ {
		recID := helper.MakeRandomString(10, true, true, true, false)
		code := helper.MakeRandomString(8, true, false, true, false)
		q = "INSERT INTO HANSIP_TOTP_RECOVERY_CODES(REC_ID, RECOVERY_CODE, USED_FLAG, USER_REC_ID) VALUES (?,?,?,?)"
		_, err := db.instance.ExecContext(ctx, q, recID, code, 0, user.RecID)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
			return nil, &ErrDBExecuteError{
				Wrapped: err,
				Message: "Error RecreateTOTPRecoveryCodes",
				SQL:     q,
			}
		} else {
			ret = append(ret, code)
		}
	}
	return ret, nil
}

// MarkTOTPRecoveryCodeUsed will mark the specific recovery code as used and thus can not be used anymore.
func (db *SqliteDB) MarkTOTPRecoveryCodeUsed(ctx context.Context, user *User, code string) error {
	fLog := sqliteLog.WithField("func", "MarkTOTPRecoveryCodeUsed").WithField("RequestID", ctx.Value(constants.RequestID))

	rexp := regexp.MustCompile(`^[A-Z0-9]{8}$`)
	if rexp.Match([]byte(code)) {
		q := "UPDATE HANSIP_TOTP_RECOVERY_CODES SET USED_FLAG = ? WHERE USER_REC_ID = ? AND RECOVERY_CODE=?"
		_, err := db.instance.ExecContext(ctx, q, 1, user.RecID, code)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
			return &ErrDBExecuteError{
				Wrapped: err,
				Message: "Error MarkTOTPRecoveryCodeUsed",
				SQL:     q,
			}
		}
		return nil
	}
	fLog.Warnf("Invalid Code format. expect 8 digit contains capital Alphabet and number only. But %s", code)
	return nil
}

// GetUserByEmail get user record by its email address
func (db *SqliteDB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	fLog := sqliteLog.WithField("func", "GetUserByEmail").WithField("RequestID", ctx.Value(constants.RequestID))
	user := &User{}
	var enabled, suspended, enable2fa int
	var lastSeen, lastLogin, activationDate float64
	q := "SELECT REC_ID, EMAIL,HASHED_PASSPHRASE,ENABLED, SUSPENDED,LAST_SEEN,LAST_LOGIN,FAIL_COUNT,ACTIVATION_CODE,ACTIVATION_DATE,TOTP_KEY,ENABLE_2FE,TOKEN_2FE,RECOVERY_CODE FROM HANSIP_USER WHERE EMAIL = ?"
	row := db.instance.QueryRowContext(ctx, q, email)
	err := row.Scan(&user.RecID, &user.Email, &user.HashedPassphrase, &enabled, &suspended, &lastSeen, &lastLogin, &user.FailCount, &user.ActivationCode,
		&activationDate, &user.UserTotpSecretKey, &enable2fa, &user.Token2FA, &user.RecoveryCode)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		fLog.Errorf("row.Scan got %s", err.Error())
		return nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error GetUserByEmail",
			SQL:     "",
		}
	}
	user.LastSeen = coreEpoch.Add(time.Duration(lastSeen * float64(time.Second)))
	user.LastLogin = coreEpoch.Add(time.Duration(lastLogin * float64(time.Second)))
	user.ActivationDate = coreEpoch.Add(time.Duration(activationDate * float64(time.Second)))
	if enabled == 1 {
		user.Enabled = true
	}
	if suspended == 1 {
		user.Suspended = true
	}
	if enable2fa == 1 {
		user.Enable2FactorAuth = true
	}
	return user, nil
}

// GetUserBy2FAToken get a user by its 2FA token
func (db *SqliteDB) GetUserBy2FAToken(ctx context.Context, token string) (*User, error) {
	fLog := sqliteLog.WithField("func", "GetUserBy2FAToken").WithField("RequestID", ctx.Value(constants.RequestID))
	user := &User{}
	var enabled, suspended, enable2fa int
	var lastSeen, lastLogin, activationDate float64
	q := "SELECT REC_ID, EMAIL,HASHED_PASSPHRASE,ENABLED, SUSPENDED,LAST_SEEN,LAST_LOGIN,FAIL_COUNT,ACTIVATION_CODE,ACTIVATION_DATE,TOTP_KEY,ENABLE_2FE,TOKEN_2FE,RECOVERY_CODE FROM HANSIP_USER WHERE TOKEN_2FE = ?"
	row := db.instance.QueryRowContext(ctx, q, token)
	err := row.Scan(&user.RecID, &user.Email, &user.HashedPassphrase, &enabled, &suspended, &lastSeen, &lastLogin, &user.FailCount, &user.ActivationCode,
		&activationDate, &user.UserTotpSecretKey, &enable2fa, &user.Token2FA, &user.RecoveryCode)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		fLog.Errorf("row.Scan got %s", err.Error())
		return nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error GetUserBy2FAToken",
			SQL:     q,
		}
	}
	user.LastSeen = coreEpoch.Add(time.Duration(lastSeen * float64(time.Second)))
	user.LastLogin = coreEpoch.Add(time.Duration(lastLogin * float64(time.Second)))
	user.ActivationDate = coreEpoch.Add(time.Duration(activationDate * float64(time.Second)))
	if enabled == 1 {
		user.Enabled = true
	}
	if suspended == 1 {
		user.Suspended = true
	}
	if enable2fa == 1 {
		user.Enable2FactorAuth = true
	}
	return user, nil
}

// GetUserByRecoveryToken get a user by its recovery token
func (db *SqliteDB) GetUserByRecoveryToken(ctx context.Context, token string) (*User, error) {
	fLog := sqliteLog.WithField("func", "GetUserByRecoveryToken").WithField("RequestID", ctx.Value(constants.RequestID))
	user := &User{}
	var enabled, suspended, enable2fa int
	var lastSeen, lastLogin, activationDate float64
	q := "SELECT REC_ID, EMAIL,HASHED_PASSPHRASE,ENABLED, SUSPENDED,LAST_SEEN,LAST_LOGIN,FAIL_COUNT,ACTIVATION_CODE,ACTIVATION_DATE,TOTP_KEY,ENABLE_2FE,TOKEN_2FE,RECOVERY_CODE FROM HANSIP_USER WHERE RECOVERY_CODE = ?"
	row := db.instance.QueryRowContext(ctx, q, token)
	err := row.Scan(&user.RecID, &user.Email, &user.HashedPassphrase, &enabled, &suspended, &lastSeen, &lastLogin, &user.FailCount, &user.ActivationCode,
		&activationDate, &user.UserTotpSecretKey, &enable2fa, &user.Token2FA, &user.RecoveryCode)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		fLog.Errorf("row.Scan got %s", err.Error())
		return nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error GetUserBy2FAToken",
			SQL:     q,
		}
	}
	user.LastSeen = coreEpoch.Add(time.Duration(lastSeen * float64(time.Second)))
	user.LastLogin = coreEpoch.Add(time.Duration(lastLogin * float64(time.Second)))
	user.ActivationDate = coreEpoch.Add(time.Duration(activationDate * float64(time.Second)))
	if enabled == 1 {
		user.Enabled = true
	}
	if suspended == 1 {
		user.Suspended = true
	}
	if enable2fa == 1 {
		user.Enable2FactorAuth = true
	}
	return user, nil
}

// DeleteUser delete a user
func (db *SqliteDB) DeleteUser(ctx context.Context, user *User) error {
	fLog := sqliteLog.WithField("func", "DeleteUser").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "DELETE FROM HANSIP_USER WHERE REC_ID=?"
	_, err := db.instance.ExecContext(ctx, q, user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteUser",
			SQL:     q,
		}
	}
	return nil
}

// IsUserRecIDExist check if a specific user recId is exist in database
func (db *SqliteDB) IsUserRecIDExist(ctx context.Context, recID string) (bool, error) {
	fLog := sqliteLog.WithField("func", "IsUserRecIDExist").WithField("RequestID", ctx.Value(constants.RequestID))

	q := "SELECT COUNT(*) AS CNT FROM HANSIP_USER WHERE REC_ID=?"

	rows, err := db.instance.QueryContext(ctx, q, recID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return false, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error IsUserRecIDExist",
			SQL:     q,
		}
	}
	defer rows.Close()
	if rows.Next() {
		count := 0
		err = rows.Scan(&count)
		if err != nil {
			fLog.Errorf("db.instance.IsUserRecIDExist cant scan")
			return false, &ErrDBScanError{
				Wrapped: err,
				Message: "Error IsUserRecIDExist",
				SQL:     q,
			}
		}
		return count > 0, nil
	}
	return false, nil
}

// UpdateUser save or update a user data
func (db *SqliteDB) UpdateUser(ctx context.Context, user *User) error {
	fLog := sqliteLog.WithField("func", "UpdateUser").WithField("RequestID", ctx.Value(constants.RequestID))
	exist, err := db.IsUserRecIDExist(ctx, user.RecID)
	if err != nil {
		fLog.Errorf("db.IsUserRecIDExist got %s", err.Error())
		return err
	}
	if !exist {
		return ErrNotFound
	}
	enabled := 0
	suspended := 0
	enable2fa := 0
	if user.Enabled {
		enabled = 1
	}
	if user.Suspended {
		suspended = 1
	}
	if user.Enable2FactorAuth {
		enable2fa = 1
	}

	q := "UPDATE HANSIP_USER SET EMAIL=?,HASHED_PASSPHRASE=?,ENABLED=?, SUSPENDED=?,LAST_SEEN=?,LAST_LOGIN=?,FAIL_COUNT=?,ACTIVATION_CODE=?,ACTIVATION_DATE=?,TOTP_KEY=?,ENABLE_2FE=?,TOKEN_2FE=?,RECOVERY_CODE=? WHERE REC_ID=?"

	fLog.Infof("Updating user %s", user.Email)
	_, err = db.instance.ExecContext(ctx, q,
		user.Email, user.HashedPassphrase, enabled, suspended, user.LastSeen, user.LastLogin, user.FailCount, user.ActivationCode,
		user.ActivationDate, user.UserTotpSecretKey, enable2fa, user.Token2FA, user.RecoveryCode, user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error UpdateUser",
			SQL:     q,
		}
	}
	return nil
}

// ListUser list all user paginated
func (db *SqliteDB) ListUser(ctx context.Context, request *helper.PageRequest) ([]*User, *helper.Page, error) {
	fLog := sqliteLog.WithField("func", "ListUser").WithField("RequestID", ctx.Value(constants.RequestID))
	count, err := db.Count(ctx)
	if err != nil {
		fLog.Errorf("db.Count got  %s", err.Error())
		return nil, nil, err
	}
	page := helper.NewPage(request, uint(count))
	userList := make([]*User, 0)
	q := fmt.Sprintf("SELECT REC_ID, EMAIL,HASHED_PASSPHRASE,ENABLED, SUSPENDED,LAST_SEEN,LAST_LOGIN,FAIL_COUNT,ACTIVATION_CODE,ACTIVATION_DATE,TOTP_KEY,ENABLE_2FE,TOKEN_2FE,RECOVERY_CODE FROM HANSIP_USER ORDER BY EMAIL %s LIMIT %d, %d", request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	rows, err := db.instance.QueryContext(ctx, q)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got %s. SQL = %s", err.Error(), q)
		return nil, nil, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error ListUser",
			SQL:     q,
		}
	}
	defer rows.Close()
	for rows.Next() {
		user := &User{}
		var enabled, suspended, enable2fa int
		var lastSeen, lastLogin, activationDate float64
		err := rows.Scan(&user.RecID, &user.Email, &user.HashedPassphrase, &enabled, &suspended, &lastSeen, &lastLogin, &user.FailCount, &user.ActivationCode,
			&activationDate, &user.UserTotpSecretKey, &enable2fa, &user.Token2FA, &user.RecoveryCode)
		if err != nil {
			fLog.Warnf("rows.Scan got %s", err.Error())
			return nil, nil, &ErrDBScanError{
				Wrapped: err,
				Message: "Error ListUser",
				SQL:     q,
			}
		} else {
			user.LastSeen = coreEpoch.Add(time.Duration(lastSeen * float64(time.Second)))
			user.LastLogin = coreEpoch.Add(time.Duration(lastLogin * float64(time.Second)))
			user.ActivationDate = coreEpoch.Add(time.Duration(activationDate * float64(time.Second)))
			if enabled == 1 {
				user.Enabled = true
			}
			if suspended == 1 {
				user.Suspended = true
			}
			if enable2fa == 1 {
				user.Enable2FactorAuth = true
			}
			userList = append(userList, user)
		}
	}
	return userList, page, nil
}

// Count all user
func (db *SqliteDB) Count(ctx context.Context) (int, error) {
	fLog := sqliteLog.WithField("func", "Count").WithField("RequestID", ctx.Value(constants.RequestID))
	count := 0
	q := "SELECT COUNT(*) as CNT FROM HANSIP_USER"
	err := db.instance.QueryRowContext(ctx, q).Scan(&count)
	if err != nil {
		fLog.Errorf("db.instance.QueryRowContext got %s", err.Error())
		return 0, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error Count",
			SQL:     q,
		}
	}
	return count, nil
}

// ListAllUserRoles list all user's roles direct and indirect
func (db *SqliteDB) ListAllUserRoles(ctx context.Context, user *User, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	fLog := sqliteLog.WithField("func", "ListAllUserRoles").WithField("RequestID", ctx.Value(constants.RequestID))
	roleMap := make(map[string]*Role)
	q := "SELECT R.REC_ID, R.ROLE_NAME, R.ROLE_DOMAIN, R.DESCRIPTION FROM HANSIP_ROLE R, HANSIP_USER_ROLE UR WHERE R.REC_ID = UR.ROLE_REC_ID AND UR.USER_REC_ID = ?"
	rows, err := db.instance.QueryContext(ctx, q, user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s. SQL = %s", err.Error(), q)
		return nil, nil, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error ListAllUserRoles",
			SQL:     q,
		}
	}
	for rows.Next() {
		r := &Role{}
		err = rows.Scan(&r.RecID, &r.RoleName, &r.RoleDomain, &r.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
			rows.Close()
			return nil, nil, &ErrDBScanError{
				Wrapped: err,
				Message: "Error ListAllUserRoles",
				SQL:     q,
			}
		} else {
			roleMap[r.RecID] = r
		}
	}
	rows.Close()
	q = "SELECT DISTINCT R.REC_ID, R.ROLE_NAME, R.ROLE_DOMAIN, R.DESCRIPTION FROM HANSIP_ROLE R, HANSIP_GROUP_ROLE GR, HANSIP_USER_GROUP UG WHERE R.REC_ID = GR.ROLE_REC_ID AND GR.GROUP_REC_ID = UG.GROUP_REC_ID AND UG.USER_REC_ID = ?"
	rows, err = db.instance.QueryContext(ctx, q, user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s. SQL = %s", err.Error(), q)
		return nil, nil, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error ListAllUserRoles",
			SQL:     q,
		}
	}
	defer rows.Close()
	for rows.Next() {
		r := &Role{}
		err = rows.Scan(&r.RecID, &r.RoleName, &r.RoleDomain, &r.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
			return nil, nil, &ErrDBScanError{
				Wrapped: err,
				Message: "Error ListAllUserRoles",
				SQL:     q,
			}
		} else {
			roleMap[r.RecID] = r
		}
	}

	page := helper.NewPage(request, uint(len(roleMap)))
	roles := make([]*Role, 0)
	for _, v := range roleMap {
		roles = append(roles, v)
	}
	if request.OrderBy == "ROLE_NAME" {
		if request.Sort == "ASC" {
			sort.SliceStable(roles, func(i, j int) bool {
				return roles[i].RoleName < roles[j].RoleName
			})
		} else {
			sort.SliceStable(roles, func(i, j int) bool {
				return roles[i].RoleName > roles[j].RoleName
			})
		}
	}
	return roles[page.OffsetStart:page.OffsetEnd], page, nil
}

// GetUserRole return user's assigned roles
func (db *SqliteDB) GetUserRole(ctx context.Context, user *User, role *Role) (*UserRole, error) {
	fLog := sqliteLog.WithField("func", "GetUserRole").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) CNT FROM HANSIP_USER_ROLE WHERE USER_REC_ID=? AND ROLE_REC_ID=?"
	row := db.instance.QueryRowContext(ctx, q, user.RecID, role.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error GetUserRole",
			SQL:     q,
		}
	}
	if count == 0 {
		return nil, &ErrDBNoResult{
			Message: fmt.Sprintf("role %s is not owned by user %s", role.RoleName, user.Email),
			SQL:     q,
		}
	}
	return &UserRole{
		UserRecID: user.RecID,
		RoleRecID: role.RecID,
	}, nil
}

// CreateUserRole assign a role to a user.
func (db *SqliteDB) CreateUserRole(ctx context.Context, user *User, role *Role) (*UserRole, error) {
	fLog := sqliteLog.WithField("func", "CreateUserRole").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "INSERT INTO HANSIP_USER_ROLE(USER_REC_ID, ROLE_REC_ID) VALUES (?,?)"
	_, err := db.instance.ExecContext(ctx, q, user.RecID, role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return nil, &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error CreateUserRole",
			SQL:     q,
		}
	}
	return &UserRole{
		UserRecID: user.RecID,
		RoleRecID: role.RecID,
	}, nil
}

// ListUserRoleByUser get all roles assigned to a user, paginated
func (db *SqliteDB) ListUserRoleByUser(ctx context.Context, user *User, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	fLog := sqliteLog.WithField("func", "ListUserRoleByUser").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) FROM HANSIP_USER_ROLE WHERE USER_REC_ID=?"
	ret := make([]*Role, 0)
	row := db.instance.QueryRowContext(ctx, q, user.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return ret, helper.NewPage(request, uint(count)), nil
		}
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error ListUserRoleByUser",
			SQL:     q,
		}
	}
	page := helper.NewPage(request, uint(count))
	q = fmt.Sprintf("SELECT R.REC_ID, R.ROLE_NAME, R.ROLE_DOMAIN, R.DESCRIPTION FROM HANSIP_USER_ROLE UR, HANSIP_ROLE R WHERE UR.ROLE_REC_ID = R.REC_ID AND UR.USER_REC_ID = ? ORDER BY R.ROLE_NAME %s LIMIT %d, %d", request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	rows, err := db.instance.QueryContext(ctx, q, user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s. SQL = %s", err.Error(), q)
		return nil, nil, &ErrDBQueryError{
			Wrapped: nil,
			Message: "Error ListUserRoleByUser",
			SQL:     q,
		}
	}
	defer rows.Close()
	for rows.Next() {
		r := &Role{}
		err := rows.Scan(&r.RecID, &r.RoleName, &r.RoleDomain, &r.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
			return nil, nil, &ErrDBScanError{
				Wrapped: err,
				Message: "Error ListUserRoleByUser",
				SQL:     q,
			}
		} else {
			ret = append(ret, r)
		}
	}
	return ret, page, nil
}

// ListUserRoleByRole list all user that related to a role
func (db *SqliteDB) ListUserRoleByRole(ctx context.Context, role *Role, request *helper.PageRequest) ([]*User, *helper.Page, error) {
	fLog := sqliteLog.WithField("func", "ListUserRoleByRole").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) FROM HANSIP_USER_ROLE WHERE ROLE_REC_ID=?"
	ret := make([]*User, 0)
	row := db.instance.QueryRowContext(ctx, q, role.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return ret, helper.NewPage(request, uint(count)), nil
		}
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error ListUserRoleByRole",
			SQL:     q,
		}
	}
	page := helper.NewPage(request, uint(count))
	q = fmt.Sprintf("SELECT R.REC_ID,R.EMAIL,R.HASHED_PASSPHRASE,R.ENABLED, R.SUSPENDED,R.LAST_SEEN,R.LAST_LOGIN,R.FAIL_COUNT,R.ACTIVATION_CODE,R.ACTIVATION_DATE,R.TOTP_KEY,R.ENABLE_2FE,R.TOKEN_2FE,R.RECOVERY_CODE FROM HANSIP_USER_ROLE UR, HANSIP_USER R WHERE UR.USER_REC_ID = R.REC_ID AND UR.ROLE_REC_ID = ? ORDER BY R.EMAIL %s LIMIT %d, %d", request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	rows, err := db.instance.QueryContext(ctx, q, role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s. SQL = %s", err.Error(), q)
		return nil, nil, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error ListUserRoleByRole",
			SQL:     q,
		}
	}
	defer rows.Close()
	for rows.Next() {
		user := &User{}
		var enabled, suspended, enable2fa int
		var lastSeen, lastLogin, activationDate float64
		err := rows.Scan(&user.RecID, &user.Email, &user.HashedPassphrase, &enabled, &suspended, &lastSeen, &lastLogin, &user.FailCount, &user.ActivationCode,
			&activationDate, &user.UserTotpSecretKey, &enable2fa, &user.Token2FA, &user.RecoveryCode)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
			return nil, nil, &ErrDBScanError{
				Wrapped: err,
				Message: "Error ListUserRoleByRole",
				SQL:     q,
			}
		} else {
			user.LastSeen = coreEpoch.Add(time.Duration(lastSeen * float64(time.Second)))
			user.LastLogin = coreEpoch.Add(time.Duration(lastLogin * float64(time.Second)))
			user.ActivationDate = coreEpoch.Add(time.Duration(activationDate * float64(time.Second)))
			if enabled == 1 {
				user.Enabled = true
			}
			if suspended == 1 {
				user.Suspended = true
			}
			if enable2fa == 1 {
				user.Enable2FactorAuth = true
			}
			ret = append(ret, user)
		}
	}
	return ret, page, nil
}

// DeleteUserRole remove a role from user's assigment
func (db *SqliteDB) DeleteUserRole(ctx context.Context, userRole *UserRole) error {
	fLog := sqliteLog.WithField("func", "DeleteUserRole").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "DELETE FROM HANSIP_USER_ROLE WHERE USER_REC_ID=? AND ROLE_REC_ID=?"
	_, err := db.instance.ExecContext(ctx, q, userRole.UserRecID, userRole.RoleRecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteUserRole",
			SQL:     q,
		}
	}
	return nil
}

// DeleteUserRoleByUser remove ALL role assigment of a user
func (db *SqliteDB) DeleteUserRoleByUser(ctx context.Context, user *User) error {
	fLog := sqliteLog.WithField("func", "DeleteUserRoleByUser").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "DELETE FROM HANSIP_USER_ROLE WHERE USER_REC_ID=?"
	_, err := db.instance.ExecContext(ctx, q, user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteUserRoleByUser",
			SQL:     q,
		}
	}
	return nil
}

// DeleteUserRoleByRole remove all user-role assigment to a role
func (db *SqliteDB) DeleteUserRoleByRole(ctx context.Context, role *Role) error {
	fLog := sqliteLog.WithField("func", "DeleteUserRoleByRole").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "DELETE FROM HANSIP_USER_ROLE WHERE ROLE_REC_ID=?"
	_, err := db.instance.ExecContext(ctx, q, role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteUserRoleByRole",
			SQL:     q,
		}
	}
	return nil
}

// GetRoleByRecID return a role with speciffic recID
func (db *SqliteDB) GetRoleByRecID(ctx context.Context, recID string) (*Role, error) {
	fLog := sqliteLog.WithField("func", "GetRoleByRecID").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT REC_ID, ROLE_NAME, ROLE_DOMAIN, DESCRIPTION FROM HANSIP_ROLE WHERE REC_ID=?"
	row := db.instance.QueryRowContext(ctx, q, recID)
	r := &Role{}
	err := row.Scan(&r.RecID, &r.RoleName, &r.RoleDomain, &r.Description)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error GetRoleByRecID",
			SQL:     q,
		}
	}
	return r, nil
}

// GetRoleByName return a role record
func (db *SqliteDB) GetRoleByName(ctx context.Context, roleName, roleDomain string) (*Role, error) {
	fLog := sqliteLog.WithField("func", "GetRoleByName").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT REC_ID, ROLE_NAME, ROLE_DOMAIN, DESCRIPTION FROM HANSIP_ROLE WHERE ROLE_NAME=? AND ROLE_DOMAIN=?"
	row := db.instance.QueryRowContext(ctx, q, roleName, roleDomain)
	r := &Role{}
	err := row.Scan(&r.RecID, &r.RoleName, &r.RoleDomain, &r.Description)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error GetRoleByName",
			SQL:     q,
		}
	}
	return r, nil
}

// CreateRole creates a new role
func (db *SqliteDB) CreateRole(ctx context.Context, roleName, roleDomain, description string) (*Role, error) {
	fLog := sqliteLog.WithField("func", "CreateRole").WithField("RequestID", ctx.Value(constants.RequestID))
	r := &Role{
		RecID:       helper.MakeRandomString(10, true, true, true, false),
		RoleName:    roleName,
		RoleDomain:  roleDomain,
		Description: description,
	}
	q := "INSERT INTO HANSIP_ROLE(REC_ID, ROLE_NAME,ROLE_DOMAIN, DESCRIPTION) VALUES (?,?,?,?)"
	_, err := db.instance.ExecContext(ctx, q, r.RecID, roleName, roleDomain, description)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s. SQL = %s", err.Error(), q)
		return nil, &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error CreateRole",
			SQL:     q,
		}
	}
	return r, nil
}

// ListRoles list all roles in this server
func (db *SqliteDB) ListRoles(ctx context.Context, tenant *Tenant, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	fLog := sqliteLog.WithField("func", "ListRoles").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) AS CNT FROM HANSIP_ROLE"
	ret := make([]*Role, 0)
	row := db.instance.QueryRowContext(ctx, q)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return ret, helper.NewPage(request, uint(count)), nil
		}
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error ListRoles",
			SQL:     q,
		}
	}
	page := helper.NewPage(request, uint(count))
	q = fmt.Sprintf("SELECT REC_ID, ROLE_NAME,ROLE_DOMAIN, DESCRIPTION FROM HANSIP_ROLE WHERE ROLE_DOMAIN=? ORDER BY ROLE_NAME %s LIMIT %d, %d", request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	rows, err := db.instance.QueryContext(ctx, q, tenant.Domain)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s. SQL = %s", err.Error(), q)
		return nil, nil, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error ListRoles",
			SQL:     q,
		}
	}
	defer rows.Close()
	for rows.Next() {
		r := &Role{}
		err := rows.Scan(&r.RecID, &r.RoleName, &r.RoleDomain, &r.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
			return nil, nil, &ErrDBScanError{
				Wrapped: err,
				Message: "Error ListRoles",
				SQL:     q,
			}
		} else {
			ret = append(ret, r)
		}
	}
	return ret, page, nil
}

// DeleteRole delete a specific role from this server
func (db *SqliteDB) DeleteRole(ctx context.Context, role *Role) error {
	fLog := sqliteLog.WithField("func", "DeleteRole").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "DELETE FROM HANSIP_ROLE WHERE REC_ID=?"
	_, err := db.instance.ExecContext(ctx, q, role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteRole",
			SQL:     q,
		}
	}
	return err
}

// IsRoleRecIDExist check if a speciffic role recId is exist in database
func (db *SqliteDB) IsRoleRecIDExist(ctx context.Context, recID string) (bool, error) {
	fLog := sqliteLog.WithField("func", "IsUserRecIDExist").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) AS CNT FROM HANSIP_ROLE WHERE REC_ID=?"
	rows, err := db.instance.QueryContext(ctx, q, recID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return false, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error IsRoleRecIDExist",
			SQL:     q,
		}
	}
	defer rows.Close()
	if rows.Next() {
		count := 0
		err := rows.Scan(&count)
		if err != nil {
			fLog.Errorf("db.instance.IsRoleRecIDExist cant scan")
			return false, &ErrDBScanError{
				Wrapped: err,
				Message: "Error IsRoleRecIDExist",
				SQL:     q,
			}
		}
		return count > 0, nil
	}
	return false, nil
}

// UpdateRole save or update a role record
func (db *SqliteDB) UpdateRole(ctx context.Context, role *Role) error {
	fLog := sqliteLog.WithField("func", "UpdateRole").WithField("RequestID", ctx.Value(constants.RequestID))
	exist, err := db.IsRoleRecIDExist(ctx, role.RecID)
	if err != nil {
		return err
	}
	if !exist {
		return ErrNotFound
	}
	q := "UPDATE HANSIP_ROLE SET ROLE_NAME=?, ROLE_DOMAIN=?, DESCRIPTION=? WHERE REC_ID=?"
	_, err = db.instance.ExecContext(ctx, q,
		role.RoleName, role.RoleDomain, role.Description, role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error UpdateRole",
			SQL:     q,
		}
	}
	return nil
}

// GetGroupByRecID return a Group data by its RedID
func (db *SqliteDB) GetGroupByRecID(ctx context.Context, recID string) (*Group, error) {
	fLog := sqliteLog.WithField("func", "GetGroupByRecID").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT REC_ID, GROUP_NAME, GROUP_DOMAIN, DESCRIPTION FROM HANSIP_GROUP WHERE REC_ID=?"
	row := db.instance.QueryRowContext(ctx, q, recID)
	r := &Group{}
	err := row.Scan(&r.RecID, &r.GroupName, &r.GroupDomain, &r.Description)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		fLog.Errorf("row.Scan got %s", err.Error())
		return nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error GetGroupByRecID",
			SQL:     q,
		}
	}
	return r, nil
}

func (db *SqliteDB) GetGroupByName(ctx context.Context, groupName, groupDomain string) (*Group, error) {
	fLog := sqliteLog.WithField("func", "GetGroupByName").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT REC_ID, GROUP_NAME, GROUP_DOMAIN, DESCRIPTION FROM HANSIP_GROUP WHERE GROUP_NAME=? AND GROUP_DOMAIN=?"
	row := db.instance.QueryRowContext(ctx, q, groupName, groupDomain)
	r := &Group{}
	err := row.Scan(&r.RecID, &r.GroupName, &r.GroupDomain, &r.Description)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		fLog.Errorf("row.Scan got %s", err.Error())
		return nil, &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error GetGroupByName",
			SQL:     q,
		}
	}
	return r, nil
}

// CreateGroup create new Group
func (db *SqliteDB) CreateGroup(ctx context.Context, groupName, groupDomain, description string) (*Group, error) {
	fLog := sqliteLog.WithField("func", "CreateGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	r := &Group{
		RecID:       helper.MakeRandomString(10, true, true, true, false),
		GroupName:   groupName,
		GroupDomain: groupDomain,
		Description: description,
	}
	q := "INSERT INTO HANSIP_GROUP(REC_ID, GROUP_NAME, GROUP_DOMAIN, DESCRIPTION) VALUES (?,?,?,?)"
	_, err := db.instance.ExecContext(ctx, q, r.RecID, groupName, groupDomain, description)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return nil, &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error CreateGroup",
			SQL:     q,
		}
	}
	return r, nil
}

// ListGroups list all groups in this server
func (db *SqliteDB) ListGroups(ctx context.Context, tenant *Tenant, request *helper.PageRequest) ([]*Group, *helper.Page, error) {
	fLog := sqliteLog.WithField("func", "ListGroups").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) AS CNT FROM HANSIP_GROUP"
	ret := make([]*Group, 0)
	row := db.instance.QueryRowContext(ctx, q)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			page := helper.NewPage(request, uint(count))
			return ret, page, nil
		}
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error ListGroups",
			SQL:     q,
		}
	}
	page := helper.NewPage(request, uint(count))
	q = fmt.Sprintf("SELECT REC_ID, GROUP_NAME, GROUP_DOMAIN, DESCRIPTION FROM HANSIP_GROUP WHERE GROUP_DOMAIN=? ORDER BY GROUP_NAME %s LIMIT %d, %d", request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	rows, err := db.instance.QueryContext(ctx, q, tenant.Domain)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s. SQL = %s", err.Error(), q)
		return nil, nil, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error ListGroups",
			SQL:     q,
		}
	}
	defer rows.Close()
	for rows.Next() {
		r := &Group{}
		err := rows.Scan(&r.RecID, &r.GroupName, &r.GroupDomain, &r.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
			return nil, nil, &ErrDBScanError{
				Wrapped: err,
				Message: "Error ListGroups",
				SQL:     q,
			}
		} else {
			ret = append(ret, r)
		}
	}
	return ret, page, nil
}

// DeleteGroup delete one speciffic group
func (db *SqliteDB) DeleteGroup(ctx context.Context, group *Group) error {
	fLog := sqliteLog.WithField("func", "DeleteGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "DELETE FROM HANSIP_GROUP WHERE REC_ID=?"
	_, err := db.instance.ExecContext(ctx, q, group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteGroup",
			SQL:     q,
		}
	}
	return nil
}

// IsGroupRecIDExist check if a speciffic group recId is exist in database
func (db *SqliteDB) IsGroupRecIDExist(ctx context.Context, recID string) (bool, error) {
	fLog := sqliteLog.WithField("func", "IsGroupRecIDExist").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) AS CNT FROM HANSIP_GROUP WHERE REC_ID=?"
	rows, err := db.instance.QueryContext(ctx, q, recID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return false, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error IsGroupRecIDExist",
			SQL:     q,
		}
	}
	defer rows.Close()
	if rows.Next() {
		count := 0
		err := rows.Scan(&count)
		if err != nil {
			fLog.Errorf("db.instance.IsGroupRecIDExist cant scan")
			return false, &ErrDBScanError{
				Wrapped: err,
				Message: "Error IsGroupRecIDExist",
				SQL:     q,
			}
		}
		return count > 0, nil
	}
	return false, nil
}

// UpdateGroup delete one specific group
func (db *SqliteDB) UpdateGroup(ctx context.Context, group *Group) error {
	fLog := sqliteLog.WithField("func", "UpdateGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	exist, err := db.IsGroupRecIDExist(ctx, group.RecID)
	if err != nil {
		return err
	}
	if !exist {
		return ErrNotFound
	}
	q := "UPDATE HANSIP_GROUP SET GROUP_NAME=?, GROUP_DOMAIN=?, DESCRIPTION=? WHERE REC_ID=?"
	_, err = db.instance.ExecContext(ctx, q,
		group.GroupName, group.GroupDomain, group.Description, group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error UpdateGroup",
			SQL:     q,
		}
	}
	return nil
}

// GetGroupRole get GroupRole relation
func (db *SqliteDB) GetGroupRole(ctx context.Context, group *Group, role *Role) (*GroupRole, error) {
	fLog := sqliteLog.WithField("func", "GetGroupRole").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) CNT FROM HANSIP_GROUP_ROLE WHERE GROUP_REC_ID=? AND ROLE_REC_ID=?"
	row := db.instance.QueryRowContext(ctx, q, group.RecID, role.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		fLog.Errorf("row.Scan got %s", err.Error())
		return nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error GetGroupRole",
			SQL:     q,
		}
	}
	if count == 0 {
		return nil, &ErrDBNoResult{
			Message: fmt.Sprintf("role %s is not in group %s", role.RoleName, group.GroupName),
			SQL:     q,
		}
	}
	return &GroupRole{
		GroupRecID: group.RecID,
		RoleRecID:  role.RecID,
	}, nil
}

// CreateGroupRole create new Group and Role relation
func (db *SqliteDB) CreateGroupRole(ctx context.Context, group *Group, role *Role) (*GroupRole, error) {
	fLog := sqliteLog.WithField("func", "CreateGroupRole").WithField("RequestID", ctx.Value(constants.RequestID))
	if group.GroupDomain != role.RoleDomain {
		fLog.Errorf("Can not join between group and role with different domain.")
		return nil, &ErrGroupAndRoleDomainIncompatible{
			RoleName:    role.RoleName,
			RoleDomain:  role.RoleDomain,
			GroupName:   group.GroupName,
			GroupDomain: group.GroupDomain,
		}
	}
	q := "INSERT INTO HANSIP_GROUP_ROLE(GROUP_REC_ID, ROLE_REC_ID) VALUES (?,?)"
	stmt, err := db.instance.Prepare(q)
	_, err = stmt.ExecContext(ctx, group.RecID, role.RecID)
	//_, err := db.instance.ExecContext(ctx, q, group.RecID, role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return nil, &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error CreateGroupRole",
			SQL:     q,
		}
	}
	return &GroupRole{
		GroupRecID: group.RecID,
		RoleRecID:  role.RecID,
	}, nil
}

// ListGroupRoleByGroup list all role related to a group
func (db *SqliteDB) ListGroupRoleByGroup(ctx context.Context, group *Group, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	fLog := sqliteLog.WithField("func", "ListGroupRoleByGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) FROM HANSIP_GROUP_ROLE WHERE GROUP_REC_ID=?"
	ret := make([]*Role, 0)
	row := db.instance.QueryRowContext(ctx, q, group.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return ret, helper.NewPage(request, uint(count)), nil
		}
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error ListGroupRoleByGroup",
			SQL:     q,
		}
	}
	page := helper.NewPage(request, uint(count))
	q = fmt.Sprintf("SELECT R.REC_ID, R.ROLE_NAME, R.ROLE_DOMAIN, R.DESCRIPTION FROM HANSIP_GROUP_ROLE UR, HANSIP_ROLE R WHERE UR.ROLE_REC_ID = R.REC_ID AND UR.GROUP_REC_ID = ? ORDER BY R.ROLE_NAME %s LIMIT %d, %d", request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	rows, err := db.instance.QueryContext(ctx, q, group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got %s. SQL = %s", err.Error(), q)
		return nil, nil, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error ListGroupRoleByGroup",
			SQL:     q,
		}
	}
	defer rows.Close()
	for rows.Next() {
		role := &Role{}
		err := rows.Scan(&role.RecID, &role.RoleName, &role.RoleDomain, &role.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
			return nil, nil, &ErrDBScanError{
				Wrapped: err,
				Message: "Error ListGroupRoleByGroup",
				SQL:     q,
			}
		} else {
			ret = append(ret, role)
		}
	}
	return ret, page, nil
}

// ListGroupRoleByRole will list all group- related to a role
func (db *SqliteDB) ListGroupRoleByRole(ctx context.Context, role *Role, request *helper.PageRequest) ([]*Group, *helper.Page, error) {
	fLog := sqliteLog.WithField("func", "ListGroupRoleByRole").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) FROM HANSIP_GROUP_ROLE WHERE ROLE_REC_ID=?"
	ret := make([]*Group, 0)
	row := db.instance.QueryRowContext(ctx, q, role.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return ret, helper.NewPage(request, uint(count)), nil
		}
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error ListGroupRoleByRole",
			SQL:     q,
		}
	}
	page := helper.NewPage(request, uint(count))
	q = fmt.Sprintf("SELECT R.REC_ID, R.GROUP_NAME, R.GROUP_DOMAIN, R.DESCRIPTION FROM HANSIP_GROUP_ROLE UR, HANSIP_GROUP R WHERE UR.GROUP_REC_ID = R.REC_ID AND UR.ROLE_REC_ID = ? ORDER BY R.GROUP_NAME %s LIMIT %d, %d", request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	rows, err := db.instance.QueryContext(ctx, q, role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s. SQL = %s", err.Error(), q)
		return nil, nil, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error ListGroupRoleByRole",
			SQL:     q,
		}
	}
	defer rows.Close()
	for rows.Next() {
		group := &Group{}
		err := rows.Scan(&group.RecID, &group.GroupName, &group.GroupDomain, &group.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
			return nil, nil, &ErrDBScanError{
				Wrapped: err,
				Message: "Error ListGroupRoleByRole",
				SQL:     q,
			}
		} else {
			ret = append(ret, group)
		}
	}
	return ret, page, nil
}

// DeleteGroupRole delete a group-role relation
func (db *SqliteDB) DeleteGroupRole(ctx context.Context, groupRole *GroupRole) error {
	fLog := sqliteLog.WithField("func", "DeleteGroupRole").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "DELETE FROM HANSIP_GROUP_ROLE WHERE GROUP_REC_ID=? AND ROLE_REC_ID=?"
	_, err := db.instance.ExecContext(ctx, q, groupRole.GroupRecID, groupRole.RoleRecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteGroupRole",
			SQL:     q,
		}
	}
	return nil
}

// DeleteGroupRoleByGroup deletes group-role relation by the group
func (db *SqliteDB) DeleteGroupRoleByGroup(ctx context.Context, group *Group) error {
	fLog := sqliteLog.WithField("func", "DeleteGroupRoleByGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "DELETE FROM HANSIP_GROUP_ROLE WHERE GROUP_REC_ID=?"
	_, err := db.instance.ExecContext(ctx, q, group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteGroupRoleByGroup",
			SQL:     q,
		}
	}
	return nil
}

// DeleteGroupRoleByRole deletes grou[-role relation by the role
func (db *SqliteDB) DeleteGroupRoleByRole(ctx context.Context, role *Role) error {
	fLog := sqliteLog.WithField("func", "DeleteGroupRoleByRole").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "DELETE FROM HANSIP_GROUP_ROLE WHERE ROLE_REC_ID=?"
	_, err := db.instance.ExecContext(ctx, q, role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteGroupRoleByRole",
			SQL:     q,
		}
	}
	return nil
}

// GetUserGroup list all user-group relation
func (db *SqliteDB) GetUserGroup(ctx context.Context, user *User, group *Group) (*UserGroup, error) {
	fLog := sqliteLog.WithField("func", "GetUserGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) CNT FROM HANSIP_USER_GROUP WHERE USER_REC_ID=? AND GROUP_REC_ID=?"
	row := db.instance.QueryRowContext(ctx, q, user.RecID, group.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		fLog.Errorf("row.Scan got  %s. SQL = %s", err.Error(), q)
		return nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error GetUserGroup",
			SQL:     q,
		}
	}
	if count == 0 {
		return nil, &ErrDBNoResult{
			Message: fmt.Sprintf("user %s is not in group %s", user.Email, group.GroupName),
			SQL:     q,
		}
	}
	return &UserGroup{
		GroupRecID: group.RecID,
		UserRecID:  user.RecID,
	}, nil
}

// CreateUserGroup create new relation between user and group
func (db *SqliteDB) CreateUserGroup(ctx context.Context, user *User, group *Group) (*UserGroup, error) {
	fLog := sqliteLog.WithField("func", "CreateUserGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "INSERT INTO HANSIP_USER_GROUP(USER_REC_ID, GROUP_REC_ID) VALUES (?,?)"
	_, err := db.instance.ExecContext(ctx, q, user.RecID, group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return nil, &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error CreateUserGroup",
			SQL:     q,
		}
	}
	return &UserGroup{
		UserRecID:  user.RecID,
		GroupRecID: group.RecID,
	}, nil
}

// ListUserGroupByUser will list groups that related to a user
func (db *SqliteDB) ListUserGroupByUser(ctx context.Context, user *User, request *helper.PageRequest) ([]*Group, *helper.Page, error) {
	fLog := sqliteLog.WithField("func", "ListUserGroupByUser").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) FROM HANSIP_USER_GROUP WHERE USER_REC_ID=?"
	ret := make([]*Group, 0)
	row := db.instance.QueryRowContext(ctx, q, user.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return ret, helper.NewPage(request, uint(count)), nil
		}
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error ListUserGroupByUser",
			SQL:     q,
		}
	}
	page := helper.NewPage(request, uint(count))
	q = fmt.Sprintf("SELECT R.REC_ID, R.GROUP_NAME, R.GROUP_DOMAIN, R.DESCRIPTION FROM HANSIP_USER_GROUP UR, HANSIP_GROUP R WHERE UR.GROUP_REC_ID = R.REC_ID AND UR.USER_REC_ID = ? ORDER BY R.GROUP_NAME %s LIMIT %d, %d", request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	rows, err := db.instance.QueryContext(ctx, q, user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s. SQL = %s", err.Error(), q)
		return nil, nil, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error ListUserGroupByUser",
			SQL:     q,
		}
	}
	defer rows.Close()
	for rows.Next() {
		group := &Group{}
		err := rows.Scan(&group.RecID, &group.GroupName, &group.GroupDomain, &group.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
			return nil, nil, &ErrDBScanError{
				Wrapped: err,
				Message: "Error ListUserGroupByUser",
				SQL:     q,
			}
		} else {
			ret = append(ret, group)
		}
	}
	return ret, page, nil
}

// ListUserGroupByGroup will list all users that related to a group
func (db *SqliteDB) ListUserGroupByGroup(ctx context.Context, group *Group, request *helper.PageRequest) ([]*User, *helper.Page, error) {
	fLog := sqliteLog.WithField("func", "ListUserGroupByGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) FROM HANSIP_USER_GROUP WHERE GROUP_REC_ID=?"
	ret := make([]*User, 0)
	row := db.instance.QueryRowContext(ctx, q, group.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return ret, helper.NewPage(request, uint(count)), nil
		}
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, nil, &ErrDBScanError{
			Wrapped: err,
			Message: "Error ListUserGroupByGroup",
			SQL:     q,
		}
	}
	page := helper.NewPage(request, uint(count))
	q = fmt.Sprintf("SELECT R.REC_ID,R.EMAIL,R.HASHED_PASSPHRASE,R.ENABLED, R.SUSPENDED,R.LAST_SEEN,R.LAST_LOGIN,R.FAIL_COUNT,R.ACTIVATION_CODE,R.ACTIVATION_DATE,R.TOTP_KEY,R.ENABLE_2FE,R.TOKEN_2FE,R.RECOVERY_CODE FROM HANSIP_USER_GROUP UR, HANSIP_USER R WHERE UR.USER_REC_ID = R.REC_ID AND UR.GROUP_REC_ID = ? ORDER BY R.EMAIL %s LIMIT %d, %d", request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	rows, err := db.instance.QueryContext(ctx, q, group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s. SQL = %s", err.Error(), q)
		return nil, nil, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error ListUserGroupByGroup",
			SQL:     q,
		}
	}
	defer rows.Close()
	for rows.Next() {
		user := &User{}
		var enabled, suspended, enable2fa int
		var lastSeen, lastLogin, activationDate float64
		err := rows.Scan(&user.RecID, &user.Email, &user.HashedPassphrase, &enabled, &suspended, &lastSeen, &lastLogin, &user.FailCount, &user.ActivationCode,
			&activationDate, &user.UserTotpSecretKey, &enable2fa, &user.Token2FA, &user.RecoveryCode)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
			return nil, nil, &ErrDBScanError{
				Wrapped: err,
				Message: "Error ListUserGroupByGroup",
				SQL:     q,
			}
		} else {
			user.LastSeen = coreEpoch.Add(time.Duration(lastSeen * float64(time.Second)))
			user.LastLogin = coreEpoch.Add(time.Duration(lastLogin * float64(time.Second)))
			user.ActivationDate = coreEpoch.Add(time.Duration(activationDate * float64(time.Second)))
			if enabled == 1 {
				user.Enabled = true
			}
			if suspended == 1 {
				user.Suspended = true
			}
			if enable2fa == 1 {
				user.Enable2FactorAuth = true
			}
			ret = append(ret, user)
		}
	}
	return ret, page, nil
}

// DeleteUserGroup will delete a user-group
func (db *SqliteDB) DeleteUserGroup(ctx context.Context, userGroup *UserGroup) error {
	fLog := sqliteLog.WithField("func", "DeleteUserGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "DELETE FROM HANSIP_USER_GROUP WHERE GROUP_REC_ID=? AND USER_REC_ID=?"
	_, err := db.instance.ExecContext(ctx, q, userGroup.GroupRecID, userGroup.UserRecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteUserGroup",
			SQL:     q,
		}
	}
	return nil
}

// DeleteUserGroupByUser will delete a user-group relation by a user
func (db *SqliteDB) DeleteUserGroupByUser(ctx context.Context, user *User) error {
	fLog := sqliteLog.WithField("func", "DeleteUserGroupByUser").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "DELETE FROM HANSIP_USER_GROUP WHERE USER_REC_ID=?"
	_, err := db.instance.ExecContext(ctx, q, user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteUserGroupByUser",
			SQL:     q,
		}
	}
	return nil
}

// DeleteUserGroupByGroup will delete user-group relation by a group
func (db *SqliteDB) DeleteUserGroupByGroup(ctx context.Context, group *Group) error {
	fLog := sqliteLog.WithField("func", "DeleteUserGroupByGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "DELETE FROM HANSIP_USER_GROUP WHERE GROUP_REC_ID=?"
	_, err := db.instance.ExecContext(ctx, q, group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error DeleteUserGroupByGroup",
			SQL:     q,
		}
	}
	return nil
}

// Revoke a subject
func (db *SqliteDB) Revoke(ctx context.Context, subject string) error {
	fLog := sqliteLog.WithField("func", "Revoke").WithField("RequestID", ctx.Value(constants.RequestID))
	revoked, err := db.IsRevoked(ctx, subject)
	if err != nil {
		return err
	}
	if revoked {
		return nil
	}
	q := "INSERT INTO HANSIP_REVOCATION(SUBJECT, ACTIVATION_DATE) VALUES (?,?)"
	_, err = db.instance.ExecContext(ctx, q, subject, time.Now())
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error Revoke",
			SQL:     q,
		}
	}
	return nil
}

// UnRevoke a subject
func (db *SqliteDB) UnRevoke(ctx context.Context, subject string) error {
	fLog := sqliteLog.WithField("func", "UnRevoke").WithField("RequestID", ctx.Value(constants.RequestID))
	revoked, err := db.IsRevoked(ctx, subject)
	if err != nil {
		return err
	}
	if !revoked {
		return nil
	}
	q := "DELETE FROM HANSIP_REVOCATION WHERE SUBJECT=?"
	_, err = db.instance.ExecContext(ctx, q, subject)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s. SQL = %s", err.Error(), q)
		return &ErrDBExecuteError{
			Wrapped: err,
			Message: "Error UnRevoke",
			SQL:     q,
		}
	}
	return nil
}

// IsRevoked validate if a subject is revoked
func (db *SqliteDB) IsRevoked(ctx context.Context, subject string) (bool, error) {
	fLog := sqliteLog.WithField("func", "IsRevoked").WithField("RequestID", ctx.Value(constants.RequestID))
	q := "SELECT COUNT(*) AS CNT FROM HANSIP_REVOCATION WHERE SUBJECT=?"

	rows, err := db.instance.QueryContext(ctx, q, subject)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got %s. SQL = %s", err.Error(), q)
		return false, &ErrDBQueryError{
			Wrapped: err,
			Message: "Error IsRevoked",
			SQL:     q,
		}
	}
	defer rows.Close()
	if rows.Next() {
		count := 0
		err := rows.Scan(&count)
		if err != nil {
			fLog.Errorf("db.instance.IsRevoked cant scan")
			return false, &ErrDBScanError{
				Wrapped: err,
				Message: "Error IsRevoked",
				SQL:     q,
			}
		}
		return count > 0, nil
	}
	return false, nil
}

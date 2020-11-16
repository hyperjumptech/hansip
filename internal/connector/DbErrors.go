package connector

import "fmt"

type ErrDBCreateTableDuplicate struct {
	Wrapped error
	Message string
}

func (err *ErrDBCreateTableDuplicate) Error() string {
	return err.Message
}

func (err *ErrDBCreateTableDuplicate) Unwrap() error {
	return err.Wrapped
}

type ErrDBQueryError struct {
	Wrapped error
	Message string
	SQL     string
}

func (err *ErrDBQueryError) Error() string {
	return err.Message
}

func (err *ErrDBQueryError) Unwrap() error {
	return err.Wrapped
}

type ErrDBExecuteError struct {
	Wrapped error
	Message string
	SQL     string
}

func (err *ErrDBExecuteError) Error() string {
	return err.Message
}

func (err *ErrDBExecuteError) Unwrap() error {
	return err.Wrapped
}

type ErrDBScanError struct {
	Wrapped error
	Message string
	SQL     string
}

func (err *ErrDBScanError) Error() string {
	return err.Message
}

func (err *ErrDBScanError) Unwrap() error {
	return err.Wrapped
}

type ErrLibraryCallError struct {
	Wrapped     error
	Message     string
	LibraryName string
}

func (err *ErrLibraryCallError) Error() string {
	return err.Message
}

func (err *ErrLibraryCallError) Unwrap() error {
	return err.Wrapped
}

type ErrGroupAndRoleDomainIncompatible struct {
	RoleName    string
	RoleDomain  string
	GroupName   string
	GroupDomain string
}

func (err *ErrGroupAndRoleDomainIncompatible) Error() string {
	return fmt.Sprintf("Can not create group role with between incompatible domain Group: %s@%s to Role: %s@%s", err.GroupName, err.GroupDomain, err.RoleName, err.RoleDomain)
}

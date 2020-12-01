package endpoint

import (
	"encoding/json"
	"fmt"
	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/constants"
	"github.com/hyperjumptech/hansip/internal/hansipcontext"
	"github.com/hyperjumptech/hansip/pkg/helper"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"strings"
)

var (
	tenantMgmtLog = log.WithField("go", "TenantManagement")
)

// ListAllGroup serving the listing of group request
func ListAllTenants(w http.ResponseWriter, r *http.Request) {
	fLog := tenantMgmtLog.WithField("func", "ListAllTenans").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		fLog.Tracef("Missing authentication context")
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}
	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.HasIsAdminOfDomain(config.Get("hansip.domain")) {
		fLog.Tracef("Missing right")
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to access this resource", nil, nil)
		return
	}
	pageRequest, err := helper.NewPageRequestFromRequest(r)
	if err != nil {
		fLog.Errorf("helper.NewPageRequestFromRequest got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	tenants, page, err := TenantRepo.ListTenant(r.Context(), pageRequest)
	if err != nil {
		fLog.Errorf("TenantRepo.ListTenant got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	ret := make(map[string]interface{})
	ret["tenants"] = tenants
	ret["page"] = page
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "List of all tenants paginated", nil, ret)
}

// CreateGroupRequest hold model for Create new Group.
type CreateTenantRequest struct {
	TenantName   string `json:"name"`
	TenantDomain string `json:"domain"`
	Description  string `json:"description"`
}

// CreateNewGroup serving request to create new Group
func CreateNewTenant(w http.ResponseWriter, r *http.Request) {
	fLog := tenantMgmtLog.WithField("func", "CreateNewTenant").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}
	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.HasIsAdminOfDomain(config.Get("hansip.domain")) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to access this resource", nil, nil)
		return
	}

	req := &CreateTenantRequest{}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fLog.Errorf("ioutil.ReadAll got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	err = json.Unmarshal(body, req)
	if err != nil {
		fLog.Errorf("json.Unmarshal got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	if strings.Contains(req.TenantDomain, "@") {
		fLog.Errorf("Domain contains @")
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, "Tenant domain contains @", nil, nil)
		return
	}
	tenant, err := TenantRepo.CreateTenantRecord(r.Context(), req.TenantName, req.TenantDomain, req.Description)
	if err != nil {
		fLog.Errorf("TenantRepo.CreateTenantRecord got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Success creating tenant", nil, tenant)
	return
}

// GetGroupDetail serving request to fetch group detail
func GetTenantDetail(w http.ResponseWriter, r *http.Request) {
	fLog := tenantMgmtLog.WithField("func", "GetTenantDetail").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}
	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.HasIsAdminOfDomain(config.Get("hansip.domain")) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/tenant/{tenantRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	tenant, err := TenantRepo.GetTenantByRecID(r.Context(), params["tenantRecId"])
	if err != nil {
		fLog.Errorf("TenantRepo.GetTenantByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Tenant retrieved", nil, tenant)
}

// UpdateGroup serving request to update group detail
func UpdateTenantDetail(w http.ResponseWriter, r *http.Request) {
	fLog := tenantMgmtLog.WithField("func", "UpdateTenantDetail").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}
	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.HasIsAdminOfDomain(config.Get("hansip.domain")) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/tenant/{tenantRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}

	req := &CreateTenantRequest{}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fLog.Errorf("ioutil.ReadAll got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}
	err = json.Unmarshal(body, req)
	if err != nil {
		fLog.Errorf("json.Unmarshal got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusBadRequest, err.Error(), nil, nil)
		return
	}

	tenant, err := TenantRepo.GetTenantByRecID(r.Context(), params["tenantRecId"])
	if err != nil {
		fLog.Errorf("GroupRepo.GetGroupByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	tenant.Name = req.TenantName
	tenant.Domain = req.TenantDomain
	tenant.Description = req.Description

	exTenant, err := TenantRepo.GetTenantByDomain(r.Context(), req.TenantDomain)
	if err == nil && exTenant.Domain == req.TenantDomain && exTenant.RecID != params["tenantRecId"] {
		fLog.Errorf("Duplicate tenant domain name. tenant domain %s already exist", req.TenantDomain)
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}

	err = TenantRepo.UpdateTenant(r.Context(), tenant)
	if err != nil {
		fLog.Errorf("TenantRepo.UpdateTenant got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusInternalServerError, err.Error(), nil, nil)
		return
	}

	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Tenant updated", nil, tenant)

}

// DeleteGroup serving request to delete a group
func DeleteTenant(w http.ResponseWriter, r *http.Request) {
	fLog := tenantMgmtLog.WithField("func", "DeleteTenant").WithField("RequestID", r.Context().Value(constants.RequestID)).WithField("path", r.URL.Path).WithField("method", r.Method)
	iauthctx := r.Context().Value(constants.HansipAuthentication)
	if iauthctx == nil {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, "You are not authorized to access this resource", nil, nil)
		return
	}
	authCtx := iauthctx.(*hansipcontext.AuthenticationContext)
	if !authCtx.HasIsAdminOfDomain(config.Get("hansip.domain")) {
		helper.WriteHTTPResponse(r.Context(), w, http.StatusForbidden, "You don't have the right to access this resource", nil, nil)
		return
	}

	params, err := helper.ParsePathParams(fmt.Sprintf("%s/management/tenant/{tenantRecId}", apiPrefix), r.URL.Path)
	if err != nil {
		panic(err)
	}
	tenant, err := TenantRepo.GetTenantByRecID(r.Context(), params["groupRecId"])
	if err != nil {
		fLog.Errorf("TenantRepo.GetTenantByRecID got %s", err.Error())
		helper.WriteHTTPResponse(r.Context(), w, http.StatusNotFound, err.Error(), nil, nil)
		return
	}
	TenantRepo.DeleteTenant(r.Context(), tenant)

	// todo delete all role and group that have the same domain name

	helper.WriteHTTPResponse(r.Context(), w, http.StatusOK, "Group deleted", nil, nil)
}

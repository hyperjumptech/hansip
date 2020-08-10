package helper

import (
	"net/http"
	"strconv"
)

// NewPageRequestFromRequest create new page request information based on the http request query
func NewPageRequestFromRequest(r *http.Request) (*PageRequest, error) {
	no := 1
	size := 10
	queries := r.URL.Query()
	order := ""
	sorting := "ASC"

	if len(queries.Get("page_no")) > 0 {
		pno, err := strconv.Atoi(queries.Get("page_no"))
		if err != nil {
			return nil, err
		}
		no = pno
	}

	if len(queries.Get("page_size")) > 0 {
		psize, err := strconv.Atoi(queries.Get("page_size"))
		if err != nil {
			return nil, err
		}
		size = psize
	}

	if len(queries.Get("order_by")) > 0 {
		order = queries.Get("order_by")
	}

	if len(queries.Get("sort")) > 0 {
		sorting = queries.Get("sort")
	}

	ret := &PageRequest{
		No:       uint(no),
		PageSize: uint(size),
		OrderBy:  order,
		Sort:     sorting,
	}
	return ret, nil
}

// NewPage create a new page structure based on page request and total number of items.
func NewPage(pageRequest *PageRequest, totalItems uint) *Page {
	page := &Page{
		Sort:       pageRequest.Sort,
		PageSize:   pageRequest.PageSize,
		OrderBy:    pageRequest.OrderBy,
		TotalItems: totalItems,
	}
	if totalItems == 0 {
		page.No = 1
		page.TotalPages = 1
		page.Items = 0
		page.LastPage = 1
		page.FistPage = 1
		page.NextPage = 1
		page.PrevPage = 1
		page.OffsetStart = 0
		page.OffsetEnd = 0
		page.IsFirst = true
		page.IsLast = true
		return page
	}
	page.TotalPages = uint(totalItems / pageRequest.PageSize)
	if totalItems%pageRequest.PageSize > 0 {
		page.TotalPages++
	}
	if pageRequest.No < 1 {
		page.No = 1
	} else if pageRequest.No > page.TotalPages {
		page.No = page.TotalPages
	} else {
		page.No = pageRequest.No
	}
	if page.No == page.TotalPages {
		if totalItems%pageRequest.PageSize > 0 {
			page.Items = totalItems % pageRequest.PageSize
		} else {
			page.Items = pageRequest.PageSize
		}
	} else {
		page.Items = pageRequest.PageSize
	}
	page.HasNext = page.No < page.TotalPages
	page.HasPrev = page.No > 1
	page.FistPage = 1
	page.LastPage = page.TotalPages
	page.NextPage = page.No + 1
	if page.NextPage > page.TotalPages {
		page.NextPage = page.TotalPages
	}
	page.PrevPage = page.No - 1
	if page.PrevPage < 1 {
		page.PrevPage = 1
	}
	page.OffsetStart = (page.No - 1) * page.PageSize
	page.OffsetEnd = page.OffsetStart + page.PageSize
	if page.OffsetEnd >= page.TotalItems {
		page.OffsetEnd = page.TotalItems
	}
	if page.No == page.FistPage {
		page.IsFirst = true
	}
	if page.No == page.LastPage {
		page.IsLast = true
	}
	return page
}

// Page a meta data for listing that contains pagination structure
type Page struct {
	No          uint   `json:"no"`
	TotalPages  uint   `json:"total_pages"`
	PageSize    uint   `json:"page_size"`
	Items       uint   `json:"items"`
	TotalItems  uint   `json:"total_items"`
	HasNext     bool   `json:"has_next"`
	HasPrev     bool   `json:"has_prev"`
	IsFirst     bool   `json:"is_first"`
	IsLast      bool   `json:"is_last"`
	FistPage    uint   `json:"fist_page"`
	NextPage    uint   `json:"next_page"`
	PrevPage    uint   `json:"prev_page"`
	LastPage    uint   `json:"last_page"`
	OrderBy     string `json:"order_by"`
	OffsetStart uint   `json:"-"`
	OffsetEnd   uint   `json:"-"`
	Sort        string `json:"sort"`
}

// PageRequest define a list query specification in paginated fashion.
type PageRequest struct {
	No       uint   `json:"no"`
	PageSize uint   `json:"page_size"`
	OrderBy  string `json:"order_by"`
	Sort     string `json:"sort"`
}

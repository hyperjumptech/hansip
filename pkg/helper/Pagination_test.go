package helper

import (
	"net/http/httptest"
	"testing"
)

var (
	pages = []*Page{
		{
			No:          1,
			TotalPages:  10,
			PageSize:    10,
			Items:       10,
			TotalItems:  100,
			HasNext:     true,
			HasPrev:     false,
			FistPage:    1,
			NextPage:    2,
			PrevPage:    1,
			LastPage:    10,
			IsFirst:     true,
			IsLast:      false,
			OrderBy:     "ABC",
			OffsetStart: 0,
			OffsetEnd:   10,
			Sort:        "ASC",
		},
		{
			No:          2,
			TotalPages:  10,
			PageSize:    10,
			Items:       10,
			TotalItems:  100,
			HasNext:     true,
			HasPrev:     true,
			FistPage:    1,
			NextPage:    3,
			PrevPage:    1,
			LastPage:    10,
			IsFirst:     false,
			IsLast:      false,
			OrderBy:     "ABC",
			OffsetStart: 10,
			OffsetEnd:   20,
			Sort:        "ASC",
		},
		{
			No:          1,
			TotalPages:  1,
			PageSize:    10,
			Items:       6,
			TotalItems:  6,
			HasNext:     false,
			HasPrev:     false,
			FistPage:    1,
			NextPage:    1,
			PrevPage:    1,
			LastPage:    1,
			IsFirst:     true,
			IsLast:      true,
			OrderBy:     "ABC",
			OffsetStart: 0,
			OffsetEnd:   6,
			Sort:        "ASC",
		},
		{
			No:          1,
			TotalPages:  1,
			PageSize:    10,
			Items:       0,
			TotalItems:  0,
			HasNext:     false,
			HasPrev:     false,
			FistPage:    1,
			NextPage:    1,
			PrevPage:    1,
			LastPage:    1,
			IsFirst:     true,
			IsLast:      true,
			OrderBy:     "ABC",
			OffsetStart: 0,
			OffsetEnd:   0,
			Sort:        "ASC",
		},
		{
			No:          1,
			TotalPages:  1,
			PageSize:    10,
			Items:       1,
			TotalItems:  1,
			HasNext:     false,
			HasPrev:     false,
			FistPage:    1,
			NextPage:    1,
			PrevPage:    1,
			LastPage:    1,
			IsFirst:     true,
			IsLast:      true,
			OrderBy:     "ABC",
			OffsetStart: 0,
			OffsetEnd:   1,
			Sort:        "ASC",
		},
		{
			No:          1,
			TotalPages:  1,
			PageSize:    10,
			Items:       10,
			TotalItems:  10,
			HasNext:     false,
			HasPrev:     false,
			FistPage:    1,
			NextPage:    1,
			PrevPage:    1,
			LastPage:    1,
			IsFirst:     true,
			IsLast:      true,
			OrderBy:     "ABC",
			OffsetStart: 0,
			OffsetEnd:   10,
			Sort:        "ASC",
		},
		{
			No:          1,
			TotalPages:  2,
			PageSize:    10,
			Items:       10,
			TotalItems:  11,
			HasNext:     true,
			HasPrev:     false,
			FistPage:    1,
			NextPage:    2,
			PrevPage:    1,
			LastPage:    2,
			IsFirst:     true,
			IsLast:      false,
			OrderBy:     "ABC",
			OffsetStart: 0,
			OffsetEnd:   10,
			Sort:        "ASC",
		},
		{
			No:          2,
			TotalPages:  2,
			PageSize:    10,
			Items:       1,
			TotalItems:  11,
			HasNext:     false,
			HasPrev:     true,
			FistPage:    1,
			NextPage:    2,
			PrevPage:    1,
			LastPage:    2,
			IsFirst:     false,
			IsLast:      true,
			OrderBy:     "ABC",
			OffsetStart: 10,
			OffsetEnd:   11,
			Sort:        "ASC",
		},
		{
			No:          5,
			TotalPages:  10,
			PageSize:    10,
			Items:       10,
			TotalItems:  100,
			HasNext:     true,
			HasPrev:     true,
			FistPage:    1,
			NextPage:    6,
			PrevPage:    4,
			LastPage:    10,
			IsFirst:     false,
			IsLast:      false,
			OrderBy:     "ABC",
			OffsetStart: 40,
			OffsetEnd:   50,
			Sort:        "ASC",
		},
		{
			No:          11,
			TotalPages:  11,
			PageSize:    10,
			Items:       5,
			TotalItems:  105,
			HasNext:     false,
			HasPrev:     true,
			FistPage:    1,
			NextPage:    11,
			PrevPage:    10,
			LastPage:    11,
			IsFirst:     false,
			IsLast:      true,
			OrderBy:     "ABC",
			OffsetStart: 100,
			OffsetEnd:   105,
			Sort:        "ASC",
		},
	}
)

func TestNewPageRequestFromRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "/?page_no=2&page_size=20&order_by=EMAIL&sort=DESC", nil)
	//req, err := http.NewRequest("GET", "/?page_no=2&page_size=20&order_by=EMAIL&sort=DESC", nil)
	t.Log(req.URL.String())
	t.Log(req.URL.Query())
	preq, err := NewPageRequestFromRequest(req)
	if err != nil {
		t.Errorf("error got %s", err.Error())
		t.Fail()
	} else {
		if preq.OrderBy != "EMAIL" {
			t.Errorf("expect order by EMAIL but %s", preq.OrderBy)
			t.Fail()
		}
		if preq.Sort != "DESC" {
			t.Errorf("expect sort DESC but %s", preq.Sort)
			t.Fail()
		}
		if preq.No != 2 {
			t.Errorf("expect no 2 but %d", preq.No)
			t.Fail()
		}
		if preq.PageSize != 20 {
			t.Errorf("expect page size 20 but %d", preq.PageSize)
			t.Fail()
		}
	}
}

func TestNewPage(t *testing.T) {
	for idx, testPage := range pages {
		pr := &PageRequest{
			No:       testPage.No,
			PageSize: testPage.PageSize,
			OrderBy:  testPage.OrderBy,
			Sort:     testPage.Sort,
		}
		presult := NewPage(pr, testPage.TotalItems)
		t.Log("Testing page ", idx)
		if presult.No != testPage.No {
			t.Error("Test", idx, "Expect No", testPage.No, "but", presult.No)
			t.Fail()
		}
		if presult.TotalPages != testPage.TotalPages {
			t.Error("Test", idx, "Expect TotalPages", testPage.TotalPages, "but", presult.TotalPages)
			t.Fail()
		}
		if presult.PageSize != testPage.PageSize {
			t.Error("Test", idx, "Expect PageSize", testPage.PageSize, "but", presult.PageSize)
			t.Fail()
		}
		if presult.Items != testPage.Items {
			t.Error("Test", idx, "Expect Items", testPage.Items, "but", presult.Items)
			t.Fail()
		}
		if presult.TotalItems != testPage.TotalItems {
			t.Error("Test", idx, "Expect TotalItems", testPage.TotalItems, "but", presult.TotalItems)
			t.Fail()
		}
		if presult.HasNext != testPage.HasNext {
			t.Error("Test", idx, "Expect HasNext", testPage.HasNext, "but", presult.HasNext)
			t.Fail()
		}
		if presult.HasPrev != testPage.HasPrev {
			t.Error("Test", idx, "Expect HasPrev", testPage.HasPrev, "but", presult.HasPrev)
			t.Fail()
		}
		if presult.FistPage != testPage.FistPage {
			t.Error("Test", idx, "Expect FistPage", testPage.FistPage, "but", presult.FistPage)
			t.Fail()
		}
		if presult.LastPage != testPage.LastPage {
			t.Error("Test", idx, "Expect LastPage", testPage.LastPage, "but", presult.LastPage)
			t.Fail()
		}
		if presult.PrevPage != testPage.PrevPage {
			t.Error("Test", idx, "Expect PrevPage", testPage.PrevPage, "but", presult.PrevPage)
			t.Fail()
		}
		if presult.NextPage != testPage.NextPage {
			t.Error("Test", idx, "Expect NextPage", testPage.NextPage, "but", presult.NextPage)
			t.Fail()
		}
		if presult.OrderBy != testPage.OrderBy {
			t.Error("Test", idx, "Expect OrderBy", testPage.OrderBy, "but", presult.OrderBy)
			t.Fail()
		}
		if presult.Sort != testPage.Sort {
			t.Error("Test", idx, "Expect Sort", testPage.Sort, "but", presult.Sort)
			t.Fail()
		}
		if presult.OffsetStart != testPage.OffsetStart {
			t.Error("Test", idx, "Expect OffsetStart", testPage.OffsetStart, "but", presult.OffsetStart)
			t.Fail()
		}
		if presult.OffsetEnd != testPage.OffsetEnd {
			t.Error("Test", idx, "Expect OffsetEnd", testPage.OffsetEnd, "but", presult.OffsetEnd)
			t.Fail()
		}
		if presult.IsLast != testPage.IsLast {
			t.Error("Test", idx, "Expect IsLast", testPage.IsLast, "but", presult.IsLast)
			t.Fail()
		}
		if presult.IsFirst != testPage.IsFirst {
			t.Error("Test", idx, "Expect IsFirst", testPage.IsFirst, "but", presult.IsFirst)
			t.Fail()
		}
	}
}

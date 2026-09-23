package database

import (
	"testing"

	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
)

// TestSetGPDB verifies that a connection opened elsewhere (the unified
// evilgophish binary's gophish handle) can be adopted and used for the proxy
// result/event database writes.
func TestSetGPDB(t *testing.T) {
	sqliteDB, err := gorm.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer sqliteDB.Close()

	if err := sqliteDB.CreateTable(&Event{}).Error; err != nil {
		t.Fatalf("create events table: %v", err)
	}
	if err := sqliteDB.CreateTable(&Result{}).Error; err != nil {
		t.Fatalf("create results table: %v", err)
	}

	SetGPDB(sqliteDB)
	if gp_db != sqliteDB {
		t.Fatal("gp_db does not reference the adopted connection")
	}

	e := &Event{Email: "victim@example.com", Message: "Clicked Link"}
	if err := AddEvent(e, 42); err != nil {
		t.Fatalf("AddEvent: %v", err)
	}
	if e.Id == 0 {
		t.Fatal("AddEvent did not persist the event row")
	}
	if e.CampaignId != 42 {
		t.Fatalf("campaign id = %d, want 42", e.CampaignId)
	}
	if e.Time.IsZero() {
		t.Fatal("AddEvent did not set the event time")
	}

	got := Event{}
	if err := sqliteDB.First(&got, e.Id).Error; err != nil {
		t.Fatalf("read back event: %v", err)
	}
	if got.Email != "victim@example.com" || got.Message != "Clicked Link" {
		t.Fatalf("read back mismatch: %+v", got)
	}

	// The result-write path (click/credential capture handlers) must also work
	// through the adopted connection.
	res := Result{RId: "abc123", UserId: 7, Status: "Email/SMS Sent"}
	res.BaseRecipient = BaseRecipient{Email: "victim@example.com"}
	if err := sqliteDB.Save(&res).Error; err != nil {
		t.Fatalf("save result: %v", err)
	}
	if err := HandleClickedLink("abc123", nil, false); err != nil {
		t.Fatalf("HandleClickedLink: %v", err)
	}
	r := Result{}
	if err := sqliteDB.Table("results").Where("r_id=?", "abc123").Scan(&r).Error; err != nil {
		t.Fatalf("query results: %v", err)
	}
	if r.Status != "Clicked Link" {
		t.Fatalf("status = %q, want %q", r.Status, "Clicked Link")
	}

	SetGPDB(nil)
}

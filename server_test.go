package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRuleStorePersistsRules(t *testing.T) {
	path := t.TempDir() + "/nested/rules.json"
	store, err := NewRuleStore(path)
	if err != nil {
		t.Fatal(err)
	}

	rule := Rule{Identifier: "abc123", Type: "binary", Action: "allow"}
	if err := store.Put(rule); err != nil {
		t.Fatal(err)
	}
	if got := store.List(); len(got) != 1 || got[0].Type != "BINARY" || got[0].Action != "ALLOW" {
		t.Fatalf("unexpected rules after put: %#v", got)
	}

	reloaded, err := NewRuleStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].Identifier != rule.Identifier {
		t.Fatalf("unexpected persisted rules: %#v", got)
	}
	if err := reloaded.Delete("binary", rule.Identifier); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.List(); len(got) != 0 {
		t.Fatalf("expected deleted rule, got %#v", got)
	}
}

func TestRuleStoreRejectsInvalidRules(t *testing.T) {
	store, err := NewRuleStore(t.TempDir() + "/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(Rule{Identifier: "abc123", Type: "BINARY", Action: "INVALID"}); err == nil {
		t.Fatal("expected invalid action to be rejected")
	}
}

func TestHandlerCreatesAndDownloadsSantaRules(t *testing.T) {
	store, err := NewRuleStore(t.TempDir() + "/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(store)

	create := httptest.NewRequest(http.MethodPost, "/v1/rules",
		strings.NewReader(`{"identifier":"abc123","type":"binary","action":"block"}`))
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, create)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d: %s", createResponse.Code, http.StatusCreated, createResponse.Body)
	}
	if err := store.Put(Rule{Identifier: "/usr/bin/example", Type: "PATH", Action: "ALLOW"}); err != nil {
		t.Fatal(err)
	}

	download := httptest.NewRequest(http.MethodPost, "/santa/v1/rule_download",
		strings.NewReader(`{"machine_id":"machine-1"}`))
	downloadResponse := httptest.NewRecorder()
	handler.ServeHTTP(downloadResponse, download)
	if downloadResponse.Code != http.StatusOK {
		t.Fatalf("download status = %d, want %d: %s", downloadResponse.Code, http.StatusOK, downloadResponse.Body)
	}

	var response struct {
		Rules []struct {
			Identifier string `json:"identifier"`
			RuleType   string `json:"rule_type"`
			Policy     string `json:"policy"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(downloadResponse.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Rules) != 1 {
		t.Fatalf("downloaded %d rules, want 1", len(response.Rules))
	}
	got := response.Rules[0]
	if got.Identifier != "abc123" || got.RuleType != "BINARY" || got.Policy != "BLOCKLIST" {
		t.Fatalf("unexpected Santa rule: %#v", got)
	}
}

func TestSantaRuleDownloadRequiresMachineID(t *testing.T) {
	store, err := NewRuleStore(t.TempDir() + "/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/santa/v1/rule_download", strings.NewReader(`{}`))
	response := httptest.NewRecorder()
	NewHandler(store).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

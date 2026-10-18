package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type Rule struct {
	Identifier string `json:"identifier"`
	Type       string `json:"type"`
	Action     string `json:"action"`
}

type RuleStore struct {
	mu    sync.RWMutex
	path  string
	rules map[string]Rule
}

func NewRuleStore(path string) (*RuleStore, error) {
	store := &RuleStore{path: path, rules: make(map[string]Rule)}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}

	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("decode rules: %w", err)
	}
	for _, rule := range rules {
		if err := validateRule(rule); err != nil {
			return nil, fmt.Errorf("invalid stored rule: %w", err)
		}
		store.rules[ruleKey(rule)] = rule
	}
	return store, nil
}

func (s *RuleStore) List() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rules := make([]Rule, 0, len(s.rules))
	for _, rule := range s.rules {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Type == rules[j].Type {
			return rules[i].Identifier < rules[j].Identifier
		}
		return rules[i].Type < rules[j].Type
	})
	return rules
}

func (s *RuleStore) Put(rule Rule) error {
	rule.Type = strings.ToUpper(rule.Type)
	rule.Action = strings.ToUpper(rule.Action)
	if err := validateRule(rule); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]Rule, len(s.rules)+1)
	for key, current := range s.rules {
		next[key] = current
	}
	next[ruleKey(rule)] = rule
	if err := s.save(next); err != nil {
		return err
	}
	s.rules = next
	return nil
}

func (s *RuleStore) Delete(ruleType, identifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]Rule, len(s.rules))
	for key, rule := range s.rules {
		next[key] = rule
	}
	delete(next, ruleKey(Rule{Type: strings.ToUpper(ruleType), Identifier: identifier}))
	if err := s.save(next); err != nil {
		return err
	}
	s.rules = next
	return nil
}

func (s *RuleStore) save(rules map[string]Rule) error {
	ordered := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		ordered = append(ordered, rule)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Type == ordered[j].Type {
			return ordered[i].Identifier < ordered[j].Identifier
		}
		return ordered[i].Type < ordered[j].Type
	})

	data, err := json.MarshalIndent(ordered, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0750); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(s.path), ".rules-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), s.path)
}

func ruleKey(rule Rule) string {
	return rule.Type + "\x00" + rule.Identifier
}

func validateRule(rule Rule) error {
	if strings.TrimSpace(rule.Identifier) == "" {
		return errors.New("identifier is required")
	}
	switch rule.Type {
	case "BINARY", "CERTIFICATE", "TEAMID", "SIGNINGID", "CDHASH", "PATH":
	default:
		return fmt.Errorf("unsupported rule type %q", rule.Type)
	}
	if rule.Action != "ALLOW" && rule.Action != "BLOCK" {
		return fmt.Errorf("unsupported rule action %q", rule.Action)
	}
	return nil
}

func NewHandler(store *RuleStore) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/rules", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, store.List())
	})
	mux.HandleFunc("POST /v1/rules", func(w http.ResponseWriter, r *http.Request) {
		var rule Rule
		if err := decodeJSON(w, r, &rule); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		rule.Type = strings.ToUpper(rule.Type)
		rule.Action = strings.ToUpper(rule.Action)
		if err := store.Put(rule); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, rule)
	})
	mux.HandleFunc("DELETE /v1/rules/{identifier}", func(w http.ResponseWriter, r *http.Request) {
		ruleType := r.URL.Query().Get("type")
		if ruleType == "" {
			writeError(w, http.StatusBadRequest, "type query parameter is required")
			return
		}
		if err := store.Delete(ruleType, r.PathValue("identifier")); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /santa/v1/rule_download", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			MachineID string `json:"machine_id"`
		}
		if err := decodeJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if strings.TrimSpace(request.MachineID) == "" {
			writeError(w, http.StatusBadRequest, "machine_id is required")
			return
		}
		rules := store.List()
		santaRules := make([]map[string]string, 0, len(rules))
		for _, rule := range rules {
			if rule.Type == "PATH" {
				continue
			}
			policy := "ALLOWLIST"
			if rule.Action == "BLOCK" {
				policy = "BLOCKLIST"
			}
			santaRules = append(santaRules, map[string]string{
				"identifier": rule.Identifier,
				"rule_type":  rule.Type,
				"policy":     policy,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"rules": santaRules})
	})
	return mux
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("request must contain a single JSON value")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

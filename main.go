package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	address := os.Getenv("ADDR")
	if address == "" {
		address = ":8080"
	}
	database := os.Getenv("ALLOWLIST_DB")
	if database == "" {
		database = "data/rules.json"
	}

	store, err := NewRuleStore(database)
	if err != nil {
		log.Fatalf("load rules: %v", err)
	}

	log.Printf("execution allowlist server listening on %s", address)
	if err := http.ListenAndServe(address, NewHandler(store)); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

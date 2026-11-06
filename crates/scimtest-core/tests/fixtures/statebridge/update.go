package main

import (
	"encoding/json"
	"os"

	"github.com/rselbach/scimtest/internal/update"
)

func updateFeed(operation string) error {
	var input struct {
		Key     string          `json:"key"`
		Release update.Release  `json:"release"`
		Feed    json.RawMessage `json:"feed"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return err
	}
	if operation == "sign-update-feed" {
		key, err := update.ParseSigningKey(input.Key)
		if err != nil {
			return err
		}
		feed, err := update.Seal(input.Release, key)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(feed)
		return err
	}
	key, err := update.ParsePublicKey(input.Key)
	if err != nil {
		return err
	}
	release, err := update.Open(input.Feed, key)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"valid": err == nil, "release": release,
	})
}

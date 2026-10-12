package loader

import (
	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/yamltokens"
	"go.yaml.in/yaml/v3"
)

// decodeVerifiedYAML requires authentication and exact payload equality at its caller.
func decodeVerifiedYAML(payload []byte) (map[string]any, error) {
	document, budget, err := yamltokens.Decode(payload)
	if err != nil {
		// The adapted parser returns exact static sentinels, without wrappers.
		// Direct comparison avoids errors.Is assertion/cache helper work.
		switch err {
		case yamltokens.ErrLimit:
			return nil, ErrYAMLLimit
		case yamltokens.ErrTag:
			return nil, ErrExplicitTag
		default:
			return nil, ErrYAML
		}
	}
	if document == nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, ErrYAML
	}
	root := document.Content[0]
	if err := inspectYAML(root, budget); err != nil {
		return nil, err
	}
	if err := duplicateYAMLKeys(root, budget); err != nil {
		return nil, err
	}
	if err := boundYAMLMaps(root, budget); err != nil {
		return nil, err
	}
	return convertYAML(root, budget)
}

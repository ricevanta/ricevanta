package loader

import (
	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/yamltokens"
	"go.yaml.in/yaml/v3"
)

// decodeVerifiedYAML requires authentication and exact payload equality at its caller.
func decodeVerifiedYAML(payload []byte) (map[string]any, error) {
	m, _, err := decodeVerifiedYAMLAccounted(payload)
	return m, err
}

type yamlUsage struct{ bytes, objects uint64 }

// The scalar snapshot is copied after every stage, including failed reserves.
func decodeVerifiedYAMLAccounted(payload []byte) (map[string]any, yamlUsage, error) {
	document, budget, err := yamltokens.DecodeAccounted(payload)
	if err != nil {
		// The adapted parser returns exact static sentinels, without wrappers.
		// Direct comparison avoids errors.Is assertion/cache helper work.
		switch err {
		case yamltokens.ErrLimit:
			return nil, usageYAML(budget), ErrYAMLLimit
		case yamltokens.ErrTag:
			return nil, usageYAML(budget), ErrExplicitTag
		default:
			return nil, usageYAML(budget), ErrYAML
		}
	}
	if document == nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, usageYAML(budget), ErrYAML
	}
	root := document.Content[0]
	if err := inspectYAML(root, budget); err != nil {
		return nil, usageYAML(budget), err
	}
	if err := duplicateYAMLKeys(root, budget); err != nil {
		return nil, usageYAML(budget), err
	}
	if err := boundYAMLMaps(root, budget); err != nil {
		return nil, usageYAML(budget), err
	}
	m, err := convertYAML(root, budget)
	return m, usageYAML(budget), err
}

func usageYAML(b *yamltokens.Budget) yamlUsage {
	bytes, objects := b.Usage()
	return yamlUsage{bytes, objects}
}

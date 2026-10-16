package config

import (
	"bytes"
	"errors"
	"io"
	"strconv"

	"go.yaml.in/yaml/v3"
)

type nodeKind int

const (
	kindMap nodeKind = iota
	kindString
	kindInt
	kindBool
	kindStringList
)

type shape struct {
	kind   nodeKind
	fields map[string]*shape
}

var (
	str     = &shape{kind: kindString}
	num     = &shape{kind: kindInt}
	boolean = &shape{kind: kindBool}
)

// document is the closed shape of the configuration file. The pre-pass uses
// it to reject unknown keys and YAML types the JSON projection would not
// carry, such as `yes` for a Boolean or a quoted number.
var document = &shape{kind: kindMap, fields: map[string]*shape{
	"schema": str,
	"roles":  {kind: kindStringList},
	"listen": {kind: kindMap, fields: map[string]*shape{
		"api": {kind: kindMap, fields: map[string]*shape{
			"address": str,
			"tls": {kind: kindMap, fields: map[string]*shape{
				"mode":             str,
				"certificate_file": str,
				"key_file":         str,
			}},
		}},
	}},
	"console":  {kind: kindMap, fields: map[string]*shape{"enabled": boolean}},
	"log":      {kind: kindMap, fields: map[string]*shape{"level": str}},
	"http":     {kind: kindMap, fields: map[string]*shape{"read_header_timeout_ms": num, "idle_timeout_ms": num, "max_header_bytes": num}},
	"shutdown": {kind: kindMap, fields: map[string]*shape{"timeout_ms": num}},
}}

// prepass decodes data into yaml.Node trees and requires exactly one
// document whose root is a mapping, no alias, anchor or explicit tag on any
// node, and the closed key and type shape. Duplicate keys are left to the
// struct decoder, which rejects them on its own.
func prepass(data []byte) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return invalid("", "file holds no YAML document")
		}
		return sanitizeYAML(err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return sanitizeYAML(err)
		}
		return invalid("", "file holds more than one YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return invalid("", "file must hold one YAML document")
	}
	if err := plain(&doc, ""); err != nil {
		return err
	}
	return check(doc.Content[0], document, "")
}

// plain rejects aliases, anchors and explicit tags on n.
func plain(n *yaml.Node, path string) error {
	at := lineOf(n, path)
	switch {
	case n.Kind == yaml.AliasNode:
		return invalid(at, "aliases are not allowed")
	case n.Anchor != "":
		return invalid(at, "anchors are not allowed")
	case n.Style&yaml.TaggedStyle != 0:
		return invalid(at, "explicit tags are not allowed")
	}
	return nil
}

func lineOf(n *yaml.Node, path string) string {
	if path == "" {
		return "line " + strconv.Itoa(n.Line)
	}
	return path + " (line " + strconv.Itoa(n.Line) + ")"
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func check(n *yaml.Node, s *shape, path string) error {
	if err := plain(n, path); err != nil {
		return err
	}
	field := path
	if field == "" {
		field = "document root"
	}
	switch s.kind {
	case kindMap:
		if n.Kind != yaml.MappingNode {
			return invalid(lineOf(n, field), "must be a mapping")
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if err := plain(k, path); err != nil {
				return err
			}
			if k.Kind != yaml.ScalarNode || k.ShortTag() != "!!str" {
				return invalid(lineOf(k, field), "keys must be plain strings")
			}
			child, ok := s.fields[k.Value]
			if !ok {
				return invalid(lineOf(k, field), "unknown key")
			}
			if err := check(v, child, join(path, k.Value)); err != nil {
				return err
			}
		}
	case kindString:
		return scalar(n, "!!str", path, "must be a string")
	case kindInt:
		return scalar(n, "!!int", path, "must be an integer")
	case kindBool:
		return scalar(n, "!!bool", path, "must be true or false")
	case kindStringList:
		if n.Kind != yaml.SequenceNode {
			return invalid(lineOf(n, path), "must be a list")
		}
		for _, item := range n.Content {
			if err := plain(item, path); err != nil {
				return err
			}
			if err := scalar(item, "!!str", path, "items must be strings"); err != nil {
				return err
			}
		}
	}
	return nil
}

func scalar(n *yaml.Node, tag, path, reason string) error {
	if n.Kind != yaml.ScalarNode || n.ShortTag() != tag {
		return invalid(lineOf(n, path), "%s", reason)
	}
	return nil
}

// Package loader authenticates bounded extension packages for later admission.
// Production consumers require both parser and complete-loader qualification.
package loader

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strconv"

	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
	"github.com/ricevanta/ricevanta/server/internal/signing/dsse"
)

// Options carries caller authority and the listed-file byte ceiling.
type Options struct {
	AllowReservedID   bool
	MaxTotalFileBytes uint64
}

// File retains an exact, independently owned body and its verified commitment.
type File struct {
	Path   string
	Size   uint64
	SHA256 [32]byte
	Bytes  []byte
}

// Package is owned byte evidence, not installation or publication authority.
type Package struct {
	Archive              []byte
	Manifest             []byte
	Envelope             []byte
	Document             map[string]any
	Files                []File
	PackageSHA256        [32]byte
	ManifestSHA256       [32]byte
	EnvelopeSHA256       [32]byte
	PublisherFingerprint string
}

// Dependencies are per-call values, never shared hooks or mutable caches.
type loadDependencies struct {
	decode   func([]byte) (map[string]any, error)
	validate func(any, manifest.Options) error
}

// Load verifies under a caller-authorized key without extracting or executing.
// The caller owns cancellation, key authority, concurrency and later admission.
func Load(body *io.LimitedReader, authorizedKey ed25519.PublicKey, options Options) (Package, error) {
	return loadWithDependencies(body, authorizedKey, options, loadDependencies{decodeVerifiedYAML, manifest.Validate})
}

func loadWithDependencies(body *io.LimitedReader, key ed25519.PublicKey, options Options, deps loadDependencies) (Package, error) {
	if options.MaxTotalFileBytes > manifest.HardMaxTotalFileBytes {
		return Package{}, ErrOptions
	}
	f := options.MaxTotalFileBytes
	if f == 0 {
		f = manifest.DefaultMaxTotalFileBytes
	}
	// The hard ceiling makes both additions safe before int64 conversion.
	ceiling := f + archiveOverhead + compressedOverhead
	if body == nil || body.R == nil || body.N != int64(ceiling+1) {
		return Package{}, ErrReader
	}
	if len(key) != ed25519.PublicKeySize {
		return Package{}, ErrKey
	}
	archive, members, err := readArchive(body, f)
	if err != nil {
		return Package{}, err
	}
	var payload, envelope []byte
	bodies := make([]member, 0, len(members)-2)
	for _, m := range members {
		switch m.path {
		case "extension.yaml":
			payload = m.body
		case "envelope.json":
			envelope = m.body
		default:
			bodies = append(bodies, m)
		}
	}
	if err = checkPayloadBudget(envelope); err != nil {
		return Package{}, err
	}
	verified, err := dsse.Verify(envelope, dsse.TypeExtensionManifest, key)
	if err != nil {
		return Package{}, err
	}
	if len(verified.Payload) > manifest.MaxManifestBytes {
		return Package{}, ErrPayloadLimit
	}
	if !bytes.Equal(verified.Payload, payload) {
		return Package{}, ErrPayloadMismatch
	}
	document, err := deps.decode(verified.Payload)
	if err != nil {
		return Package{}, err
	}
	if err = deps.validate(document, manifest.Options{AllowReservedID: options.AllowReservedID, MaxTotalFileBytes: options.MaxTotalFileBytes}); err != nil {
		return Package{}, err
	}
	fingerprintHash := sha256.Sum256(key)
	fingerprint := "sha256:" + hex.EncodeToString(fingerprintHash[:])
	publisher := document["metadata"].(map[string]any)["publisher"].(map[string]any)
	if publisher["key"].(string) != fingerprint {
		return Package{}, ErrPublisher
	}
	// Validation establishes the concrete types and lexemes below. Sort private
	// evidence, then finish each whole-file stage before entering the next one.
	listed := document["files"].([]any)
	if len(bodies) != len(listed) {
		return Package{}, ErrFileSet
	}
	commitments := make([]File, len(listed))
	for i, item := range listed {
		fields := item.(map[string]any)
		size, _ := strconv.ParseUint(string(fields["size"].(json.Number)), 10, 64)
		commitments[i].Path = fields["path"].(string)
		commitments[i].Size = size
		// The validator proves exactly 64 lowercase hex digits.
		_, _ = hex.Decode(commitments[i].SHA256[:], []byte(fields["sha256"].(string)))
	}
	sort.Slice(commitments, func(i, j int) bool { return commitments[i].Path < commitments[j].Path })
	sort.Slice(bodies, func(i, j int) bool { return bodies[i].path < bodies[j].path })
	for i, m := range bodies {
		if m.path != commitments[i].Path {
			return Package{}, ErrFileSet
		}
	}
	for i, m := range bodies {
		if uint64(len(m.body)) != commitments[i].Size {
			return Package{}, ErrFileSize
		}
	}
	for i, m := range bodies {
		if sha256.Sum256(m.body) != commitments[i].SHA256 {
			return Package{}, ErrFileDigest
		}
	}
	// Nothing exported is materialized until every authentication/binding check
	// succeeds. Each byte slice gets its own storage, independent of all inputs.
	for i, m := range bodies {
		commitments[i].Bytes = bytes.Clone(m.body)
	}
	return Package{
		Archive: bytes.Clone(archive), Manifest: bytes.Clone(verified.Payload), Envelope: bytes.Clone(envelope),
		Document: document, Files: commitments, PackageSHA256: sha256.Sum256(archive), ManifestSHA256: sha256.Sum256(verified.Payload),
		EnvelopeSHA256: verified.EnvelopeSHA256, PublisherFingerprint: fingerprint,
	}, nil
}

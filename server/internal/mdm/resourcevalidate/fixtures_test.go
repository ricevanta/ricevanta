package resourcevalidate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
)

type fixtureRecord struct {
	File       string `json:"file"`
	Structural bool   `json:"structural"`
	Accepted   bool   `json:"accepted"`
	Sentinel   string `json:"sentinel"`
	Path       string `json:"path"`
	Rule       string `json:"rule"`
}

func fixtureDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "../../../../schemas/policy/v1alpha1/fixtures/mdm")
}

// Parse fixtures without accepting duplicate members or nonfinite numbers.
func strictJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var read func() (any, error)
	read = func() (any, error) {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		switch tok {
		case json.Delim('{'):
			m := map[string]any{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return nil, err
				}
				key, ok := k.(string)
				if !ok {
					return nil, errors.New("key type")
				}
				if _, ok = m[key]; ok {
					return nil, errors.New("duplicate key")
				}
				v, err := read()
				if err != nil {
					return nil, err
				}
				m[key] = v
			}
			_, err = d.Token()
			return m, err
		case json.Delim('['):
			a := []any{}
			for d.More() {
				v, err := read()
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err = d.Token()
			return a, err
		default:
			return tok, nil
		}
	}
	v, err := read()
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return v, nil
}
func readFixture(t testing.TB, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	v, err := strictJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatal("fixture is not object")
	}
	return m
}
func fixtureRecords(t testing.TB) []fixtureRecord {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir(), "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	records, err := decodeManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	pattern := regexp.MustCompile(`^(valid|invalid)/mdm-[a-z0-9-]+\.json$`)
	for _, r := range records {
		if !pattern.MatchString(r.File) || seen[r.File] {
			t.Fatalf("bad manifest file %q", r.File)
		}
		seen[r.File] = true
		if strings.HasPrefix(r.File, "valid/") != r.Accepted {
			t.Fatalf("fixture placement %s", r.File)
		}
		if r.Accepted {
			if r.Sentinel != "" || r.Path != "" || r.Rule != "" || !r.Structural {
				t.Fatalf("success metadata %s", r.File)
			}
		} else if sentinel(r.Sentinel) == nil || r.Rule == "" {
			t.Fatalf("failure metadata %s", r.File)
		}
	}
	err = filepath.WalkDir(fixtureDir(), func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.Type()&os.ModeSymlink != 0 {
			return errors.New("fixture symlink")
		}
		if e.IsDir() {
			return nil
		}
		name, err := filepath.Rel(fixtureDir(), p)
		if err != nil {
			return err
		}
		name = filepath.ToSlash(name)
		if name != "manifest.json" && !seen[name] {
			return errors.New("fixture missing from manifest: " + name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return records
}
func sentinel(s string) error {
	switch s {
	case "ErrInput":
		return ErrInput
	case "ErrLimit":
		return ErrLimit
	case "ErrEnvelope":
		return ErrEnvelope
	case "ErrSchema":
		return ErrSchema
	case "ErrSemantic":
		return ErrSemantic
	}
	return nil
}
func checkError(t testing.TB, m map[string]any, want error, path, rule string) {
	t.Helper()
	r, err := Validate(m)
	if !errors.Is(err, want) || !reflect.DeepEqual(r, Result{}) {
		t.Fatalf("Validate = %+v, %v; want zero, %v", r, err, want)
	}
	var e *Error
	if !errors.As(err, &e) || e.Path != path || e.Rule != rule {
		t.Fatalf("error = %+v; want %s at %s", e, rule, path)
	}
	if err.Error() != "mdm validation "+rule+" at "+path {
		t.Fatalf("error text %q", err.Error())
	}
}
func expectedResult(m map[string]any) Result {
	r := Result{Kind: m["kind"].(string), Name: m["metadata"].(map[string]any)["name"].(string)}
	if r.Kind == "SoftwarePackage" {
		r.RequiresContentApproval = true
	}
	if r.Kind == "Baseline" {
		for _, v := range m["spec"].(map[string]any)["items"].([]any) {
			it := v.(map[string]any)
			if it["kind"] != "check.query" && it["kind"] != "check.collector" {
				r.RequiresContentApproval = true
				r.ApplyItemIDs = append(r.ApplyItemIDs, it["id"].(string))
			}
		}
	}
	return r
}
func runFixtures(t *testing.T) {
	for _, c := range fixtureRecords(t) {
		t.Run(c.File, func(t *testing.T) {
			m := readFixture(t, c.File)
			shapeError := envelope(m)
			if shapeError == nil {
				shapeError = structural(m)
			}
			if (shapeError == nil) != c.Structural {
				t.Fatalf("structural outcome %v, want %v", shapeError, c.Structural)
			}
			if !c.Accepted {
				checkError(t, m, sentinel(c.Sentinel), c.Path, c.Rule)
				return
			}
			r, err := Validate(m)
			if err != nil || !reflect.DeepEqual(r, expectedResult(m)) {
				t.Fatalf("result %+v error %v", r, err)
			}
		})
	}
}
func TestValidateFixtures(t *testing.T) { runFixtures(t) }
func TestFixtureDrift(t *testing.T) {
	runFixtures(t)
	directory := filepath.Join(fixtureDir(), "../../baseline")
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 17 {
		t.Fatalf("settings schema count %d", len(entries))
	}
	for _, entry := range entries {
		b, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		v, err := strictJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		s := v.(map[string]any)
		kind := strings.TrimSuffix(entry.Name(), ".json")
		if !knownKind(kind) || s["title"] != kind {
			t.Fatalf("unknown settings schema %s", entry.Name())
		}
		_, apply := kindClass(kind)
		effect := "check"
		if apply {
			effect = "apply"
		}
		if s["x-ricevanta-effect"] != effect || s["x-ricevanta-protected-publication"] != apply {
			t.Fatalf("classification drift for %s", kind)
		}
	}
}

type fixtureBranch struct {
	key      string
	positive []string
	negative string
}

func TestManifestRecordCompleteness(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(fixtureDir(), "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := strictJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	records := v.([]any)
	for _, index := range []int{0, len(records) - 1} {
		original := records[index].(map[string]any)
		for _, field := range []string{"file", "structural", "accepted", "sentinel", "path", "rule"} {
			for _, mutation := range []string{"missing", "null", "wrong-type"} {
				t.Run(field+"/"+mutation, func(t *testing.T) {
					copy := map[string]any{}
					for k, v := range original {
						copy[k] = v
					}
					switch mutation {
					case "missing":
						delete(copy, field)
					case "null":
						copy[field] = nil
					case "wrong-type":
						copy[field] = []any{}
					}
					data, err := json.Marshal([]any{copy})
					if err != nil {
						t.Fatal(err)
					}
					if _, err = decodeManifest(data); err == nil {
						t.Fatalf("accepted %s %s", field, mutation)
					}
				})
			}
		}
	}
	for _, data := range []string{`null`, `{}`, `[null]`, `[{"file":"a","file":"b"}]`, `[{"x":NaN}]`} {
		if _, err := decodeManifest([]byte(data)); err == nil {
			t.Fatalf("accepted manifest %s", data)
		}
	}
	if _, err = decodeManifest(b); err != nil {
		t.Fatal(err)
	}
}
func TestFixtureCompleteness(t *testing.T) {
	records := fixtureRecords(t)
	if err := checkBranchCoverage(records, requiredBranches); err != nil {
		t.Fatal(err)
	}
	for _, branch := range requiredBranches {
		names := append(append([]string{}, branch.positive...), branch.negative)
		subset := []fixtureRecord{}
		for _, r := range records {
			for _, name := range names {
				if r.File == name {
					subset = append(subset, r)
				}
			}
		}
		if err := checkBranchCoverage(subset, []fixtureBranch{branch}); err != nil {
			t.Fatalf("branch %s: %v", branch.key, err)
		}
		// Every listed positive and paired negative is a required record. No
		// directory or filename convention can hide a removed branch fixture.
		for _, name := range names {
			remaining := []fixtureRecord{}
			for _, r := range subset {
				if r.File != name {
					remaining = append(remaining, r)
				}
			}
			if err := checkBranchCoverage(remaining, []fixtureBranch{branch}); err == nil {
				t.Fatalf("missing %s escaped coverage for %s", name, branch.key)
			}
		}
	}
}

var requiredBranches = []fixtureBranch{
	{"baseline/apple.declaration/macos", []string{"valid/mdm-apple-declaration-macos-minimum.json", "valid/mdm-apple-declaration-macos-populated.json"}, "invalid/mdm-contract-item-apple-declaration-missing-settings.json"},
	{"baseline/apple.profile/macos", []string{"valid/mdm-apple-profile-macos-minimum.json", "valid/mdm-apple-profile-macos-populated.json"}, "invalid/mdm-contract-item-apple-profile-missing-settings.json"},
	{"baseline/windows.csp/windows", []string{"valid/mdm-windows-csp-windows-minimum.json", "valid/mdm-windows-csp-windows-populated.json"}, "invalid/mdm-contract-item-windows-csp-missing-settings.json"},
	{"baseline/windows.registry/windows", []string{"valid/mdm-windows-registry-windows-minimum.json", "valid/mdm-windows-registry-windows-populated.json"}, "invalid/mdm-contract-item-windows-registry-missing-settings.json"},
	{"baseline/windows.service/windows", []string{"valid/mdm-windows-service-windows-minimum.json", "valid/mdm-windows-service-windows-populated.json"}, "invalid/mdm-contract-item-windows-service-missing-settings.json"},
	{"baseline/linux.dconf/linux", []string{"valid/mdm-linux-dconf-linux-minimum.json", "valid/mdm-linux-dconf-linux-populated.json"}, "invalid/mdm-contract-item-linux-dconf-missing-settings.json"},
	{"baseline/linux.polkit/linux", []string{"valid/mdm-linux-polkit-linux-minimum.json", "valid/mdm-linux-polkit-linux-populated.json"}, "invalid/mdm-contract-item-linux-polkit-missing-settings.json"},
	{"baseline/linux.sysctl/linux", []string{"valid/mdm-linux-sysctl-linux-minimum.json", "valid/mdm-linux-sysctl-linux-populated.json"}, "invalid/mdm-contract-item-linux-sysctl-missing-settings.json"},
	{"baseline/linux.systemd/linux", []string{"valid/mdm-linux-systemd-linux-minimum.json", "valid/mdm-linux-systemd-linux-populated.json"}, "invalid/mdm-contract-item-linux-systemd-missing-settings.json"},
	{"baseline/linux.pam/linux", []string{"valid/mdm-linux-pam-linux-minimum.json", "valid/mdm-linux-pam-linux-populated.json"}, "invalid/mdm-contract-item-linux-pam-missing-settings.json"},
	{"baseline/linux.file/linux", []string{"valid/mdm-linux-file-linux-minimum.json", "valid/mdm-linux-file-linux-populated.json"}, "invalid/mdm-contract-item-linux-file-missing-settings.json"},
	{"baseline/linux.repository/linux", []string{"valid/mdm-linux-repository-linux-minimum.json", "valid/mdm-linux-repository-linux-populated.json"}, "invalid/mdm-contract-item-linux-repository-missing-settings.json"},
	{"baseline/software/macos", []string{"valid/mdm-software-macos-minimum.json", "valid/mdm-software-macos-populated.json"}, "invalid/mdm-contract-item-software-missing-settings.json"},
	{"baseline/software/windows", []string{"valid/mdm-software-windows-minimum.json", "valid/mdm-software-windows-populated.json"}, "invalid/mdm-contract-item-software-missing-settings.json"},
	{"baseline/software/linux", []string{"valid/mdm-software-linux-minimum.json", "valid/mdm-software-linux-populated.json"}, "invalid/mdm-contract-item-software-missing-settings.json"},
	{"baseline/check.query/macos", []string{"valid/mdm-check-query-macos-minimum.json", "valid/mdm-check-query-macos-populated.json"}, "invalid/mdm-contract-item-check-query-missing-settings.json"},
	{"baseline/check.query/windows", []string{"valid/mdm-check-query-windows-minimum.json", "valid/mdm-check-query-windows-populated.json"}, "invalid/mdm-contract-item-check-query-missing-settings.json"},
	{"baseline/check.query/linux", []string{"valid/mdm-check-query-linux-minimum.json", "valid/mdm-check-query-linux-populated.json"}, "invalid/mdm-contract-item-check-query-missing-settings.json"},
	{"baseline/check.collector/macos", []string{"valid/mdm-check-collector-macos-minimum.json", "valid/mdm-check-collector-macos-populated.json"}, "invalid/mdm-contract-item-check-collector-missing-settings.json"},
	{"baseline/check.collector/windows", []string{"valid/mdm-check-collector-windows-minimum.json", "valid/mdm-check-collector-windows-populated.json"}, "invalid/mdm-contract-item-check-collector-missing-settings.json"},
	{"baseline/check.collector/linux", []string{"valid/mdm-check-collector-linux-minimum.json", "valid/mdm-check-collector-linux-populated.json"}, "invalid/mdm-contract-item-check-collector-missing-settings.json"},
	{"baseline/os_update/macos", []string{"valid/mdm-os-update-macos-minimum.json", "valid/mdm-os-update-macos-populated.json"}, "invalid/mdm-contract-item-os-update-missing-settings.json"},
	{"baseline/os_update/windows", []string{"valid/mdm-os-update-windows-minimum.json", "valid/mdm-os-update-windows-populated.json"}, "invalid/mdm-contract-item-os-update-missing-settings.json"},
	{"baseline/os_update/linux", []string{"valid/mdm-os-update-linux-minimum.json", "valid/mdm-os-update-linux-populated.json"}, "invalid/mdm-contract-item-os-update-missing-settings.json"},
	{"baseline/encryption/macos", []string{"valid/mdm-encryption-macos-minimum.json", "valid/mdm-encryption-macos-populated.json"}, "invalid/mdm-contract-item-encryption-missing-settings.json"},
	{"baseline/encryption/windows", []string{"valid/mdm-encryption-windows-minimum.json", "valid/mdm-encryption-windows-populated.json"}, "invalid/mdm-contract-item-encryption-missing-settings.json"},
	{"baseline/encryption/linux", []string{"valid/mdm-encryption-linux-minimum.json", "valid/mdm-encryption-linux-populated.json"}, "invalid/mdm-contract-item-encryption-missing-settings.json"},
	{"package/macos/pkg/blob/developer-id/bundle", []string{"valid/mdm-package-macos-pkg-blob-developer-id-bundle.json"}, "invalid/mdm-package-macos-pkg-blob-developer-id-bundle-signature-mismatch.json"},
	{"package/macos/pkg/blob/none/bundle", []string{"valid/mdm-package-macos-pkg-blob-none-bundle.json"}, "invalid/mdm-package-macos-pkg-blob-none-bundle-unsigned-false.json"},
	{"package/macos/homebrew-formula/homebrew/checksum/package", []string{"valid/mdm-package-macos-homebrew-formula-homebrew-checksum-package.json"}, "invalid/mdm-package-macos-homebrew-formula-homebrew-checksum-package-signature-mismatch.json"},
	{"package/macos/homebrew-formula/homebrew/none/package", []string{"valid/mdm-package-macos-homebrew-formula-homebrew-none-package.json"}, "invalid/mdm-package-macos-homebrew-formula-homebrew-none-package-unsigned-false.json"},
	{"package/macos/homebrew-cask/homebrew/checksum/bundle", []string{"valid/mdm-package-macos-homebrew-cask-homebrew-checksum-bundle.json"}, "invalid/mdm-package-macos-homebrew-cask-homebrew-checksum-bundle-signature-mismatch.json"},
	{"package/macos/homebrew-cask/homebrew/none/bundle", []string{"valid/mdm-package-macos-homebrew-cask-homebrew-none-bundle.json"}, "invalid/mdm-package-macos-homebrew-cask-homebrew-none-bundle-unsigned-false.json"},
	{"package/windows/msi/blob/authenticode/msi", []string{"valid/mdm-package-windows-msi-blob-authenticode-msi.json"}, "invalid/mdm-package-windows-msi-blob-authenticode-msi-signature-mismatch.json"},
	{"package/windows/msi/blob/none/msi", []string{"valid/mdm-package-windows-msi-blob-none-msi.json"}, "invalid/mdm-package-windows-msi-blob-none-msi-unsigned-false.json"},
	{"package/windows/msix/blob/msix/msix", []string{"valid/mdm-package-windows-msix-blob-msix-msix.json"}, "invalid/mdm-package-windows-msix-blob-msix-msix-signature-mismatch.json"},
	{"package/windows/msix/blob/none/msix", []string{"valid/mdm-package-windows-msix-blob-none-msix.json"}, "invalid/mdm-package-windows-msix-blob-none-msix-unsigned-false.json"},
	{"package/windows/exe/blob/authenticode/uninstall", []string{"valid/mdm-package-windows-exe-blob-authenticode-uninstall.json"}, "invalid/mdm-package-windows-exe-blob-authenticode-uninstall-signature-mismatch.json"},
	{"package/windows/exe/blob/none/uninstall", []string{"valid/mdm-package-windows-exe-blob-none-uninstall.json"}, "invalid/mdm-package-windows-exe-blob-none-uninstall-unsigned-false.json"},
	{"package/windows/winget/winget/authenticode/uninstall", []string{"valid/mdm-package-windows-winget-winget-authenticode-uninstall.json"}, "invalid/mdm-package-windows-winget-winget-authenticode-uninstall-signature-mismatch.json"},
	{"package/windows/winget/winget/none/uninstall", []string{"valid/mdm-package-windows-winget-winget-none-uninstall.json"}, "invalid/mdm-package-windows-winget-winget-none-uninstall-unsigned-false.json"},
	{"package/windows/winget/winget/msix/msix", []string{"valid/mdm-package-windows-winget-winget-msix-msix.json"}, "invalid/mdm-package-windows-winget-winget-msix-msix-signature-mismatch.json"},
	{"package/windows/winget/winget/none/msix", []string{"valid/mdm-package-windows-winget-winget-none-msix.json"}, "invalid/mdm-package-windows-winget-winget-none-msix-unsigned-false.json"},
	{"package/linux/deb/blob/none/package", []string{"valid/mdm-package-linux-deb-blob-none-package.json"}, "invalid/mdm-package-linux-deb-blob-none-package-unsigned-false.json"},
	{"package/linux/deb/apt/openpgp/package", []string{"valid/mdm-package-linux-deb-apt-openpgp-package.json"}, "invalid/mdm-package-linux-deb-apt-openpgp-package-signature-mismatch.json"},
	{"package/linux/deb/apt/none/package", []string{"valid/mdm-package-linux-deb-apt-none-package.json"}, "invalid/mdm-package-linux-deb-apt-none-package-unsigned-false.json"},
	{"package/linux/rpm/blob/openpgp/package", []string{"valid/mdm-package-linux-rpm-blob-openpgp-package.json"}, "invalid/mdm-package-linux-rpm-blob-openpgp-package-signature-mismatch.json"},
	{"package/linux/rpm/blob/none/package", []string{"valid/mdm-package-linux-rpm-blob-none-package.json"}, "invalid/mdm-package-linux-rpm-blob-none-package-unsigned-false.json"},
	{"package/linux/rpm/dnf/openpgp/package", []string{"valid/mdm-package-linux-rpm-dnf-openpgp-package.json"}, "invalid/mdm-package-linux-rpm-dnf-openpgp-package-signature-mismatch.json"},
	{"package/linux/rpm/dnf/none/package", []string{"valid/mdm-package-linux-rpm-dnf-none-package.json"}, "invalid/mdm-package-linux-rpm-dnf-none-package-unsigned-false.json"},
	{"package/linux/rpm/zypper/openpgp/package", []string{"valid/mdm-package-linux-rpm-zypper-openpgp-package.json"}, "invalid/mdm-package-linux-rpm-zypper-openpgp-package-signature-mismatch.json"},
	{"package/linux/rpm/zypper/none/package", []string{"valid/mdm-package-linux-rpm-zypper-none-package.json"}, "invalid/mdm-package-linux-rpm-zypper-none-package-unsigned-false.json"},
	{"package/linux/flatpak/flatpak/openpgp/package", []string{"valid/mdm-package-linux-flatpak-flatpak-openpgp-package.json"}, "invalid/mdm-package-linux-flatpak-flatpak-openpgp-package-signature-mismatch.json"},
	{"package/linux/flatpak/flatpak/none/package", []string{"valid/mdm-package-linux-flatpak-flatpak-none-package.json"}, "invalid/mdm-package-linux-flatpak-flatpak-none-package-unsigned-false.json"},
	{"authority/windows.csp/agent", []string{"valid/mdm-windows-csp-windows-populated.json"}, "invalid/mdm-contract-item-windows-csp-missing-settings.json"},
	{"authority/windows.csp/native", []string{"valid/mdm-windows-csp-windows-minimum.json"}, "invalid/mdm-contract-item-windows-csp-missing-settings.json"},
	{"csp/Device/b64", []string{"valid/mdm-csp-b64-native.json"}, "invalid/mdm-contract-item-windows-csp-missing-settings.json"},
	{"csp/Device/bool", []string{"valid/mdm-csp-bool-native.json"}, "invalid/mdm-contract-item-windows-csp-missing-settings.json"},
	{"csp/Device/chr", []string{"valid/mdm-csp-chr-native.json"}, "invalid/mdm-contract-item-windows-csp-missing-settings.json"},
	{"csp/Device/int", []string{"valid/mdm-windows-csp-windows-minimum.json"}, "invalid/mdm-contract-item-windows-csp-missing-settings.json"},
	{"csp/Device/xml", []string{"valid/mdm-csp-xml-native.json"}, "invalid/mdm-contract-item-windows-csp-missing-settings.json"},
	{"csp/User/b64", []string{"valid/mdm-csp-user-b64.json"}, "invalid/mdm-contract-item-windows-csp-missing-settings.json"},
	{"csp/User/bool", []string{"valid/mdm-csp-user-bool.json"}, "invalid/mdm-contract-item-windows-csp-missing-settings.json"},
	{"csp/User/chr", []string{"valid/mdm-csp-user-chr.json"}, "invalid/mdm-contract-item-windows-csp-missing-settings.json"},
	{"csp/User/int", []string{"valid/mdm-csp-user-int.json"}, "invalid/mdm-contract-item-windows-csp-missing-settings.json"},
	{"csp/User/xml", []string{"valid/mdm-csp-user-xml.json"}, "invalid/mdm-contract-item-windows-csp-missing-settings.json"},
	{"group/selector", []string{"valid/mdm-group-in.json"}, "invalid/mdm-contract-group-spec-unknown.json"},
	{"group/static", []string{"valid/mdm-group-static.json"}, "invalid/mdm-contract-group-spec-unknown.json"},
	{"group/union", []string{"valid/mdm-group-union.json"}, "invalid/mdm-contract-group-spec-unknown.json"},
	{"group-field/matchLabels", []string{"valid/mdm-group-selector-labels.json"}, "invalid/mdm-group-empty-or-duplicate-1267.json"},
	{"group-field/matchExpressions", []string{"valid/mdm-group-in.json"}, "invalid/mdm-group-empty-or-duplicate-1268.json"},
	{"group-field/os", []string{"valid/mdm-group-selector-os.json"}, "invalid/mdm-group-empty-or-duplicate-1269.json"},
	{"interaction/defer-while-running", []string{"valid/mdm-exe-none-defer-while-running.json"}, "invalid/mdm-contract-package-spec-pkg-missing-allowedgroups.json"},
	{"interaction/silent", []string{"valid/mdm-package-macos-pkg-blob-developer-id-bundle.json"}, "invalid/mdm-contract-package-spec-pkg-missing-allowedgroups.json"},
	{"operator/DoesNotExist", []string{"valid/mdm-group-doesnotexist.json"}, "invalid/mdm-contract-group-spec-unknown.json"},
	{"operator/Exists", []string{"valid/mdm-group-exists.json"}, "invalid/mdm-contract-group-spec-unknown.json"},
	{"operator/In", []string{"valid/mdm-group-in.json"}, "invalid/mdm-contract-group-spec-unknown.json"},
	{"operator/NotIn", []string{"valid/mdm-group-notin.json"}, "invalid/mdm-contract-group-spec-unknown.json"},
	{"pam/both", []string{"valid/mdm-pam-both.json"}, "invalid/mdm-contract-item-linux-pam-missing-settings.json"},
	{"pam/faillock", []string{"valid/mdm-pam-faillock.json"}, "invalid/mdm-contract-item-linux-pam-missing-settings.json"},
	{"pam/pwquality", []string{"valid/mdm-linux-pam-linux-minimum.json"}, "invalid/mdm-contract-item-linux-pam-missing-settings.json"},
	{"reboot/exit-code", []string{"valid/mdm-exe-exit-code-silent.json"}, "invalid/mdm-contract-package-spec-pkg-missing-allowedgroups.json"},
	{"reboot/none", []string{"valid/mdm-package-macos-pkg-blob-developer-id-bundle.json"}, "invalid/mdm-contract-package-spec-pkg-missing-allowedgroups.json"},
	{"reboot/required", []string{"valid/mdm-exe-required-silent.json"}, "invalid/mdm-contract-package-spec-pkg-missing-allowedgroups.json"},
	{"registry/binary", []string{"valid/mdm-registry-binary.json"}, "invalid/mdm-contract-item-windows-registry-missing-settings.json"},
	{"registry/dword", []string{"valid/mdm-registry-dword.json"}, "invalid/mdm-contract-item-windows-registry-missing-settings.json"},
	{"registry/expand-string", []string{"valid/mdm-registry-expand-string.json"}, "invalid/mdm-contract-item-windows-registry-missing-settings.json"},
	{"registry/multi-string", []string{"valid/mdm-registry-multi-string.json"}, "invalid/mdm-contract-item-windows-registry-missing-settings.json"},
	{"registry/qword", []string{"valid/mdm-registry-qword.json"}, "invalid/mdm-contract-item-windows-registry-missing-settings.json"},
	{"registry/string", []string{"valid/mdm-windows-registry-windows-minimum.json"}, "invalid/mdm-contract-item-windows-registry-missing-settings.json"},
	{"repository/apt", []string{"valid/mdm-linux-repository-linux-minimum.json"}, "invalid/mdm-contract-item-linux-repository-missing-settings.json"},
	{"repository/dnf", []string{"valid/mdm-repository-dnf.json"}, "invalid/mdm-contract-item-linux-repository-missing-settings.json"},
	{"repository/flatpak", []string{"valid/mdm-repository-flatpak.json"}, "invalid/mdm-contract-item-linux-repository-missing-settings.json"},
	{"repository/zypper", []string{"valid/mdm-repository-zypper.json"}, "invalid/mdm-contract-item-linux-repository-missing-settings.json"},
	{"systemd/both", []string{"valid/mdm-systemd-both.json"}, "invalid/mdm-contract-item-linux-systemd-missing-settings.json"},
	{"systemd/dropIn", []string{"valid/mdm-systemd-drop-in.json"}, "invalid/mdm-contract-item-linux-systemd-missing-settings.json"},
	{"systemd/state", []string{"valid/mdm-linux-systemd-linux-minimum.json"}, "invalid/mdm-contract-item-linux-systemd-missing-settings.json"},
}

func decodeManifest(data []byte) ([]fixtureRecord, error) {
	v, err := strictJSON(data)
	if err != nil {
		return nil, err
	}
	entries, ok := v.([]any)
	if !ok {
		return nil, errors.New("manifest must be array")
	}
	for _, entry := range entries {
		m, ok := entry.(map[string]any)
		if !ok || len(m) != 6 {
			return nil, errors.New("manifest record fields")
		}
		for _, k := range []string{"file", "sentinel", "path", "rule"} {
			if _, ok := m[k].(string); !ok {
				return nil, errors.New("manifest string field: " + k)
			}
		}
		for _, k := range []string{"structural", "accepted"} {
			if _, ok := m[k].(bool); !ok {
				return nil, errors.New("manifest boolean field: " + k)
			}
		}
	}
	var records []fixtureRecord
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(&records); err != nil {
		return nil, err
	}
	return records, nil
}
func checkBranchCoverage(records []fixtureRecord, branches []fixtureBranch) error {
	index := map[string]fixtureRecord{}
	for _, r := range records {
		if _, ok := index[r.File]; ok {
			return fmt.Errorf("duplicate coverage record %s", r.File)
		}
		index[r.File] = r
	}
	for _, b := range branches {
		for _, name := range b.positive {
			r, ok := index[name]
			if !ok || !r.Accepted {
				return fmt.Errorf("%s lacks positive %s", b.key, name)
			}
			data, err := os.ReadFile(filepath.Join(fixtureDir(), name))
			if err != nil {
				return err
			}
			v, err := strictJSON(data)
			if err != nil {
				return err
			}
			m, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("%s not object", name)
			}
			if !fixtureBranchKeys(m)[b.key] {
				return fmt.Errorf("%s does not cover %s", name, b.key)
			}
		}
		if r, ok := index[b.negative]; !ok || r.Accepted {
			return fmt.Errorf("%s lacks paired negative %s", b.key, b.negative)
		}
	}
	return nil
}

// Coverage keys follow resource fields. Required tables remain independent of
// production discriminators and refer to explicit manifest records.
func fixtureBranchKeys(m map[string]any) map[string]bool {
	out := map[string]bool{}
	s := m["spec"].(map[string]any)
	switch m["kind"] {
	case "Baseline":
		for _, x := range s["items"].([]any) {
			it := x.(map[string]any)
			kind := it["kind"].(string)
			v := it["settings"].(map[string]any)
			out["baseline/"+kind+"/"+s["os"].(string)] = true
			switch kind {
			case "windows.csp":
				out["csp/"+strings.Split(v["locUri"].(string), "/")[1]+"/"+v["format"].(string)] = true
				authority := "native"
				if a, ok := it["authority"].(string); ok {
					authority = a
				}
				out["authority/windows.csp/"+authority] = true
			case "windows.registry":
				out["registry/"+v["type"].(string)] = true
			case "linux.pam":
				_, pw := v["pwquality"]
				_, fl := v["faillock"]
				branch := "both"
				if !pw {
					branch = "faillock"
				} else if !fl {
					branch = "pwquality"
				}
				out["pam/"+branch] = true
			case "linux.systemd":
				_, state := v["state"]
				_, drop := v["dropIn"]
				branch := "both"
				if !state {
					branch = "dropIn"
				} else if !drop {
					branch = "state"
				}
				out["systemd/"+branch] = true
			case "linux.repository":
				out["repository/"+v["manager"].(string)] = true
			}
		}
	case "SoftwarePackage":
		source := s["source"].(map[string]any)
		signature := s["signature"].(map[string]any)
		detection := s["detection"].(map[string]any)
		manager := "blob"
		if source["type"] == "repository" {
			manager = source["manager"].(string)
		}
		out["package/"+strings.Join([]string{s["os"].(string), s["format"].(string), manager, signature["type"].(string), detection["type"].(string)}, "/")] = true
		out["reboot/"+s["reboot"].(map[string]any)["mode"].(string)] = true
		out["interaction/"+s["interaction"].(map[string]any)["mode"].(string)] = true
	case "DeviceGroup":
		_, members := s["members"]
		selector, selected := s["selector"].(map[string]any)
		branch := "union"
		if !members {
			branch = "selector"
		} else if !selected {
			branch = "static"
		}
		out["group/"+branch] = true
		if selected {
			for _, field := range []string{"matchLabels", "matchExpressions", "os"} {
				if _, exists := selector[field]; exists {
					out["group-field/"+field] = true
				}
			}
			if a, ok := selector["matchExpressions"].([]any); ok {
				for _, x := range a {
					out["operator/"+x.(map[string]any)["operator"].(string)] = true
				}
			}
		}
	}
	return out
}

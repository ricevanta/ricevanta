package admission

import "strconv"

type componentPair struct{ kind, iface string }

// componentPairs are the kind and interface pairs the manifest schema defines.
var componentPairs = []componentPair{
	{"content", "ext.ricevanta.io/content/v1"},
	{"browser-adapter", "ext.ricevanta.io/browser-adapter/v1"},
	{"agent-module", "ricevanta:agent/classifier@1.0.0"},
	{"agent-module", "ricevanta:agent/parser@1.0.0"},
	{"agent-module", "ricevanta:agent/collector@1.0.0"},
	{"agent-module", "ricevanta:agent/responder@1.0.0"},
	{"console-module", "ext.ricevanta.io/console-module/v1"},
	{"service-connector", "ext.ricevanta.io/export-destination/v1"},
	{"service-connector", "ext.ricevanta.io/ca-connector/v1"},
	{"service-connector", "ext.ricevanta.io/notifier/v1"},
	{"service-connector", "ext.ricevanta.io/enricher/v1"},
}

const (
	kindContent          = "content"
	kindBrowserAdapter   = "browser-adapter"
	kindAgentModule      = "agent-module"
	kindConsoleModule    = "console-module"
	kindServiceConnector = "service-connector"

	ifaceClassifier = "ricevanta:agent/classifier@1.0.0"
	ifaceParser     = "ricevanta:agent/parser@1.0.0"
	ifaceCollector  = "ricevanta:agent/collector@1.0.0"
	ifaceResponder  = "ricevanta:agent/responder@1.0.0"
)

func definedPair(kind, iface string) bool {
	for _, p := range componentPairs {
		if p.kind == kind && p.iface == iface {
			return true
		}
	}
	return false
}

var (
	slotNames         = []string{"navigation", "device-tab", "alert-panel", "finding-panel", "dashboard-panel", "settings"}
	consoleOperations = []string{"listDevices", "getDevice", "getDeviceInventory", "listDeviceSoftware", "getDeviceCapabilities", "getDevicePolicyState",
		"getDeviceFootprint", "listComplianceResults", "listAlerts", "getAlert", "listInvestigations", "listResponseActions", "listDlpFindings",
		"getDlpFinding", "listClassifications", "listExceptions", "queryLineage", "getLineageEdge", "updateAlert", "createInvestigation",
		"updateInvestigation", "updateDlpFinding", "createResponseAction"}
	responderActions = []string{"edr.kill_process", "edr.quarantine_file", "edr.restore_file", "edr.isolate_host", "edr.unisolate_host",
		"edr.kill_and_ban", "edr.unban", "edr.collect", "edr.scan"}
)

// agentField names one numeric agent-module value with its schema ceiling.
type agentField struct {
	name    string
	ceiling uint64
	get     func(*AgentModuleValues) *uint64
}

var (
	budgetFields = []agentField{
		{"memory_pages", 4096, func(v *AgentModuleValues) *uint64 { return &v.MemoryPages }},
		{"fuel_per_call", 1000000000, func(v *AgentModuleValues) *uint64 { return &v.FuelPerCall }},
		{"deadline_ms", 60000, func(v *AgentModuleValues) *uint64 { return &v.DeadlineMS }},
	}
	collectorFields = []agentField{
		{"max_roots", 16, func(v *AgentModuleValues) *uint64 { return &v.MaxRoots }},
		{"max_path_depth", 32, func(v *AgentModuleValues) *uint64 { return &v.MaxPathDepth }},
		{"max_directory_entries", 10000, func(v *AgentModuleValues) *uint64 { return &v.MaxDirectoryEntries }},
		{"max_open_handles", 64, func(v *AgentModuleValues) *uint64 { return &v.MaxOpenHandles }},
		{"max_list_requests", 1024, func(v *AgentModuleValues) *uint64 { return &v.MaxListRequests }},
		{"max_read_requests", 4096, func(v *AgentModuleValues) *uint64 { return &v.MaxReadRequests }},
		{"max_bytes_per_file", 16777216, func(v *AgentModuleValues) *uint64 { return &v.MaxBytesPerFile }},
		{"max_input_bytes", 67108864, func(v *AgentModuleValues) *uint64 { return &v.MaxInputBytes }},
		{"max_rows", 10000, func(v *AgentModuleValues) *uint64 { return &v.MaxRows }},
		{"max_output_bytes", 16777216, func(v *AgentModuleValues) *uint64 { return &v.MaxOutputBytes }},
	}
	responderFields = []agentField{
		{"max_entities", 256, func(v *AgentModuleValues) *uint64 { return &v.MaxEntities }},
		{"max_parameters_bytes", 65536, func(v *AgentModuleValues) *uint64 { return &v.MaxParametersBytes }},
		{"max_plan_steps", 256, func(v *AgentModuleValues) *uint64 { return &v.MaxPlanSteps }},
		{"max_plan_bytes", 1048576, func(v *AgentModuleValues) *uint64 { return &v.MaxPlanBytes }},
	}
)

// numericFields lists the numeric fields an agent interface carries.
func numericFields(iface string) []agentField {
	out := append([]agentField{}, budgetFields...)
	switch iface {
	case ifaceCollector:
		out = append(out, collectorFields...)
	case ifaceResponder:
		out = append(out, responderFields...)
	}
	return out
}

// ParseGrantRecord decodes one committed grant record.
func ParseGrantRecord(data []byte) (GrantRecord, error) {
	root, err := decodeJSON(data, MaxGrantRecordBytes)
	if err != nil {
		return GrantRecord{}, err
	}
	var c checker
	r, ok := c.grantRecord(root)
	if ok {
		c.validGrantRecord(&r)
	}
	if err := c.result(ok); err != nil {
		return GrantRecord{}, err
	}
	return r, nil
}

func (c *checker) grantRecord(n *node) (GrantRecord, bool) {
	var r GrantRecord
	if !fields(n, []string{"extension_id", "version", "package_sha256", "recovery_epoch", "grant_generation", "approval", "grant"}) {
		return r, false
	}
	ok := true
	step := func(b bool) { ok = ok && b }
	var b bool
	r.ExtensionID, b = asString(n.member("extension_id"))
	step(b)
	r.Version, b = asString(n.member("version"))
	step(b)
	r.PackageSHA256, b = c.hexDigest(n.member("package_sha256"))
	step(b)
	r.RecoveryEpoch, b = c.uint64Lexeme(n.member("recovery_epoch"))
	step(b)
	r.GrantGeneration, b = c.uint64Lexeme(n.member("grant_generation"))
	step(b)
	if !ok {
		return r, false
	}
	if r.Approval, ok = c.approval(n.member("approval")); !ok {
		return r, false
	}
	r.Grant, ok = c.grant(n.member("grant"))
	return r, ok
}

// approval decodes one of the three approval shapes. An unknown kind is a
// field failure; members that do not match the kind are a shape failure.
func (c *checker) approval(n *node) (Approval, bool) {
	var a Approval
	if n == nil || n.kind != nodeObject {
		return a, false
	}
	kind, ok := asString(n.member("kind"))
	if !ok {
		return a, false
	}
	a.Kind = ApprovalKind(kind)
	var b bool
	switch a.Kind {
	case Operator, SingleAdministrator:
		who := "approver"
		if a.Kind == SingleAdministrator {
			who = "principal"
		}
		if !fields(n, []string{"kind", "request_digest", "approval_uid", who, "recovery_epoch"}) {
			return a, false
		}
		if a.RequestDigest, ok = asString(n.member("request_digest")); !ok {
			return a, false
		}
		if a.ApprovalUID, ok = asString(n.member("approval_uid")); !ok {
			return a, false
		}
		var principal string
		if principal, ok = asString(n.member(who)); !ok {
			return a, false
		}
		if a.Kind == Operator {
			a.Approver = principal
		} else {
			a.Principal = principal
		}
		a.RecoveryEpoch, b = c.uint64Lexeme(n.member("recovery_epoch"))
		return a, b
	case ReleaseFixed:
		if !fields(n, []string{"kind", "release_version"}) {
			return a, false
		}
		a.ReleaseVersion, ok = asString(n.member("release_version"))
		return a, ok
	}
	c.check(false)
	return a, true
}

func (c *checker) validApproval(a *Approval) {
	switch a.Kind {
	case Operator:
		c.check(validFingerprint(a.RequestDigest) && validUUID(a.ApprovalUID) && validUUID(a.Approver) && a.Principal == "" && a.ReleaseVersion == "")
	case SingleAdministrator:
		c.check(validFingerprint(a.RequestDigest) && validUUID(a.ApprovalUID) && validUUID(a.Principal) && a.Approver == "" && a.ReleaseVersion == "")
	case ReleaseFixed:
		c.check(validVersion(a.ReleaseVersion) && a.RequestDigest == "" && a.ApprovalUID == "" && a.Approver == "" && a.Principal == "" && a.RecoveryEpoch == 0)
	default:
		c.check(false)
	}
}

func (c *checker) validGrantRecord(r *GrantRecord) {
	c.check(validID(r.ExtensionID) && validVersion(r.Version))
	c.validApproval(&r.Approval)
	c.validGrant(&r.Grant)
}

// grant decodes {component, kind, interface, values}. The outer members are
// shape; the kind and interface pair and the values members are grant
// agreement. A disagreeing grant keeps zero Values.
func (c *checker) grant(n *node) (Grant, bool) {
	var g Grant
	if !fields(n, []string{"component", "kind", "interface", "values"}) {
		return g, false
	}
	ok := true
	step := func(b bool) { ok = ok && b }
	var b bool
	g.Component, b = asString(n.member("component"))
	step(b)
	g.Kind, b = asString(n.member("kind"))
	step(b)
	g.Interface, b = asString(n.member("interface"))
	step(b)
	values := n.member("values")
	step(values.kind == nodeObject)
	if !ok {
		return g, false
	}
	if !definedPair(g.Kind, g.Interface) {
		c.agree(false)
		return g, true
	}
	v, agrees := decodeValues(g.Kind, g.Interface, values)
	c.agree(agrees)
	if agrees {
		g.Values = v
	}
	return g, true
}

// decodeValues decodes values for a defined pair; false is disagreement.
func decodeValues(kind, iface string, n *node) (Values, bool) {
	var v Values
	switch kind {
	case kindContent:
		if !fields(n, nil) {
			return v, false
		}
		v.Content = &struct{}{}
	case kindBrowserAdapter:
		if !fields(n, []string{"registration", "os"}) {
			return v, false
		}
		registration, ok := asString(n.member("registration"))
		if !ok {
			return v, false
		}
		os, known, ok := osPolicies(n.member("os"))
		if !ok || !known {
			return v, false
		}
		v.BrowserAdapter = &BrowserAdapterValues{Registration: registration, OS: os}
	case kindAgentModule:
		a := &AgentModuleValues{}
		numbers := numericFields(iface)
		required := make([]string, 0, len(numbers)+2)
		for _, f := range numbers {
			required = append(required, f.name)
		}
		switch iface {
		case ifaceParser:
			required = append(required, "mime_types")
		case ifaceCollector:
			required = append(required, "roots", "disclosure_profile")
		case ifaceResponder:
			required = append(required, "actions")
		}
		if !fields(n, required) {
			return v, false
		}
		for _, f := range numbers {
			x, ok := integer(n.member(f.name))
			if !ok {
				return v, false
			}
			*f.get(a) = x
		}
		var ok bool
		switch iface {
		case ifaceParser:
			if a.MIMETypes, ok = asStrings(n.member("mime_types")); !ok {
				return v, false
			}
		case ifaceCollector:
			items, ok := asArray(n.member("roots"))
			if !ok {
				return v, false
			}
			a.Roots = make([]Root, len(items))
			for i, item := range items {
				if !fields(item, []string{"os", "path"}) {
					return v, false
				}
				if a.Roots[i].OS, ok = asString(item.member("os")); !ok {
					return v, false
				}
				if a.Roots[i].Path, ok = asString(item.member("path")); !ok {
					return v, false
				}
			}
			if a.DisclosureProfile, ok = asString(n.member("disclosure_profile")); !ok {
				return v, false
			}
		case ifaceResponder:
			if a.Actions, ok = asStrings(n.member("actions")); !ok {
				return v, false
			}
		}
		v.AgentModule = a
	case kindConsoleModule:
		if !fields(n, []string{"slots"}) {
			return v, false
		}
		slots := n.member("slots")
		if slots.kind != nodeObject {
			return v, false
		}
		m := make(map[string][]string, len(slots.keys))
		for i, k := range slots.keys {
			if !oneOf(k, slotNames...) {
				return v, false
			}
			ops, ok := asStrings(slots.items[i])
			if !ok {
				return v, false
			}
			m[k] = ops
		}
		v.ConsoleModule = &ConsoleModuleValues{Slots: m}
	case kindServiceConnector:
		if !fields(n, []string{"outbound"}) {
			return v, false
		}
		items, ok := asArray(n.member("outbound"))
		if !ok {
			return v, false
		}
		out := make([]Outbound, len(items))
		for i, item := range items {
			if !fields(item, []string{"host", "port", "transport"}) {
				return v, false
			}
			if out[i].Host, ok = asString(item.member("host")); !ok {
				return v, false
			}
			if out[i].Port, ok = integer(item.member("port")); !ok {
				return v, false
			}
			if out[i].Transport, ok = asString(item.member("transport")); !ok {
				return v, false
			}
		}
		v.ServiceConnector = &ServiceConnectorValues{Outbound: out}
	}
	return v, true
}

// integer decodes an integer token. A value above MaxUint64 decodes as
// MaxUint64, which every ceiling rejects as a field failure.
func integer(n *node) (uint64, bool) {
	if n == nil || n.kind != nodeNumber {
		return 0, false
	}
	x, err := strconv.ParseUint(n.text, 10, 64)
	if err != nil {
		return ^uint64(0), true
	}
	return x, true
}

// valuesAgree reports whether exactly the field for kind is set and, for an
// agent module, no field of another agent interface is present.
func valuesAgree(kind, iface string, v *Values) bool {
	set := 0
	for _, p := range []bool{v.Content != nil, v.BrowserAdapter != nil, v.AgentModule != nil, v.ConsoleModule != nil, v.ServiceConnector != nil} {
		if p {
			set++
		}
	}
	if set != 1 {
		return false
	}
	switch kind {
	case kindContent:
		return v.Content != nil
	case kindBrowserAdapter:
		return v.BrowserAdapter != nil
	case kindAgentModule:
		a := v.AgentModule
		if a == nil {
			return false
		}
		if iface != ifaceParser && a.MIMETypes != nil {
			return false
		}
		if iface != ifaceResponder && a.Actions != nil {
			return false
		}
		if iface != ifaceCollector && (a.Roots != nil || a.DisclosureProfile != "") {
			return false
		}
		present := map[string]bool{}
		for _, f := range numericFields(iface) {
			present[f.name] = true
		}
		for _, f := range append(append([]agentField{}, collectorFields...), responderFields...) {
			if !present[f.name] && *f.get(a) != 0 {
				return false
			}
		}
		return true
	case kindConsoleModule:
		if v.ConsoleModule == nil {
			return false
		}
		for k := range v.ConsoleModule.Slots {
			if !oneOf(k, slotNames...) {
				return false
			}
		}
		return true
	case kindServiceConnector:
		return v.ServiceConnector != nil
	}
	return false
}

// validGrant checks a typed grant: the name is a field rule, the kind and
// interface pair and the values layout are agreement, and value contents are
// field rules checked only when the values agree.
func (c *checker) validGrant(g *Grant) {
	c.check(validName(g.Component))
	if !definedPair(g.Kind, g.Interface) || !valuesAgree(g.Kind, g.Interface, &g.Values) {
		c.agree(false)
		return
	}
	c.check(validGrantValues(g.Interface, &g.Values))
}

func validGrantValues(iface string, v *Values) bool {
	switch {
	case v.Content != nil:
		return true
	case v.BrowserAdapter != nil:
		var c checker
		c.validOSPolicies(&v.BrowserAdapter.OS)
		return validID(v.BrowserAdapter.Registration) && !c.fieldFail
	case v.AgentModule != nil:
		a := v.AgentModule
		for _, f := range numericFields(iface) {
			if x := *f.get(a); x < 1 || x > f.ceiling {
				return false
			}
		}
		switch iface {
		case ifaceParser:
			return stringSet(a.MIMETypes, 1, 32, func(s string) bool { return matches(s, 3, 127, mimePattern) })
		case ifaceCollector:
			if len(a.Roots) < 1 || len(a.Roots) > 16 || !validProfile(a.DisclosureProfile) {
				return false
			}
			for i, r := range a.Roots {
				if !validRoot(r) {
					return false
				}
				for j := 0; j < i; j++ {
					if a.Roots[j] == r {
						return false
					}
				}
			}
			return true
		case ifaceResponder:
			return stringSet(a.Actions, 1, 9, func(s string) bool { return oneOf(s, responderActions...) })
		}
		return true
	case v.ConsoleModule != nil:
		if len(v.ConsoleModule.Slots) < 1 {
			return false
		}
		for _, ops := range v.ConsoleModule.Slots {
			if !stringSet(ops, 0, 23, func(s string) bool { return oneOf(s, consoleOperations...) }) {
				return false
			}
		}
		return true
	case v.ServiceConnector != nil:
		out := v.ServiceConnector.Outbound
		if len(out) > 64 {
			return false
		}
		for i, o := range out {
			if !matches(o.Host, 3, 253, hostPattern) || o.Port < 1 || o.Port > 65535 || !oneOf(o.Transport, "tcp", "udp") {
				return false
			}
			for j := 0; j < i; j++ {
				if out[j] == o {
					return false
				}
			}
		}
		return true
	}
	return false
}

func validRoot(r Root) bool {
	switch r.OS {
	case "macos", "linux":
		return matches(r.Path, 2, 256, posixRootPattern)
	case "windows":
		return matches(r.Path, 4, 256, windowsRootPattern)
	}
	return false
}

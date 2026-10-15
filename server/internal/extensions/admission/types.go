// Package admission decides whether verified extension package evidence may be
// installed under a decision-scoped authority snapshot. It is a pure function
// over typed inputs: no I/O, clock, database, network, randomness or shared
// state. docs/specs/extension-admission.md owns the decision model and
// docs/specs/extension-admission-contracts.md owns this API.
package admission

import "errors"

var (
	ErrEvidence = errors.New("extension admission evidence")
	ErrJSON     = errors.New("extension admission JSON")
	ErrShape    = errors.New("extension admission shape")
	ErrField    = errors.New("extension admission field")
	ErrGrant    = errors.New("extension admission grant")
)

// SystemPrincipal requests every server-image proposal and nothing else.
const SystemPrincipal = "00000000-0000-7000-8000-000000000000"

type Source string

const (
	SourceUpload      Source = "upload"
	SourceAPI         Source = "api"
	SourceGitOps      Source = "gitops"
	SourceIndex       Source = "index"
	SourceServerImage Source = "server-image"
)

type Outcome string

const (
	Admit            Outcome = "admit"
	ApprovalRequired Outcome = "approval_required"
	IdenticalRetry   Outcome = "identical_retry"
	Reject           Outcome = "reject"
)

type Operation string

const (
	OperationInstall     Operation = "install"
	OperationUpgrade     Operation = "upgrade"
	OperationReinstall   Operation = "reinstall"
	OperationGrantUpdate Operation = "grant_update"
)

type Stage string

const (
	StageInput      Stage = "input"
	StageKey        Stage = "key"
	StageNamespace  Stage = "namespace"
	StageRevocation Stage = "revocation"
	StageTombstone  Stage = "tombstone"
	StageOwnership  Stage = "ownership"
	StageInterface  Stage = "interface"
	StageComponent  Stage = "component"
	StageTargets    Stage = "targets"
	StageGrant      Stage = "grant"
	StageApproval   Stage = "approval"
)

var stageOrder = []Stage{StageInput, StageKey, StageNamespace, StageRevocation, StageTombstone, StageOwnership, StageInterface, StageComponent, StageTargets, StageGrant, StageApproval}

type ApprovalKind string

const (
	Operator            ApprovalKind = "operator"
	SingleAdministrator ApprovalKind = "single-administrator"
	ReleaseFixed        ApprovalKind = "release-fixed"
)

type InstallState string

const (
	StateActive          InstallState = "active"
	StateRecoveryPending InstallState = "recovery_pending"
)

type Code string

const (
	CodeInputEvidence                   Code = "input.evidence"
	CodeInputSnapshot                   Code = "input.snapshot"
	CodeInputRequest                    Code = "input.request"
	CodeKeyUnknown                      Code = "key.unknown"
	CodeKeyInvalid                      Code = "key.invalid"
	CodeKeyRevoked                      Code = "key.revoked"
	CodeKeyRetired                      Code = "key.retired"
	CodeNamespaceReserved               Code = "namespace.reserved"
	CodeNamespacePrefix                 Code = "namespace.prefix"
	CodeRevocationID                    Code = "revocation.id"
	CodeRevocationVersion               Code = "revocation.version"
	CodeTombstoneManifest               Code = "tombstone.manifest"
	CodeTombstonePackage                Code = "tombstone.package"
	CodeTombstonePublisher              Code = "tombstone.publisher"
	CodeTombstoneGrants                 Code = "tombstone.grants"
	CodeTombstoneTargets                Code = "tombstone.targets"
	CodeTombstoneNotInstalled           Code = "tombstone.not_installed"
	CodeOwnershipOwner                  Code = "ownership.owner"
	CodeOwnershipAssignmentRequired     Code = "ownership.assignment_required"
	CodeInterfaceUnserved               Code = "interface.unserved"
	CodeComponentVerdictMissing         Code = "component.verdict_missing"
	CodeComponentVerdictFailed          Code = "component.verdict_failed"
	CodeComponentRegistrationUnknown    Code = "component.registration_unknown"
	CodeComponentRegistrationOS         Code = "component.registration_os"
	CodeComponentRegistrationNames      Code = "component.registration_names"
	CodeComponentRegistrationNativeHost Code = "component.registration_native_host"
	CodeComponentRegistrationBound      Code = "component.registration_bound"
	CodeComponentRegistrationDuplicate  Code = "component.registration_duplicate"
	CodeTargetsDeviceGroupsRequired     Code = "targets.device_groups_required"
	CodeTargetsDeviceGroupsForbidden    Code = "targets.device_groups_forbidden"
	CodeTargetsAllDevices               Code = "targets.all_devices"
	CodeTargetsConsole                  Code = "targets.console"
	CodeTargetsJobs                     Code = "targets.jobs"
	CodeTargetsUnknownGroup             Code = "targets.unknown_group"
	CodeTargetsRetiredKey               Code = "targets.retired_key"
	CodeGrantMissing                    Code = "grant.missing"
	CodeGrantExtra                      Code = "grant.extra"
	CodeGrantKind                       Code = "grant.kind"
	CodeGrantRegistration               Code = "grant.registration"
	CodeGrantExceeds                    Code = "grant.exceeds"
	CodeGrantProfile                    Code = "grant.profile"
	CodeGrantRoots                      Code = "grant.roots"
	CodeGrantRetiredKey                 Code = "grant.retired_key"
	CodeApprovalReleaseFixed            Code = "approval.release_fixed"
	CodeApprovalReleaseOperation        Code = "approval.release_operation"
	CodeApprovalWidened                 Code = "approval.widened"
	CodeApprovalTargetsChanged          Code = "approval.targets_changed"
	CodeApprovalEpoch                   Code = "approval.epoch"
	CodeApprovalDigest                  Code = "approval.digest"
	CodeApprovalSeparation              Code = "approval.separation"
	CodeApprovalExemptUnavailable       Code = "approval.exempt_unavailable"
	CodeApprovalExemptPrincipal         Code = "approval.exempt_principal"
	CodeApprovalConsumed                Code = "approval.consumed"
)

var allCodes = []Code{
	CodeInputEvidence, CodeInputSnapshot, CodeInputRequest,
	CodeKeyUnknown, CodeKeyInvalid, CodeKeyRevoked, CodeKeyRetired,
	CodeNamespaceReserved, CodeNamespacePrefix,
	CodeRevocationID, CodeRevocationVersion,
	CodeTombstoneManifest, CodeTombstonePackage, CodeTombstonePublisher, CodeTombstoneGrants, CodeTombstoneTargets, CodeTombstoneNotInstalled,
	CodeOwnershipOwner, CodeOwnershipAssignmentRequired,
	CodeInterfaceUnserved,
	CodeComponentVerdictMissing, CodeComponentVerdictFailed, CodeComponentRegistrationUnknown, CodeComponentRegistrationOS, CodeComponentRegistrationNames, CodeComponentRegistrationNativeHost, CodeComponentRegistrationBound, CodeComponentRegistrationDuplicate,
	CodeTargetsDeviceGroupsRequired, CodeTargetsDeviceGroupsForbidden, CodeTargetsAllDevices, CodeTargetsConsole, CodeTargetsJobs, CodeTargetsUnknownGroup, CodeTargetsRetiredKey,
	CodeGrantMissing, CodeGrantExtra, CodeGrantKind, CodeGrantRegistration, CodeGrantExceeds, CodeGrantProfile, CodeGrantRoots, CodeGrantRetiredKey,
	CodeApprovalReleaseFixed, CodeApprovalReleaseOperation, CodeApprovalWidened, CodeApprovalTargetsChanged, CodeApprovalEpoch, CodeApprovalDigest, CodeApprovalSeparation, CodeApprovalExemptUnavailable, CodeApprovalExemptPrincipal, CodeApprovalConsumed,
}

// Evidence is the typed projection of a loader-verified package.
type Evidence struct {
	ID, Version, PublisherFingerprint             string
	PackageSHA256, ManifestSHA256, EnvelopeSHA256 [32]byte
	Requires                                      map[string][]string // kind -> interfaces, as validated
	Components                                    []Component         // sorted by Name, names unique
}

type Component struct {
	Name, Kind, Interface, Format string
	Slots                         []string // console-module only
	Requested                     Values   // the manifest capabilities in grant-value shape
}

// Values carries exactly one field, selected by Kind and Interface.
type Values struct {
	Content          *struct{}
	BrowserAdapter   *BrowserAdapterValues
	AgentModule      *AgentModuleValues
	ConsoleModule    *ConsoleModuleValues
	ServiceConnector *ServiceConnectorValues
}

type BrowserAdapterValues struct {
	Registration string
	OS           OSPolicies
}

// OSPolicies holds the per-OS policy names and native-host flag; nil is absent.
type OSPolicies struct {
	MacOS, Windows, Linux *OSPolicy
}

type OSPolicy struct {
	PolicyNames []string
	NativeHost  bool
}

// AgentModuleValues holds the fields of all four agent interfaces; the
// component's interface selects which are present. Roots and
// DisclosureProfile appear in collector grants only, never in a request.
type AgentModuleValues struct {
	MemoryPages, FuelPerCall, DeadlineMS uint64

	MIMETypes []string // parser

	MaxRoots, MaxPathDepth, MaxDirectoryEntries, MaxOpenHandles, MaxListRequests uint64 // collector
	MaxReadRequests, MaxBytesPerFile, MaxInputBytes, MaxRows, MaxOutputBytes     uint64 // collector
	Roots                                                                        []Root // collector grant
	DisclosureProfile                                                            string // collector grant

	Actions                                                     []string // responder
	MaxEntities, MaxParametersBytes, MaxPlanSteps, MaxPlanBytes uint64   // responder
}

type Root struct {
	OS, Path string
}

// ConsoleModuleValues maps a slot name to its operations.
type ConsoleModuleValues struct {
	Slots map[string][]string
}

type ServiceConnectorValues struct {
	Outbound []Outbound
}

type Outbound struct {
	Host      string
	Port      uint64
	Transport string
}

// Snapshot is scoped to one id, version, approval and the referenced registrations.
type Snapshot struct {
	RecoveryEpoch            uint64
	ApprovalPolicyDisabled   bool
	ApprovalPolicyGeneration uint64
	FirstStart               bool
	ReleaseVersion           string // empty without a verified release manifest (JSON null)
	ProjectKey               string
	ServedInterfaces         []string
	TrustList                []TrustEntry
	Revocations              []Revocation
	RevocationGeneration     uint64
	Ownership                *Ownership
	Tombstones               []Tombstone
	Install                  *Install
	Registrations            []Registration
	DisclosureProfiles       []string
	DeviceGroups             []string
	ConsumedApprovals        []string
}

type TrustEntry struct {
	Fingerprint      string
	PublicKey        [32]byte
	Name             string
	Prefixes         []string
	ProjectPublisher bool
	Revoked          bool
	Retired          bool
	Generation       uint64
}

// Revocation is id-level when Version is empty.
type Revocation struct {
	ID, Version string
}

type Ownership struct {
	ID                  string
	Owner               string
	PriorOwners         []string
	OwnershipGeneration uint64
}

type Tombstone struct {
	ID, Version, Publisher        string
	ManifestSHA256, PackageSHA256 [32]byte
}

type Install struct {
	ID, Version   string
	PackageSHA256 [32]byte
	State         InstallState
	Enabled       bool
	Generation    uint64
	Targets       Targets
	Grants        []GrantRecord
}

type GrantRecord struct {
	ExtensionID     string
	Version         string
	PackageSHA256   [32]byte
	RecoveryEpoch   uint64
	GrantGeneration uint64
	Approval        Approval
	Grant           Grant
}

type Registration struct {
	ID                     string
	Browser                string
	RegistrationGeneration uint64
	OS                     OSPolicies
	Bound                  *Bound
}

type Bound struct {
	ID, Component string
	State         InstallState
}

type Grant struct {
	Component, Kind, Interface string
	Values                     Values
}

type Targets struct {
	DeviceGroups []string
	AllDevices   bool
	Console      bool
	Jobs         bool
}

// Approval carries Approver for the operator kind, Principal for the
// single-administrator kind and ReleaseVersion for the release-fixed kind.
type Approval struct {
	Kind           ApprovalKind
	RequestDigest  string
	ApprovalUID    string
	Approver       string
	Principal      string
	RecoveryEpoch  uint64
	ReleaseVersion string
}

type Request struct {
	Source      Source
	Requester   string
	GrantUpdate bool
	Grants      []Grant
	Targets     Targets
	Approval    *Approval
}

type Verdict struct {
	Component string
	OK        bool
}

type Decision struct {
	Outcome       Outcome
	Operation     Operation // set only on Admit and ApprovalRequired
	Stage         Stage     // set only on Reject
	Reasons       []Reason  // sorted by Code then Subject
	ClosureDigest string    // set only on Admit and ApprovalRequired
	RequestDigest string    // set only on Admit and ApprovalRequired
	Intent        *Intent   // non-nil only on Admit
}

type Reason struct {
	Code    Code
	Subject string
}

type Intent struct {
	Operation        Operation
	ApprovalKind     ApprovalKind
	TombstoneCreate  bool
	OwnershipCreate  bool
	Enabled          bool
	Grants           []string
	Targets          Targets
	RegistrationBind []Binding // the id's complete binding set after commit; unnamed bindings are released
	ApprovalConsume  string
}

type Binding struct {
	Registration, Component string
}

// Resource is the GitOps kind Extension. ID is metadata.name.
type Resource struct {
	ID      string
	Version string
	Source  ResourceSource
	Grants  []Grant
	Targets Targets
	Enabled bool
}

type ResourceSource struct {
	URL    string // optional
	SHA256 [32]byte
}

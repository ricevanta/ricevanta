"""Catalogue compatibility reads reviewed base and candidate objects from Git."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import hashlib

import yaml

import check_policy
import inventory

ROOT = Path(__file__).resolve().parents[2]
CATALOGUE = 'schemas/permissions/v1/catalogue.json'
SCHEMA = 'schemas/permissions/v1/catalogue.schema.json'
EMBEDDED = 'server/internal/authz/catalogue/catalogue.json'
PROBE = 'mdm.commands.restart'
COMMAND = 'python -B scripts/ci/catalogue_compat.py --root . --base-sha "$BASE_SHA" --candidate-sha "$CANDIDATE_SHA"'
TOMBSTONE = PROBE + ': tombstone changed; retired rows keep all metadata and retired_in'

# Actual reviewed base bytes are a fixed test fixture, never a runtime baseline.
_REVIEWED_BASE_JSON = r'''{
  "format_version": 1,
  "revision": 3,
  "permissions": [
    {"name": "audit.events.export","owner": "audit","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["exportAuditBundle","createExport#audit"],"source": "docs/design/console.md#5.12","note": "Additional to audit.events.read; signed bundle and all audit exports are audited."},
    {"name": "audit.events.read","owner": "audit","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listAuditEvents","getAuditEvent","getAuditChainStatus"],"source": "docs/design/console.md#5.12","note": "Requires current permission and target access."},
    {"name": "authz.access_policies.read","owner": "authz","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listAccessPolicies"],"source": "docs/design/console.md#5.11","note": "Requires current permission and target access."},
    {"name": "authz.access_policies.update","owner": "authz","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["updateAccessPolicy"],"source": "docs/design/console.md#5.11","note": "Requires current permission and target access."},
    {"name": "authz.approvals.approve","owner": "authz","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:approve-protected-action"],"source": "docs/design/console.md#3.2","note": "Fresh interactive different account, current approver-group eligibility and target access; excludes identity-authority decisions."},
    {"name": "authz.approvals.read","owner": "authz","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:all-approval-requests"],"source": "docs/design/console.md#3.2","note": "Full queue metadata; does not reveal target secrets or grant approval rights."},
    {"name": "authz.approvals.reject","owner": "authz","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:reject-protected-action"],"source": "docs/design/console.md#3.2","note": "Same decision eligibility as approve; identity-authority rejection requires identity.authority.approve."},
    {"name": "authz.catalogue.read","owner": "authz","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:permission-picker","api:get-permission-catalogue"],"source": "docs/design/console.md#5.11","note": "Future authenticated API publishes metadata only; the library adds no route."},
    {"name": "authz.role_assignments.create","owner": "authz","scope": "organization","protection": "conditional","approval": "access_policy","rule": "grant_sensitive","grant": "role","status": "active","introduced": 1,"uses": ["createRoleAssignment"],"source": "docs/design/console.md#5.11","note": "Fresh authentication on writes; authority approver permission cannot enter a role or directory assignment."},
    {"name": "authz.role_assignments.delete","owner": "authz","scope": "organization","protection": "conditional","approval": "access_policy","rule": "grant_sensitive","grant": "role","status": "active","introduced": 1,"uses": ["deleteRoleAssignment"],"source": "docs/design/console.md#5.11","note": "Fresh authentication on writes; authority approver permission cannot enter a role or directory assignment."},
    {"name": "authz.role_assignments.read","owner": "authz","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listRoleAssignments"],"source": "docs/design/console.md#5.11","note": "Fresh authentication on writes; authority approver permission cannot enter a role or directory assignment."},
    {"name": "authz.role_assignments.update","owner": "authz","scope": "organization","protection": "conditional","approval": "access_policy","rule": "grant_sensitive","grant": "role","status": "active","introduced": 1,"uses": ["api:update-role-assignment"],"source": "docs/design/console.md#5.11","note": "Fresh authentication on writes; authority approver permission cannot enter a role or directory assignment."},
    {"name": "authz.roles.create","owner": "authz","scope": "organization","protection": "conditional","approval": "access_policy","rule": "grant_sensitive","grant": "role","status": "active","introduced": 1,"uses": ["createRole"],"source": "docs/design/console.md#5.11","note": "Fresh authentication on writes; authority approver permission cannot enter a role or directory assignment."},
    {"name": "authz.roles.delete","owner": "authz","scope": "organization","protection": "conditional","approval": "access_policy","rule": "grant_sensitive","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-role"],"source": "docs/design/console.md#5.11","note": "Fresh authentication on writes; authority approver permission cannot enter a role or directory assignment."},
    {"name": "authz.roles.read","owner": "authz","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listRoles"],"source": "docs/design/console.md#5.11","note": "Fresh authentication on writes; authority approver permission cannot enter a role or directory assignment."},
    {"name": "authz.roles.update","owner": "authz","scope": "organization","protection": "conditional","approval": "access_policy","rule": "grant_sensitive","grant": "role","status": "active","introduced": 1,"uses": ["updateRole"],"source": "docs/design/console.md#5.11","note": "Fresh authentication on writes; authority approver permission cannot enter a role or directory assignment."},
    {"name": "dlp.classifications.create","owner": "dlp","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["api:create-classification"],"source": "docs/design/console.md#5.4","note": "Requires current permission and target access."},
    {"name": "dlp.classifications.delete","owner": "dlp","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-classification"],"source": "docs/design/console.md#5.4","note": "Requires current permission and target access."},
    {"name": "dlp.classifications.read","owner": "dlp","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listClassifications"],"source": "docs/design/console.md#5.4","note": "Requires current permission and target access."},
    {"name": "dlp.classifications.update","owner": "dlp","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["api:update-classification"],"source": "docs/design/console.md#5.4","note": "Requires current permission and target access."},
    {"name": "dlp.evidence.read","owner": "dlp","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["getDlpFinding#snippet"],"source": "docs/design/console.md#3.1","note": "Additional to dlp.findings.read; redacted snippet only, audited."},
    {"name": "dlp.findings.read","owner": "dlp","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listDlpFindings","getDlpFinding"],"source": "docs/design/console.md#5.4","note": "Requires current permission and target access."},
    {"name": "dlp.findings.update","owner": "dlp","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["updateDlpFinding"],"source": "docs/design/console.md#5.4","note": "Requires current permission and target access."},
    {"name": "dlp.fingerprints.create","owner": "dlp","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:register-fingerprint-document"],"source": "docs/design/dlp.md#4","note": "Requires current permission and target access."},
    {"name": "dlp.fingerprints.delete","owner": "dlp","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-fingerprint-set"],"source": "docs/design/dlp.md#4","note": "Requires current permission and target access."},
    {"name": "dlp.fingerprints.publish","owner": "dlp","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:publish-fingerprint-pack"],"source": "docs/design/dlp.md#4","note": "Also requires policy.rulepacks.publish; originals stay private."},
    {"name": "dlp.fingerprints.read","owner": "dlp","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:fingerprint-sets"],"source": "docs/design/dlp.md#4","note": "Metadata only, never original documents."},
    {"name": "dlp.fingerprints.update","owner": "dlp","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["api:update-fingerprint-set"],"source": "docs/design/dlp.md#4","note": "Requires current permission and target access."},
    {"name": "dlp.managed_tenants.read","owner": "dlp","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 2,"uses": ["api:read-dlp-managed-tenants"],"source": "docs/design/dlp.md#6.1","note": "Metadata only on reads; never original documents or secrets. Writes require policy.policies.update over the full before/after dependent policy scope and policy_change for any changed enforcement outcome. Freeze dependency closure and reject unresolved scope."},
    {"name": "dlp.managed_tenants.update","owner": "dlp","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 2,"uses": ["api:update-dlp-managed-tenants"],"source": "docs/design/dlp.md#6.1","note": "Metadata only on reads; never original documents or secrets. Writes require policy.policies.update over the full before/after dependent policy scope and policy_change for any changed enforcement outcome. Freeze dependency closure and reject unresolved scope."},
    {"name": "dlp.originals.delete","owner": "dlp","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:discard-fingerprint-originals"],"source": "docs/design/dlp.md#4","note": "Requires dlp.fingerprints.update for the exact set. Delete originals only after fingerprinting; retain derived fingerprints and enforce legal holds. Deletion grants no original-content read and cannot delete the set or withdraw its pack."},
    {"name": "dlp.originals.upload","owner": "dlp","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 2,"uses": ["api:upload-fingerprint-originals"],"source": "docs/design/dlp.md#4","note": "Requires dlp.fingerprints.create for a new set or dlp.fingerprints.update for an existing set. Originals stay private. Recompute server-side; changed derived content must use dlp.fingerprints.publish and policy.rulepacks.publish with all target checks."},
    {"name": "dlp.template_corpus.read","owner": "dlp","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 2,"uses": ["api:read-dlp-template-corpus"],"source": "docs/design/dlp.md#4","note": "Metadata only on reads; never original documents or secrets. Writes require policy.policies.update over the full before/after dependent policy scope and policy_change for any changed enforcement outcome. Freeze dependency closure and reject unresolved scope."},
    {"name": "dlp.template_corpus.update","owner": "dlp","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 2,"uses": ["api:update-dlp-template-corpus"],"source": "docs/design/dlp.md#4","note": "Metadata only on reads; never original documents or secrets. Writes require policy.policies.update over the full before/after dependent policy scope and policy_change for any changed enforcement outcome. Freeze dependency closure and reject unresolved scope."},
    {"name": "edr.alerts.read","owner": "detection","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listAlerts","getAlert"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.alerts.update","owner": "detection","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["updateAlert"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.collection.cancel","owner": "detection","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 2,"uses": ["api:cancel-artifact-collection"],"source": "docs/specs/edr-response-actions.md#3.5","note": "Requires edr.response.collect and edr.response.read for every device in the original collection. Cancel only a collection, preserve uploaded parts and audit the result; no general command cancellation or evidence deletion."},
    {"name": "edr.indicators.pin","owner": "detection","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 2,"uses": ["api:pin-indicator"],"source": "docs/design/edr.md#8.3","note": "Requires edr.intel.update and policy.policies.update for all affected before/after devices. Recompute cap/truncation effects across every dependent blocking policy; freeze indicator and set revisions and apply policy_change. Pinning cannot bypass source caps."},
    {"name": "edr.indicators.unpin","owner": "detection","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 2,"uses": ["api:unpin-indicator"],"source": "docs/design/edr.md#8.3","note": "Requires edr.intel.update and policy.policies.update for all affected before/after devices. Recompute cap/truncation effects across every dependent blocking policy; freeze indicator and set revisions and apply policy_change. Pinning cannot bypass source caps."},
    {"name": "edr.intel.create","owner": "detection","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:create-intel-feed"],"source": "docs/design/edr.md#8","note": "Requires current permission and target access."},
    {"name": "edr.intel.delete","owner": "detection","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-intel-feed"],"source": "docs/design/edr.md#8","note": "Requires current permission and target access."},
    {"name": "edr.intel.import","owner": "detection","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["api:import-indicators"],"source": "docs/design/edr.md#8","note": "Requires current permission and target access."},
    {"name": "edr.intel.read","owner": "detection","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:threat-intelligence"],"source": "docs/design/edr.md#8","note": "Requires current permission and target access."},
    {"name": "edr.intel.update","owner": "detection","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["api:update-intel-feed"],"source": "docs/design/edr.md#8","note": "Requires current permission and target access."},
    {"name": "edr.investigations.create","owner": "detection","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createInvestigation"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.investigations.read","owner": "detection","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listInvestigations"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.investigations.update","owner": "detection","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["updateInvestigation"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.isolation_release.create","owner": "detection","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:create-offline-isolation-release"],"source": "docs/design/edr.md#7","note": "Signed device-bound nonce; same protection as unisolate_host."},
    {"name": "edr.response.collect","owner": "detection","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "fleet_gt_10","grant": "role","status": "active","introduced": 1,"uses": ["createResponseAction#edr.collect"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.response.isolate_host","owner": "detection","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "fleet_gt_10","grant": "role","status": "active","introduced": 1,"uses": ["createResponseAction#edr.isolate_host"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.response.kill_and_ban","owner": "detection","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "fleet_gt_10","grant": "role","status": "active","introduced": 1,"uses": ["createResponseAction#edr.kill_and_ban"],"source": "docs/design/console.md#5.3","note": "Each command has its own permission; kill_and_ban also needs policy.policies.update and the full affected-device scope."},
    {"name": "edr.response.kill_process","owner": "detection","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "fleet_gt_10","grant": "role","status": "active","introduced": 1,"uses": ["createResponseAction#edr.kill_process"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.response.quarantine_file","owner": "detection","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "fleet_gt_10","grant": "role","status": "active","introduced": 1,"uses": ["createResponseAction#edr.quarantine_file"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.response.read","owner": "detection","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listResponseActions"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.response.restore_file","owner": "detection","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createResponseAction#edr.restore_file"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.response.run_script","owner": "detection","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createResponseAction#edr.run_script"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.response.scan","owner": "detection","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "fleet_gt_10","grant": "role","status": "active","introduced": 1,"uses": ["createResponseAction#edr.scan"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.response.unban","owner": "detection","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createResponseAction#edr.unban"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.response.unisolate_host","owner": "detection","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createResponseAction#edr.unisolate_host"],"source": "docs/design/console.md#5.3","note": "Requires current permission and target access."},
    {"name": "edr.scripts.cancel","owner": "detection","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:cancel-operator-script"],"source": "docs/specs/edr-response-actions.md#3.7","note": "Requires edr.response.run_script and edr.response.read over every original target. Freeze command, device and containment identity; recheck authority before dispatch. Use the qualified containment mechanism and prove all owned descendants stopped before terminal cancellation. Unknown ownership stays reconcile_required."},
    {"name": "edr.telemetry.capture","owner": "detection","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:enable-investigation-capture"],"source": "docs/design/edr.md#6","note": "Bounded investigation set of at most 50 devices for 7 days."},
    {"name": "edr.telemetry.read","owner": "detection","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["searchTelemetry"],"source": "docs/design/edr.md#6","note": "Audited raw-store query; no source means a coverage gap, never invented rows."},
    {"name": "events.archive_holds.release","owner": "events","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:release-archive-hold"],"source": "docs/design/events.md#5","note": "Requires events.retention.update, events.retention.read and every source read over the full affected footprint; audit data requires audit.events.read. Freeze failed archive plan, partition/source digests and affected entities. Authorize possible data loss explicitly and audit it. Preserve every legal-hold pin and other retention gate; release cannot claim successful archival."},
    {"name": "events.dashboards.read","owner": "events","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listDashboards"],"source": "docs/design/console.md#5.10","note": "Panel results require report and source checks."},
    {"name": "events.dashboards.update","owner": "events","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["updateDashboard"],"source": "docs/design/console.md#5.10","note": "Editing layout grants no data authority; source checks govern previews."},
    {"name": "events.dead_letters.read","owner": "events","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listDeadLetters"],"source": "docs/design/console.md#5.16","note": "Metadata only; payload access additionally needs every source read permission."},
    {"name": "events.dead_letters.replay","owner": "events","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["replayDeadLetters"],"source": "docs/design/console.md#5.16","note": "Conservative approval for external redispatch; immutable destination plan and source rights still apply."},
    {"name": "events.destinations.backfill","owner": "events","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:backfill-export-destination"],"source": "docs/design/events.md#4.3","note": "Also requires events.destinations.read, events.exports.create and every source read over the complete selected footprint; audit data adds audit.events.read and audit.events.export. Freeze destination revision, filter, projection and range; include DLP evidence rights for snippets. Reject partial or unresolved coverage. S3 intentional replay gets a new namespace; retries retain their frozen plan."},
    {"name": "events.destinations.create","owner": "events","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createExportDestination"],"source": "docs/design/console.md#5.16","note": "Requires current permission and target access."},
    {"name": "events.destinations.delete","owner": "events","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-export-destination"],"source": "docs/design/console.md#5.16","note": "Requires current permission and target access."},
    {"name": "events.destinations.disable","owner": "events","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:disable-export-destination"],"source": "docs/design/console.md#5.16","note": "Requires current permission and target access."},
    {"name": "events.destinations.enable","owner": "events","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:enable-export-destination"],"source": "docs/design/console.md#5.16","note": "Requires current permission and target access."},
    {"name": "events.destinations.read","owner": "events","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listExportDestinations","getExportStatus"],"source": "docs/design/console.md#5.16","note": "Requires current permission and target access."},
    {"name": "events.destinations.replay","owner": "events","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:rewind-export-cursor"],"source": "docs/design/events.md#4.3","note": "Also requires events.destinations.read, events.exports.create and every source read over the complete selected footprint; audit data adds audit.events.read and audit.events.export. Freeze destination revision, filter, projection and range; include DLP evidence rights for snippets. Reject partial or unresolved coverage. S3 intentional replay gets a new namespace; retries retain their frozen plan."},
    {"name": "events.destinations.update","owner": "events","scope": "organization","protection": "conditional","approval": "access_policy","rule": "destination_change","grant": "role","status": "active","introduced": 1,"uses": ["updateExportDestination"],"source": "docs/design/console.md#5.16","note": "Requires current permission and target access."},
    {"name": "events.exports.create","owner": "events","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createExport#non-audit"],"source": "docs/design/console.md#4","note": "All source read permissions and footprint checks apply; audit export also requires audit.events.export."},
    {"name": "events.health.read","owner": "events","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["getDeviceFootprint"],"source": "docs/design/console.md#5.1","note": "Requires current permission and target access."},
    {"name": "events.holds.create","owner": "events","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createHold"],"source": "docs/design/console.md#5.16","note": "Capture requires all affected source permissions; cannot claim active before the hold capture gate."},
    {"name": "events.holds.read","owner": "events","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listHolds"],"source": "docs/design/console.md#5.16","note": "Requires current permission and target access."},
    {"name": "events.holds.release","owner": "events","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["releaseHold"],"source": "docs/design/console.md#5.16","note": "Requires current permission and target access."},
    {"name": "events.holds.update","owner": "events","scope": "organization","protection": "conditional","approval": "access_policy","rule": "hold_narrow","grant": "role","status": "active","introduced": 1,"uses": ["api:update-hold"],"source": "docs/design/console.md#5.16","note": "Requires current permission and target access."},
    {"name": "events.pipeline.read","owner": "events","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["getPipelineStatus"],"source": "docs/design/console.md#5.16","note": "Organization counters without attributable devices require scope all."},
    {"name": "events.quarantine.promote","owner": "events","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:promote-quarantined-events"],"source": "docs/design/events.md#3.2","note": "Also requires events.quarantine.read, events.quarantine.validate and all source reads over the full selected footprint. Freeze raw-line hashes, validation version and authenticated device/batch bindings; rerun validation at commit. Reject identity mismatches and partial coverage. Fresh inventory/compliance needs current provenance; historical security telemetry may retain old provenance without current authority. Preserve deduplication and hold/export gates. No raw-body disclosure."},
    {"name": "events.quarantine.read","owner": "events","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listQuarantinedEvents"],"source": "docs/design/console.md#5.16","note": "Metadata only; malformed payloads need a separate reviewed disclosure contract before serving."},
    {"name": "events.quarantine.validate","owner": "events","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 2,"uses": ["api:revalidate-quarantined-events"],"source": "docs/design/events.md#3.2","note": "Also requires events.quarantine.read and current source reads covering every selected authenticated device. Revalidate server-side against current schemas, mappings and provenance; return bounded diagnostics, never raw bodies. Validation cannot promote events or repair device identity."},
    {"name": "events.report_catalogue.read","owner": "events","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["getReportCatalogue"],"source": "docs/design/console.md#5.10","note": "Schema metadata only; no source rows or aggregates."},
    {"name": "events.report_schedules.create","owner": "events","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createReportSchedule"],"source": "docs/design/console.md#5.10","note": "Also needs events.reports.run and source reads; executes as owner."},
    {"name": "events.report_schedules.delete","owner": "events","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-report-schedule"],"source": "docs/design/console.md#5.10","note": "Requires current permission and target access."},
    {"name": "events.report_schedules.read","owner": "events","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listReportSchedules"],"source": "docs/design/console.md#5.10","note": "Requires current permission and target access."},
    {"name": "events.report_schedules.update","owner": "events","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["updateReportSchedule"],"source": "docs/design/console.md#5.10","note": "Editor becomes runner; requires events.reports.run and source reads."},
    {"name": "events.report_templates.create","owner": "events","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createReportTemplate"],"source": "docs/design/console.md#5.10","note": "Requires current permission and target access."},
    {"name": "events.report_templates.delete","owner": "events","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-report-template"],"source": "docs/design/console.md#5.10","note": "Requires current permission and target access."},
    {"name": "events.report_templates.read","owner": "events","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listReportTemplates"],"source": "docs/design/console.md#5.10","note": "Requires current permission and target access."},
    {"name": "events.report_templates.update","owner": "events","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:update-report-template"],"source": "docs/design/console.md#5.10","note": "Requires current permission and target access."},
    {"name": "events.reports.read","owner": "events","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["getReportRun","listReportRuns","api:download-report-dataset"],"source": "docs/design/console.md#5.10","note": "Every read and download rechecks all source permissions and current footprint coverage."},
    {"name": "events.reports.run","owner": "events","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createReportRun"],"source": "docs/design/console.md#5.10","note": "Also requires every dataset source permission; frozen immutable result footprint."},
    {"name": "events.retention.read","owner": "events","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:retention-and-archive"],"source": "docs/design/console.md#5.16","note": "Requires current permission and target access."},
    {"name": "events.retention.update","owner": "events","scope": "organization","protection": "conditional","approval": "access_policy","rule": "audit_retention","grant": "role","status": "active","introduced": 1,"uses": ["api:update-retention"],"source": "docs/design/console.md#5.16","note": "Requires current permission and target access."},
    {"name": "events.telemetry_profiles.read","owner": "events","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listTelemetryProfiles"],"source": "docs/design/console.md#5.16","note": "Requires current permission and target access."},
    {"name": "events.telemetry_profiles.update","owner": "events","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["updateTelemetryProfile"],"source": "docs/design/console.md#5.16","note": "Requires current permission and target access."},
    {"name": "extensions.bridge.create","owner": "extensions","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createExtensionBridgeBinding"],"source": "docs/design/console.md#5.15","note": "First-party host only; exact grant, slot and operator binding; permission is not bridge safety."},
    {"name": "extensions.browser_registrations.create","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:create-browser-registration"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.browser_registrations.delete","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-browser-registration"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.browser_registrations.read","owner": "extensions","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listBrowserRegistrations"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.browser_registrations.update","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:update-browser-registration"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.ca_callback.complete","owner": "extensions","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "connector","status": "active","introduced": 1,"uses": ["api:complete-own-ca-request"],"source": "docs/design/extensions.md#6","note": "Connector principal only; fixed token bound to request, CSR, epoch, package and registration generations. Not user, role, getSession or ordinary API-token grantable."},
    {"name": "extensions.components.revoke","owner": "extensions","scope": "organization","protection": "conditional","approval": "access_policy","rule": "extension_dependency","grant": "role","status": "active","introduced": 1,"uses": ["api:revoke-extension-component"],"source": "docs/design/extensions.md#2.5","note": "Component revocation follows the dependency rule; publisher-key revocation is immediate through extensions.trust.revoke."},
    {"name": "extensions.connectors.create","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:create-connector-registration"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.connectors.delete","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-connector-registration"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.connectors.read","owner": "extensions","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listConnectors"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.connectors.revoke","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:revoke-connector-token"],"source": "docs/design/extensions.md#6.2","note": "Requires extensions.connectors.read. Freeze connector/token identity and registration generation; invalidate pending callback authority under BE-12. Token revocation does not reconcile or revoke certificates already issued externally."},
    {"name": "extensions.connectors.rotate","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:rotate-connector-token"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.connectors.update","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:update-connector-registration"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.grants.update","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["updateExtensionGrants"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.index.read","owner": "extensions","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:extension-index-settings"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.index.update","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:update-extension-index"],"source": "docs/design/console.md#5.15","note": "Conservative protection for package discovery configuration; install still separately approved."},
    {"name": "extensions.ownership.assign","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:assign-extension-ownership"],"source": "docs/design/extensions.md#1","note": "Requires extensions.trust.read and extensions.packages.read. Freeze exact extension id, publisher key and overlapping prefix grants. Initial assignment cannot overwrite ownership or immutable id/version tombstones; changing the owner uses extensions.ownership.transfer."},
    {"name": "extensions.ownership.transfer","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:transfer-extension-ownership"],"source": "docs/design/extensions.md#1","note": "Bind old and new publisher keys, exact id and package digests; immutable id/version tombstones remain."},
    {"name": "extensions.packages.disable","owner": "extensions","scope": "organization","protection": "conditional","approval": "access_policy","rule": "extension_dependency","grant": "role","status": "active","introduced": 1,"uses": ["setExtensionEnabled#disable"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.packages.enable","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["setExtensionEnabled#enable"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.packages.install","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["installExtension"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.packages.read","owner": "extensions","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listExtensions"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.packages.revoke","owner": "extensions","scope": "organization","protection": "conditional","approval": "access_policy","rule": "extension_dependency","grant": "role","status": "active","introduced": 2,"uses": ["api:revoke-extension-id","api:revoke-extension-version","updateTrustList#add-id-revocation","updateTrustList#add-version-revocation"],"source": "docs/design/extensions.md#2.5","note": "Requires extensions.packages.read; resolve every dependent policy and adapter target before/after revocation, and require policy.policies.update over affected policy targets. Freeze id/version, dependency closure and generations. Preserve tombstones and fence grants, mounts, callbacks and queued work. Removing revocation requires extensions.trust.update; publisher-key revocation retains its immediate path."},
    {"name": "extensions.packages.uninstall","owner": "extensions","scope": "organization","protection": "conditional","approval": "access_policy","rule": "extension_dependency","grant": "role","status": "active","introduced": 1,"uses": ["uninstallExtension"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.packages.upgrade","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:upgrade-extension"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.packages.upload","owner": "extensions","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["uploadExtension"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.response.execute","owner": "extensions","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "child_union","grant": "role","status": "active","introduced": 1,"uses": ["createResponseAction#extension.respond"],"source": "docs/design/extensions.md#4","note": "Also requires union of every permitted child permission and approval over full frozen targets and envelopes."},
    {"name": "extensions.trust.read","owner": "extensions","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["getTrustList"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "extensions.trust.revoke","owner": "extensions","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["updateTrustList#add-publisher-key-revocation"],"source": "docs/design/console.md#5.15","note": "Publisher-key revocation is immediate and cannot wait for access-policy approval."},
    {"name": "extensions.trust.update","owner": "extensions","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["updateTrustList#trust-change"],"source": "docs/design/console.md#5.15","note": "Requires current permission and target access."},
    {"name": "identity.authority.approve","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "direct","status": "active","introduced": 1,"uses": ["api:approve-identity-authority"],"source": "docs/design/console.md#3.2","note": "Direct internal-user assignment only; different enabled account and unaffected fresh authentication. Not role-, group-, token- or bridge-grantable."},
    {"name": "identity.authority.assign","owner": "identity","scope": "organization","protection": "always","approval": "identity_authority","rule": "identity_authority","grant": "role","status": "active","introduced": 1,"uses": ["api:assign-authority-approver"],"source": "docs/design/console.md#3.2","note": "Direct assignment itself always needs unaffected authority approval."},
    {"name": "identity.authority.revoke","owner": "identity","scope": "organization","protection": "always","approval": "identity_authority","rule": "identity_authority","grant": "role","status": "active","introduced": 1,"uses": ["api:remove-authority-approver"],"source": "docs/design/console.md#3.2","note": "Removing a direct authority approver always needs unaffected authority approval."},
    {"name": "identity.break_glass.create","owner": "identity","scope": "organization","protection": "always","approval": "identity_authority","rule": "identity_authority","grant": "role","status": "active","introduced": 1,"uses": ["api:create-break-glass"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.break_glass.delete","owner": "identity","scope": "organization","protection": "always","approval": "identity_authority","rule": "identity_authority","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-break-glass"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.break_glass.disable","owner": "identity","scope": "organization","protection": "always","approval": "identity_authority","rule": "identity_authority","grant": "role","status": "active","introduced": 1,"uses": ["api:disable-break-glass"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.break_glass.enable","owner": "identity","scope": "organization","protection": "always","approval": "identity_authority","rule": "identity_authority","grant": "role","status": "active","introduced": 1,"uses": ["api:enable-break-glass"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.break_glass.read","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:break-glass"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.break_glass.replace_factor","owner": "identity","scope": "organization","protection": "always","approval": "identity_authority","rule": "identity_authority","grant": "role","status": "active","introduced": 1,"uses": ["api:replace-second-factor"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.break_glass.reset","owner": "identity","scope": "organization","protection": "always","approval": "identity_authority","rule": "identity_authority","grant": "role","status": "active","introduced": 1,"uses": ["api:reset-break-glass"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.directories.read","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["getDirectorySyncStatus"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.directories.update","owner": "identity","scope": "organization","protection": "always","approval": "identity_authority","rule": "identity_authority","grant": "role","status": "active","introduced": 1,"uses": ["api:change-directory-source"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.groups.create","owner": "identity","scope": "organization","protection": "conditional","approval": "access_policy","rule": "group_change","grant": "role","status": "active","introduced": 1,"uses": ["api:create-user-group"],"source": "docs/design/console.md#5.11","note": "Requires current permission and target access."},
    {"name": "identity.groups.delete","owner": "identity","scope": "organization","protection": "conditional","approval": "access_policy","rule": "group_change","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-user-group"],"source": "docs/design/console.md#5.11","note": "Requires current permission and target access."},
    {"name": "identity.groups.read","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listGroups"],"source": "docs/design/console.md#5.11","note": "Requires current permission and target access."},
    {"name": "identity.groups.update","owner": "identity","scope": "organization","protection": "conditional","approval": "access_policy","rule": "group_change","grant": "role","status": "active","introduced": 1,"uses": ["api:update-user-group"],"source": "docs/design/console.md#5.11","note": "Requires current permission and target access."},
    {"name": "identity.mappings.read","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:mappings"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.mappings.update","owner": "identity","scope": "organization","protection": "always","approval": "identity_authority","rule": "identity_authority","grant": "role","status": "active","introduced": 1,"uses": ["api:change-claim-or-group-mapping"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.principal_links.read","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:principal_links"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.principal_links.update","owner": "identity","scope": "organization","protection": "always","approval": "identity_authority","rule": "identity_authority","grant": "role","status": "active","introduced": 1,"uses": ["api:change-principal-link"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.providers.read","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listIdentityProviders"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.providers.update","owner": "identity","scope": "organization","protection": "always","approval": "identity_authority","rule": "identity_authority","grant": "role","status": "active","introduced": 1,"uses": ["updateIdentityProvider"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.recovery.read","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:recovery"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.recovery.update","owner": "identity","scope": "organization","protection": "always","approval": "identity_authority","rule": "identity_authority","grant": "role","status": "active","introduced": 1,"uses": ["api:change-account-recovery"],"source": "docs/design/console.md#3.2","note": "Requires current permission and target access."},
    {"name": "identity.sessions.read","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listSessions"],"source": "docs/design/console.md#5.11","note": "Requires current permission and target access."},
    {"name": "identity.sessions.revoke","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["revokeSession"],"source": "docs/design/console.md#5.11","note": "Requires current permission and target access."},
    {"name": "identity.tokens.create","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createApiToken"],"source": "docs/design/console.md#2.6","note": "Fresh authentication; subset of current permissions and scope; never authority approval or connector-only permissions."},
    {"name": "identity.tokens.manage","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listApiTokens#all","revokeApiToken#other"],"source": "docs/design/console.md#2.6","note": "Existing named aggregate permission covers listing and revoking other users tokens only, not minting or reading secrets."},
    {"name": "identity.tokens.read","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listApiTokens#own"],"source": "docs/design/console.md#2.6","note": "Requires current permission and target access."},
    {"name": "identity.tokens.revoke","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["revokeApiToken#own"],"source": "docs/design/console.md#2.6","note": "Requires current permission and target access."},
    {"name": "identity.users.read","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listUsers"],"source": "docs/design/console.md#5.11","note": "Requires current permission and target access."},
    {"name": "identity.users.update","owner": "identity","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["updateUser"],"source": "docs/design/console.md#5.11","note": "Ordinary user status only; rejects principal, mapping, recovery and break-glass mutations, which need dedicated identity-authority permissions."},
    {"name": "lineage.classification.reclassify","owner": "lineage","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:lower-sensitivity-floor"],"source": "docs/design/lineage.md#3","note": "Binds exact revision, current floor and classification catalogue, new label and evidence; signed convergence remains blocked."},
    {"name": "lineage.edges.read","owner": "lineage","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["queryLineage","getLineageEdge"],"source": "docs/design/console.md#5.5","note": "Scope every node, edge and aggregate; omitted neighbors must not leak paths or counts."},
    {"name": "mdm.activation_lock.read","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:read-activation_lock-secret"],"source": "docs/design/mdm.md#12","note": "Separate audited secret read; rotation where supported; never bridge or report data."},
    {"name": "mdm.activation_lock.rotate","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:rotate-activation_lock-secret"],"source": "docs/design/mdm.md#12","note": "Conservative protection for a recovery-route change; platform gates still apply."},
    {"name": "mdm.apple_push.create","owner": "mdm","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createApplePushCsr"],"source": "docs/design/console.md#5.2","note": "Requires current permission and target access."},
    {"name": "mdm.apple_push.read","owner": "mdm","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["getApplePushCertificate"],"source": "docs/design/console.md#5.2","note": "Requires current permission and target access."},
    {"name": "mdm.apple_push.replace","owner": "mdm","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["uploadApplePushCertificate#replace-topic"],"source": "docs/design/mdm.md#9.4","note": "Additional to mdm.apple_push.update. Freeze old/new topics and the full Apple-enrolled fleet; require mdm.devices.update and mdm.enrollments.read across every affected device. Explicit re-enrollment remains required; a certificate upload cannot silently replace a topic."},
    {"name": "mdm.apple_push.update","owner": "mdm","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["uploadApplePushCertificate"],"source": "docs/design/console.md#5.2","note": "Requires current permission and target access."},
    {"name": "mdm.bitlocker.read","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:read-bitlocker-secret"],"source": "docs/design/mdm.md#12","note": "Separate audited secret read; rotation where supported; never bridge or report data."},
    {"name": "mdm.bitlocker.rotate","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:rotate-bitlocker-secret"],"source": "docs/design/mdm.md#12","note": "Conservative protection for a recovery-route change; platform gates still apply."},
    {"name": "mdm.commands.diagnose","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#diagnostics"],"source": "docs/design/mdm.md#8","note": "Requires current permission and target access."},
    {"name": "mdm.commands.install","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#install-software"],"source": "docs/design/mdm.md#8","note": "Requires current permission and target access."},
    {"name": "mdm.commands.lock","owner": "mdm","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "fleet_gt_10","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#lock"],"source": "docs/design/mdm.md#8","note": "Requires current permission and target access."},
    {"name": "mdm.commands.message","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#message"],"source": "docs/design/mdm.md#8","note": "Requires current permission and target access."},
    {"name": "mdm.commands.preflight","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#preflight"],"source": "docs/design/mdm.md#8","note": "Requires current permission and target access."},
    {"name": "mdm.commands.read","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listDeviceCommands"],"source": "docs/design/mdm.md#8","note": "Requires current permission and target access."},
    {"name": "mdm.commands.remove","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#remove-software"],"source": "docs/design/mdm.md#8","note": "Requires current permission and target access."},
    {"name": "mdm.commands.restart","owner": "mdm","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "fleet_gt_10","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#restart"],"source": "docs/design/mdm.md#8","note": "Requires current permission and target access."},
    {"name": "mdm.commands.script","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#run-script"],"source": "docs/design/mdm.md#8","note": "Requires current permission and target access."},
    {"name": "mdm.commands.shutdown","owner": "mdm","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "fleet_gt_10","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#shutdown"],"source": "docs/design/mdm.md#8","note": "Requires current permission and target access."},
    {"name": "mdm.commands.update","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#update-software"],"source": "docs/design/mdm.md#8","note": "Requires current permission and target access."},
    {"name": "mdm.commands.update_os","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#update-os"],"source": "docs/design/mdm.md#8","note": "Conservative approval for urgent install outside an approved baseline; ordinary scheduled updates use that baseline authority."},
    {"name": "mdm.commands.wipe","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#wipe"],"source": "docs/design/mdm.md#8","note": "Requires current permission and target access."},
    {"name": "mdm.compliance.read","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listComplianceResults"],"source": "docs/design/console.md#5.2","note": "Requires current permission and target access."},
    {"name": "mdm.deployments.create","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createSoftwareDeployment"],"source": "docs/design/console.md#5.2","note": "Also requires policy.policies.create or update and policy.baselines.update for each changed resource."},
    {"name": "mdm.devices.read","owner": "devices","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listDevices","getDevice","getDeviceCapabilities"],"source": "docs/design/console.md#5.1","note": "Requires current permission and target access."},
    {"name": "mdm.devices.resume","owner": "devices","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#resume"],"source": "docs/design/console.md#5.1","note": "Requires current permission and target access."},
    {"name": "mdm.devices.retire","owner": "devices","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#retire"],"source": "docs/design/console.md#5.1","note": "Requires current permission and target access."},
    {"name": "mdm.devices.suspend","owner": "devices","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createDeviceAction#suspend"],"source": "docs/design/console.md#5.1","note": "Requires current permission and target access."},
    {"name": "mdm.devices.update","owner": "devices","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "group_change","grant": "role","status": "active","introduced": 1,"uses": ["updateDevice"],"source": "docs/design/console.md#5.1","note": "Group-link writes also require mdm.groups.update. Check labels, ownership, before/after membership, grants and compiled outcomes."},
    {"name": "mdm.enrollment_tokens.create","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createEnrollmentToken"],"source": "docs/design/console.md#5.2","note": "PKI-02 token limits and enrollment approval remain mandatory; secret shown once."},
    {"name": "mdm.enrollment_tokens.read","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listEnrollmentTokens"],"source": "docs/design/console.md#5.2","note": "Requires current permission and target access."},
    {"name": "mdm.enrollment_tokens.revoke","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["revokeEnrollmentToken"],"source": "docs/design/console.md#5.2","note": "Requires current permission and target access."},
    {"name": "mdm.enrollments.approve","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["decideEnrollmentRequest#approve"],"source": "docs/design/console.md#5.2","note": "Fresh interactive authentication; exact request, CSR, device and profile binding under PKI-02."},
    {"name": "mdm.enrollments.read","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listEnrollmentRequests","getEnrollmentConfiguration"],"source": "docs/design/console.md#5.2","note": "Configuration retrieval excludes existing token secrets; creation response alone contains a new secret."},
    {"name": "mdm.enrollments.reject","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["decideEnrollmentRequest#reject"],"source": "docs/design/console.md#5.2","note": "Fresh interactive authentication."},
    {"name": "mdm.filevault.read","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:read-filevault-secret"],"source": "docs/design/mdm.md#12","note": "Separate audited secret read; rotation where supported; never bridge or report data."},
    {"name": "mdm.filevault.rotate","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:rotate-filevault-secret"],"source": "docs/design/mdm.md#12","note": "Conservative protection for a recovery-route change; platform gates still apply."},
    {"name": "mdm.groups.create","owner": "devices","scope": "organization","protection": "conditional","approval": "access_policy","rule": "group_change","grant": "role","status": "active","introduced": 1,"uses": ["api:create-device-group"],"source": "docs/design/mdm.md#1.1","note": "Requires current permission and target access."},
    {"name": "mdm.groups.delete","owner": "devices","scope": "organization","protection": "conditional","approval": "access_policy","rule": "group_change","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-device-group"],"source": "docs/design/mdm.md#1.1","note": "Requires current permission and target access."},
    {"name": "mdm.groups.read","owner": "devices","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:device-groups"],"source": "docs/design/mdm.md#1.1","note": "Requires current permission and target access."},
    {"name": "mdm.groups.update","owner": "devices","scope": "organization","protection": "conditional","approval": "access_policy","rule": "group_change","grant": "role","status": "active","introduced": 1,"uses": ["api:update-device-group"],"source": "docs/design/mdm.md#1.1","note": "Requires current permission and target access."},
    {"name": "mdm.inventory.confirm","owner": "mdm","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["api:confirm-lower-os-report"],"source": "docs/design/policy.md#2.4","note": "Explicit confirmation of lower OS or version evidence; classify affected policy and compliance outcomes before acceptance."},
    {"name": "mdm.inventory.read","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["getDeviceInventory","listDeviceSoftware"],"source": "docs/design/console.md#5.1","note": "Requires current permission and target access."},
    {"name": "mdm.lock_pin.read","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:read-lock_pin-secret"],"source": "docs/design/mdm.md#12","note": "Separate audited secret read; rotation where supported; never bridge or report data."},
    {"name": "mdm.lock_pin.rotate","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:rotate-lock_pin-secret"],"source": "docs/design/mdm.md#12","note": "Conservative protection for a recovery-route change; platform gates still apply."},
    {"name": "mdm.luks.read","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:read-luks-secret"],"source": "docs/design/mdm.md#12","note": "Separate audited secret read; rotation where supported; never bridge or report data."},
    {"name": "mdm.luks.rotate","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:rotate-luks-secret"],"source": "docs/design/mdm.md#12","note": "Conservative protection for a recovery-route change; platform gates still apply."},
    {"name": "mdm.push_key.read","owner": "mdm","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:read-apple-push-key"],"source": "docs/design/mdm.md#12","note": "Dedicated audited secret read under MDM section 12; no general key-export authority."},
    {"name": "mdm.recovery.approve","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:approve-device-recovery"],"source": "docs/design/pki.md#1","note": "PKI-02 request and CSR binding plus fresh interactive authentication; not a generic BE-02 approval."},
    {"name": "mdm.recovery.create","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:issue-device-recovery-token"],"source": "docs/design/pki.md#1","note": "Requires PKI-02 exact record takeover approval; catalogue chooses BE-02 protection for token issuance too."},
    {"name": "mdm.recovery_lock.read","owner": "mdm","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:read-recovery_lock-secret"],"source": "docs/design/mdm.md#12","note": "Separate audited secret read; rotation where supported; never bridge or report data."},
    {"name": "mdm.recovery_lock.rotate","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:rotate-recovery_lock-secret"],"source": "docs/design/mdm.md#12","note": "Conservative protection for a recovery-route change; platform gates still apply."},
    {"name": "mdm.releases.read","owner": "devices","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listAgentReleases"],"source": "docs/design/console.md#5.14","note": "Requires current permission and target access."},
    {"name": "mdm.rollouts.advance","owner": "devices","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 2,"uses": ["updateRollout#advance"],"source": "docs/design/console.md#5.14","note": "Additional to mdm.rollouts.update. Freeze rollout, version and every before/after device, including group version pins; apply policy_change to weakened enforcement or compatibility. Health and release-signature gates remain required."},
    {"name": "mdm.rollouts.create","owner": "devices","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createRollout"],"source": "docs/design/console.md#5.14","note": "Requires current permission and target access."},
    {"name": "mdm.rollouts.pause","owner": "devices","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 2,"uses": ["updateRollout#pause"],"source": "docs/design/console.md#5.14","note": "Additional to mdm.rollouts.update. Freeze rollout, version and every before/after device, including group version pins; apply policy_change to weakened enforcement or compatibility. Health and release-signature gates remain required."},
    {"name": "mdm.rollouts.pin","owner": "devices","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 2,"uses": ["updateRollout#pin"],"source": "docs/design/console.md#5.14","note": "Additional to mdm.rollouts.update. Freeze rollout, version and every before/after device, including group version pins; apply policy_change to weakened enforcement or compatibility. Health and release-signature gates remain required."},
    {"name": "mdm.rollouts.read","owner": "devices","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listRollouts"],"source": "docs/design/console.md#5.14","note": "Requires current permission and target access."},
    {"name": "mdm.rollouts.resume","owner": "devices","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 2,"uses": ["updateRollout#resume"],"source": "docs/design/console.md#5.14","note": "Additional to mdm.rollouts.update. Freeze rollout, version and every before/after device, including group version pins; apply policy_change to weakened enforcement or compatibility. Health and release-signature gates remain required."},
    {"name": "mdm.rollouts.update","owner": "devices","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["updateRollout"],"source": "docs/design/console.md#5.14","note": "Includes advance, pause, resume and version pins; never bypass signed release and rollback floors."},
    {"name": "mdm.software.create","owner": "mdm","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:create-software-package"],"source": "docs/design/mdm.md#4","note": "Requires current permission and target access."},
    {"name": "mdm.software.delete","owner": "mdm","scope": "organization","protection": "conditional","approval": "access_policy","rule": "published_content","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-software-package"],"source": "docs/design/mdm.md#4","note": "Requires current permission and target access."},
    {"name": "mdm.software.publish","owner": "mdm","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:publish-software-package"],"source": "docs/design/mdm.md#4","note": "Requires current permission and target access."},
    {"name": "mdm.software.read","owner": "mdm","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listSoftwarePackages"],"source": "docs/design/mdm.md#4","note": "Requires current permission and target access."},
    {"name": "mdm.software.update","owner": "mdm","scope": "organization","protection": "conditional","approval": "access_policy","rule": "published_content","grant": "role","status": "active","introduced": 1,"uses": ["api:update-software-package"],"source": "docs/design/mdm.md#4","note": "Requires current permission and target access."},
    {"name": "mdm.uninstall.create","owner": "mdm","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createUninstallCode"],"source": "docs/design/console.md#5.1","note": "Fresh authentication; exact device nonce; conservative retirement-equivalent protection."},
    {"name": "mdm.versions.read","owner": "devices","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["getVersionDistribution"],"source": "docs/design/console.md#5.14","note": "Requires current permission and target access."},
    {"name": "mdm.windows_enrollment.read","owner": "mdm","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:windows-enrollment"],"source": "docs/design/console.md#5.2","note": "Requires current permission and target access."},
    {"name": "mdm.windows_enrollment.update","owner": "mdm","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:update-windows-enrollment"],"source": "docs/design/console.md#5.2","note": "Conservative approval for management enrollment authority changes."},
    {"name": "pki.cas.key_operation","owner": "pki","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createCaKeyOperation"],"source": "docs/design/console.md#5.6","note": "Includes key generation, rotation and activation of offline-root-signed issuing certificates; root key stays offline."},
    {"name": "pki.cas.read","owner": "pki","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listIssuingCas","getCaStatus"],"source": "docs/design/console.md#5.6","note": "Requires current permission and target access."},
    {"name": "pki.certificates.read","owner": "pki","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listCertificates","getCertificate"],"source": "docs/design/console.md#5.6","note": "Device-bound profiles only; service and CA certificates require pki.infrastructure.read."},
    {"name": "pki.certificates.revoke","owner": "pki","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["revokeCertificate"],"source": "docs/design/console.md#5.6","note": "Device-bound profiles only; no approval may delay revocation."},
    {"name": "pki.endorsement_keys.delete","owner": "pki","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:delete-endorsement-key-allow-list"],"source": "docs/design/pki.md#1","note": "Endorsement-key allow-list delete. Metadata contains public-key fingerprints only. Writes freeze the full before/after allow list and affected enrollment groups; require current mdm.enrollments.read scope for every affected request/device. List membership never approves enrollment, issuance or lost-key recovery."},
    {"name": "pki.endorsement_keys.import","owner": "pki","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:import-endorsement-key-allow-list"],"source": "docs/design/pki.md#1","note": "Endorsement-key allow-list import. Metadata contains public-key fingerprints only. Writes freeze the full before/after allow list and affected enrollment groups; require current mdm.enrollments.read scope for every affected request/device. List membership never approves enrollment, issuance or lost-key recovery."},
    {"name": "pki.endorsement_keys.read","owner": "pki","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 2,"uses": ["api:read-endorsement-key-allow-list"],"source": "docs/design/pki.md#1","note": "Endorsement-key allow-list read. Metadata contains public-key fingerprints only. Writes freeze the full before/after allow list and affected enrollment groups; require current mdm.enrollments.read scope for every affected request/device. List membership never approves enrollment, issuance or lost-key recovery."},
    {"name": "pki.endorsement_keys.update","owner": "pki","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:update-endorsement-key-allow-list"],"source": "docs/design/pki.md#1","note": "Endorsement-key allow-list update. Metadata contains public-key fingerprints only. Writes freeze the full before/after allow list and affected enrollment groups; require current mdm.enrollments.read scope for every affected request/device. List membership never approves enrollment, issuance or lost-key recovery."},
    {"name": "pki.external_cas.read","owner": "pki","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:external-cas"],"source": "docs/design/console.md#5.6","note": "Requires current permission and target access."},
    {"name": "pki.external_cas.update","owner": "pki","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:update-external-ca"],"source": "docs/design/console.md#5.6","note": "Also requires extensions.connectors.update when connector registration changes."},
    {"name": "pki.external_issuance.reconcile","owner": "pki","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:reconcile-external-issuance"],"source": "docs/design/extensions.md#6.2","note": "Requires pki.external_cas.read, extensions.connectors.read and authoritative device or infrastructure certificate reads for every affected issuance. Reconcile external certificates without reviving expired callbacks. Revocation uses the separate certificate revoke permission and never waits for this approval."},
    {"name": "pki.gateway_issuance.create","owner": "pki","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:request-network-gateway-certificate"],"source": "docs/design/radius.md#5","note": "Requires radius.gateways.update and pki.profiles.read. Freeze gateway registration, profile, CSR hash and derived subject/SANs; jobs validates CSR proof and stored issuance authority. Request fields cannot widen the registration or profile; no CA key disclosure."},
    {"name": "pki.infrastructure.read","owner": "pki","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listCertificates#infrastructure","getCertificate#infrastructure"],"source": "docs/design/pki.md#4","note": "Requires current permission and target access."},
    {"name": "pki.infrastructure.revoke","owner": "pki","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["revokeCertificate#infrastructure"],"source": "docs/design/pki.md#4","note": "Service, server, CA and signing certificates; revocation is immediate."},
    {"name": "pki.issuance.create","owner": "pki","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:request-service-certificate"],"source": "docs/design/pki.md#3","note": "Administrative issuance only; ACME, SCEP and agent renewal use protocol principals, not this permission."},
    {"name": "pki.profiles.read","owner": "pki","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listCertificateProfiles"],"source": "docs/design/console.md#5.6","note": "Requires current permission and target access."},
    {"name": "pki.profiles.update","owner": "pki","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["updateCertificateProfile"],"source": "docs/design/console.md#5.6","note": "Conservative approval for changes to issuance constraints."},
    {"name": "platform.api.read","owner": "platform","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["getOpenApiDocument","view:cli-downloads"],"source": "docs/design/console.md#5.13","note": "Requires current permission and target access."},
    {"name": "platform.backups.create","owner": "platform","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:create-backup"],"source": "docs/design/backend.md#6","note": "No restore permission: sealed offline-quorum repair cannot be delegated through RBAC."},
    {"name": "platform.backups.read","owner": "platform","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:backup-status"],"source": "docs/design/backend.md#6","note": "Status only; no key-custody manifest secrets or backup downloads."},
    {"name": "platform.settings.read","owner": "platform","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:server-settings"],"source": "docs/design/backend.md#6","note": "Requires current permission and target access."},
    {"name": "platform.settings.update","owner": "platform","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:update-server-settings"],"source": "docs/design/backend.md#6","note": "Conservative default; dedicated identity, export, retention and access-policy permissions still required."},
    {"name": "policy.attack.import","owner": "policy","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:import-attack-dataset"],"source": "docs/specs/rule-adapters.md#9","note": "Replace the pinned Enterprise ATT&CK dataset after validation. Freeze dataset hash and all affected rule/policy references; require policy.policies.update over affected targets and policy_change for indirect enforcement effects. Preserve required license notices."},
    {"name": "policy.backtests.create","owner": "policy","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["createBacktest"],"source": "docs/design/console.md#5.9","note": "Also requires every source read permission."},
    {"name": "policy.backtests.read","owner": "policy","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["getBacktest"],"source": "docs/design/console.md#5.9","note": "Recheck current source permissions and footprint."},
    {"name": "policy.baselines.create","owner": "policy","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["createBaseline"],"source": "docs/design/console.md#5.8","note": "Requires current permission and target access."},
    {"name": "policy.baselines.delete","owner": "policy","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["deleteBaseline"],"source": "docs/design/console.md#5.8","note": "Requires current permission and target access."},
    {"name": "policy.baselines.import","owner": "policy","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 2,"uses": ["api:import-xccdf-baseline"],"source": "docs/specs/baseline.md#5","note": "Translate or stage XCCDF into baseline items and an unsupported-rule report; do not publish or apply. Referenced resources require current reads and target scope. Saving requires policy.baselines.create or policy.baselines.update with policy_change; apply-capable content and target expansion retain protected approval."},
    {"name": "policy.baselines.read","owner": "policy","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listBaselines","getBaseline","listBaselineVersions"],"source": "docs/design/console.md#5.8","note": "Requires current permission and target access."},
    {"name": "policy.baselines.update","owner": "policy","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["updateBaseline"],"source": "docs/design/console.md#5.8","note": "Requires current permission and target access."},
    {"name": "policy.baselines.validate","owner": "policy","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["validateBaseline"],"source": "docs/design/console.md#5.8","note": "Validation and dry-run details require read permissions for referenced resources and every affected device."},
    {"name": "policy.coverage.read","owner": "policy","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["getCoverage"],"source": "docs/design/console.md#5.9","note": "Requires current permission and target access."},
    {"name": "policy.environment.read","owner": "policy","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["getCelEnvironment"],"source": "docs/design/console.md#5.8","note": "Requires current permission and target access."},
    {"name": "policy.exceptions.create","owner": "policy","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["createException"],"source": "docs/design/console.md#5.8","note": "Requires current permission and target access."},
    {"name": "policy.exceptions.delete","owner": "policy","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["deleteException"],"source": "docs/design/console.md#5.8","note": "Requires current permission and target access."},
    {"name": "policy.exceptions.read","owner": "policy","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listExceptions","getException","listExceptionVersions"],"source": "docs/design/console.md#5.8","note": "Requires current permission and target access."},
    {"name": "policy.exceptions.update","owner": "policy","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["updateException"],"source": "docs/design/console.md#5.8","note": "Requires current permission and target access."},
    {"name": "policy.exceptions.validate","owner": "policy","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["validateException"],"source": "docs/design/console.md#5.8","note": "Validation and dry-run details require read permissions for referenced resources and every affected device."},
    {"name": "policy.gitops.read","owner": "policy","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listGitOpsSources","getGitOpsStatus"],"source": "docs/design/console.md#5.13","note": "Requires current permission and target access."},
    {"name": "policy.gitops.update","owner": "policy","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["updateGitOpsSource"],"source": "docs/design/console.md#5.13","note": "Conservative protection for repository authority; every apply separately checks resource permissions and approvals."},
    {"name": "policy.gitops.validate","owner": "policy","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["dryRunGitOpsSource"],"source": "docs/design/console.md#5.13","note": "Requires permissions for every examined resource and affected scope."},
    {"name": "policy.ownership.override","owner": "policy","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["api:override-gitops-ownership"],"source": "docs/design/console.md#5.8","note": "Additional to the exact resource write permission; cannot bypass its scope or approval."},
    {"name": "policy.policies.create","owner": "policy","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["createPolicy"],"source": "docs/design/console.md#5.8","note": "Requires current permission and target access."},
    {"name": "policy.policies.delete","owner": "policy","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["deletePolicy"],"source": "docs/design/console.md#5.8","note": "Requires current permission and target access."},
    {"name": "policy.policies.read","owner": "policy","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listPolicies","getPolicy","listPolicyVersions","getDevicePolicyState"],"source": "docs/design/console.md#5.8","note": "Requires current permission and target access."},
    {"name": "policy.policies.test","owner": "policy","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 2,"uses": ["api:test-policy-fixtures"],"source": "docs/design/policy.md#7.3","note": "Requires policy.policies.read for every referenced policy and target; fixture execution grants no publication or live response authority. Stored-event tests also require policy.backtests.create and every source read."},
    {"name": "policy.policies.update","owner": "policy","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["updatePolicy"],"source": "docs/design/console.md#5.8","note": "Requires current permission and target access."},
    {"name": "policy.policies.validate","owner": "policy","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["validatePolicy"],"source": "docs/design/console.md#5.8","note": "Validation and dry-run details require read permissions for referenced resources and every affected device."},
    {"name": "policy.rulepacks.enable","owner": "policy","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:reenable-governed-rule-pack"],"source": "docs/design/policy.md#9","note": "Requires policy.rulepacks.read and policy.policies.update over every selected target. Freeze the exact pack/version, device set and governance state; apply policy_change and recheck runtime budgets. Re-enable grants no publication or approval bypass."},
    {"name": "policy.rulepacks.import","owner": "policy","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["importRulePack"],"source": "docs/design/console.md#5.9","note": "Requires current permission and target access."},
    {"name": "policy.rulepacks.publish","owner": "policy","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["publishRulePack"],"source": "docs/design/console.md#5.9","note": "License attestation and exact package version and digest bound to scopes."},
    {"name": "policy.rulepacks.read","owner": "policy","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listRulePacks","getRulePack","getRulePackReport"],"source": "docs/design/console.md#5.9","note": "Requires current permission and target access."},
    {"name": "policy.rulepacks.retire","owner": "policy","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 2,"uses": ["api:retire-rule-pack-version"],"source": "docs/design/policy.md#6.1","note": "Also requires policy.policies.update over every affected before/after target, including every publication, pinned policy and unpinned dependent policy. Freeze version digest, dependency closure and target set; reject partial coverage or unresolved targets. Apply policy_change as well; recheck dependencies before commit. Retirement changes global version availability, not selected scope bindings."},
    {"name": "policy.rulepacks.test","owner": "policy","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["runRulePackTests"],"source": "docs/design/console.md#5.9","note": "Requires current permission and target access."},
    {"name": "policy.rulepacks.upload","owner": "policy","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 2,"uses": ["api:upload-rule-pack-fixtures"],"source": "docs/design/policy.md#7.3","note": "Requires policy.rulepacks.import and policy.rulepacks.read. Bind fixtures to an imported version digest; published bytes and test results cannot be replaced. A published version change must use import and protected publish."},
    {"name": "policy.rulepacks.withdraw","owner": "policy","scope": "device_group","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["withdrawRulePack"],"source": "docs/design/console.md#5.9","note": "Requires current permission and target access."},
    {"name": "policy.scripts.create","owner": "policy","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:create-script"],"source": "docs/design/mdm.md#4","note": "Requires current permission and target access."},
    {"name": "policy.scripts.delete","owner": "policy","scope": "organization","protection": "conditional","approval": "access_policy","rule": "published_content","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-script"],"source": "docs/design/mdm.md#4","note": "Requires current permission and target access."},
    {"name": "policy.scripts.publish","owner": "policy","scope": "device_group","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["api:publish-script"],"source": "docs/design/mdm.md#4","note": "Requires current permission and target access."},
    {"name": "policy.scripts.read","owner": "policy","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["view:scripts"],"source": "docs/design/mdm.md#4","note": "Requires current permission and target access."},
    {"name": "policy.scripts.update","owner": "policy","scope": "organization","protection": "conditional","approval": "access_policy","rule": "published_content","grant": "role","status": "active","introduced": 1,"uses": ["api:update-script"],"source": "docs/design/mdm.md#4","note": "Requires current permission and target access."},
    {"name": "radius.authentications.read","owner": "radius","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listRadiusAuthentications"],"source": "docs/design/console.md#5.7","note": "Unbound or rejected identities with no provable device scope require scope all."},
    {"name": "radius.authorization.simulate","owner": "radius","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["simulateRadiusAuthorization"],"source": "docs/design/console.md#5.7","note": "Also needs radius.profiles.read; return only in-scope identity outcomes."},
    {"name": "radius.gateways.create","owner": "radius","scope": "organization","protection": "always","approval": "access_policy","rule": "always","grant": "role","status": "active","introduced": 1,"uses": ["createRadiusGateway"],"source": "docs/design/console.md#5.7","note": "Requires current permission and target access."},
    {"name": "radius.gateways.delete","owner": "radius","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-radius-gateway"],"source": "docs/design/console.md#5.7","note": "Requires current permission and target access."},
    {"name": "radius.gateways.read","owner": "radius","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listRadiusGateways","listRadiusProfiles"],"source": "docs/design/console.md#5.7","note": "Requires current permission and target access."},
    {"name": "radius.gateways.rotate","owner": "radius","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["rotateRadiusSecret"],"source": "docs/design/console.md#5.7","note": "Write-only secret; no read permission reveals it."},
    {"name": "radius.gateways.update","owner": "radius","scope": "organization","protection": "conditional","approval": "access_policy","rule": "gateway_widen","grant": "role","status": "active","introduced": 1,"uses": ["updateRadiusGateway"],"source": "docs/design/console.md#5.7","note": "Requires current permission and target access."},
    {"name": "radius.profiles.create","owner": "radius","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["api:create-network-access-profile"],"source": "docs/design/console.md#5.7","note": "Requires current permission and target access."},
    {"name": "radius.profiles.delete","owner": "radius","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["api:delete-network-access-profile"],"source": "docs/design/console.md#5.7","note": "Requires current permission and target access."},
    {"name": "radius.profiles.read","owner": "radius","scope": "organization","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listNetworkAccessProfiles"],"source": "docs/design/console.md#5.7","note": "Requires current permission and target access."},
    {"name": "radius.profiles.update","owner": "radius","scope": "organization","protection": "conditional","approval": "access_policy","rule": "policy_change","grant": "role","status": "active","introduced": 1,"uses": ["api:update-network-access-profile"],"source": "docs/design/console.md#5.7","note": "Requires current permission and target access."},
    {"name": "radius.sessions.disconnect","owner": "radius","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["disconnectRadiusSession"],"source": "docs/design/console.md#5.7","note": "No device attribution requires scope all; gateway qualification still gates dispatch."},
    {"name": "radius.sessions.read","owner": "radius","scope": "device_group","protection": "none","approval": "none","rule": "none","grant": "role","status": "active","introduced": 1,"uses": ["listRadiusSessions"],"source": "docs/design/console.md#5.7","note": "Requires current permission and target access."}
  ]
}
'''

# Reviewed fixture survives removal of the active proposal. Never read it from either Git tree.
_REVIEWED_DELTA_JSON = r'''{
  "base_revision": 3,
  "revision": 4,
  "add_permissions": [
    {
      "name": "identity.providers.create",
      "owner": "identity",
      "scope": "organization",
      "protection": "always",
      "approval": "identity_authority",
      "rule": "identity_authority",
      "grant": "role",
      "status": "active",
      "introduced": 4,
      "uses": [
        "createIdentityProvider"
      ],
      "source": "docs/specs/identity-login.md#5",
      "note": "Creating a provider adds an authentication authority; fresh authentication and an unaffected direct authority approver are required."
    },
    {
      "name": "identity.providers.delete",
      "owner": "identity",
      "scope": "organization",
      "protection": "always",
      "approval": "identity_authority",
      "rule": "identity_authority",
      "grant": "role",
      "status": "active",
      "introduced": 4,
      "uses": [
        "deleteIdentityProvider"
      ],
      "source": "docs/specs/identity-login.md#5",
      "note": "Deleting a provider removes an authentication authority and its links; fresh authentication and an unaffected direct authority approver are required."
    }
  ],
  "add_uses": [
    {
      "name": "authz.approvals.approve",
      "use": "approveApprovalRequest"
    },
    {
      "name": "authz.approvals.read",
      "use": "listApprovalRequests#all"
    },
    {
      "name": "authz.approvals.read",
      "use": "getApprovalRequest#any"
    },
    {
      "name": "authz.approvals.reject",
      "use": "rejectApprovalRequest"
    },
    {
      "name": "identity.authority.approve",
      "use": "approveIdentityAuthorityRequest"
    },
    {
      "name": "identity.authority.approve",
      "use": "rejectIdentityAuthorityRequest"
    },
    {
      "name": "identity.break_glass.create",
      "use": "createBreakGlassAccount"
    },
    {
      "name": "identity.break_glass.delete",
      "use": "deleteBreakGlassAccount"
    },
    {
      "name": "identity.break_glass.disable",
      "use": "disableBreakGlassAccount"
    },
    {
      "name": "identity.break_glass.enable",
      "use": "enableBreakGlassAccount"
    },
    {
      "name": "identity.break_glass.read",
      "use": "listBreakGlassAccounts"
    },
    {
      "name": "identity.break_glass.replace_factor",
      "use": "replaceBreakGlassFactor"
    },
    {
      "name": "identity.break_glass.reset",
      "use": "resetBreakGlassAccount"
    },
    {
      "name": "identity.principal_links.read",
      "use": "listPrincipalLinks"
    },
    {
      "name": "identity.principal_links.read",
      "use": "listPrincipalLinkRequests"
    },
    {
      "name": "identity.principal_links.update",
      "use": "createPrincipalLink"
    },
    {
      "name": "identity.principal_links.update",
      "use": "deletePrincipalLink"
    },
    {
      "name": "identity.sessions.revoke",
      "use": "revokeUserSessions"
    },
    {
      "name": "authz.approvals.read",
      "use": "getApprovalRequestTargets#any"
    },
    {
      "name": "mdm.devices.read",
      "use": "streamChanges#devices"
    },
    {
      "name": "edr.alerts.read",
      "use": "streamChanges#alerts"
    },
    {
      "name": "dlp.findings.read",
      "use": "streamChanges#dlp-findings"
    },
    {
      "name": "mdm.enrollments.read",
      "use": "streamChanges#enrollments"
    },
    {
      "name": "pki.certificates.read",
      "use": "streamChanges#certificates"
    },
    {
      "name": "pki.infrastructure.read",
      "use": "streamChanges#certificates-infrastructure"
    },
    {
      "name": "mdm.rollouts.read",
      "use": "streamChanges#rollouts"
    },
    {
      "name": "extensions.packages.read",
      "use": "streamChanges#extensions"
    },
    {
      "name": "events.destinations.read",
      "use": "streamChanges#exports"
    },
    {
      "name": "mdm.devices.read",
      "use": "streamChanges#device"
    },
    {
      "name": "edr.alerts.read",
      "use": "streamChanges#alert"
    },
    {
      "name": "mdm.commands.read",
      "use": "streamChanges#commands"
    },
    {
      "name": "authz.approvals.read",
      "use": "streamChanges#approvals-all"
    }
  ]
}
'''


def entry(cat, name):
    return next(p for p in cat['permissions'] if p['name'] == name)


def new_entry(introduced, **fields):
    row = {'name': 'mdm.devices.test', 'owner': 'mdm', 'scope': 'device_group', 'protection': 'none',
           'approval': 'none', 'rule': 'none', 'grant': 'role', 'status': 'active', 'introduced': introduced,
           'uses': ['api:test-device'], 'source': 'docs/design/mdm.md#8', 'note': 'Fixture entry.'}
    row.update(fields)
    return row


def add(cat, row):
    cat['permissions'].append(row)
    cat['permissions'].sort(key=lambda p: p['name'])


def weakened_schema(schema):
    """A PR-controlled schema that drops closed members, bounds, grammar and grant rules."""
    weak = copy.deepcopy(schema)
    weak['additionalProperties'] = True
    weak['properties']['revision'] = {'type': 'integer'}
    weak['properties']['permissions'] = {'type': 'array', 'items': {'$ref': '#/$defs/permission'}}
    permission = weak['$defs']['permission']
    permission['additionalProperties'] = True
    permission['required'] = ['name']
    for field in ('introduced', 'retired_in'):
        permission['properties'][field] = {'type': 'integer'}
    for field in ('owner', 'scope', 'protection', 'approval', 'rule', 'grant', 'status', 'source', 'note'):
        permission['properties'][field] = {'type': 'string'}
    permission['properties']['uses'] = {}
    del permission['allOf']
    weak['$defs']['name'] = {'type': 'string'}
    return weak


class CatalogueCompatTests(unittest.TestCase):
    def setUp(self):
        import catalogue_compat
        self.compat = catalogue_compat
        self.tmp = tempfile.TemporaryDirectory(prefix='ci-catalogue-compat-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git('init', '-b', 'master')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Fixture')
        self.schema_bytes = (ROOT / SCHEMA).read_bytes()
        self.schema = json.loads(self.schema_bytes)
        self.catalogue_bytes = (ROOT / CATALOGUE).read_bytes()
        self.catalogue = json.loads(self.catalogue_bytes)
        # Fixture revisions and the probe's current scope come from the live catalogue.
        self.rb = self.catalogue['revision']
        self.rc = self.rb + 1
        probe = entry(self.catalogue, PROBE)
        self.assertEqual(probe['status'], 'active')
        self.scope = probe['scope']
        self.other_scope = 'organization' if self.scope == 'device_group' else 'device_group'
        self.write(SCHEMA, self.schema_bytes)
        self.write('README.md', b'fixture\n')
        self.base = self.commit(self.catalogue_bytes)

    def git(self, *args, data=None):
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
        return subprocess.run(['git', '-c', 'core.excludesFile=' + os.devnull, '-C', str(self.root), *args],
                              env=env, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=True).stdout.decode().strip()

    def write(self, path, data):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def encode(self, value):
        return value if isinstance(value, bytes) else (json.dumps(value, indent=1) + '\n').encode()

    def commit(self, catalogue=None, schema=None):
        """Commit catalogue bytes (or a decoded catalogue) into both canonical and embedded copies."""
        if catalogue is not None:
            self.write(CATALOGUE, self.encode(catalogue))
            self.write(EMBEDDED, self.encode(catalogue))
        if schema is not None:
            self.write(SCHEMA, self.encode(schema))
        self.git('add', '-A', '.')
        self.git('commit', '-q', '--allow-empty', '-m', 'Fixture')
        return self.git('rev-parse', 'HEAD')

    def commit_mode(self, mode, data=None, oid=None, path=CATALOGUE):
        """Record an index entry of an arbitrary Git mode without using host filesystem features."""
        if oid is None:
            oid = self.git('hash-object', '-w', '--stdin', data=data)
        self.git('update-index', '--add', '--cacheinfo', f'{mode},{oid},{path}')
        self.git('commit', '-q', '-m', 'Mode fixture')
        head = self.git('rev-parse', 'HEAD')
        self.assertTrue(self.git('ls-tree', head, '--', path).startswith(mode + ' '))
        self.git('read-tree', '-q', '--reset', self.base)
        return head

    def changed(self, change, revision=None):
        cat = copy.deepcopy(self.catalogue)
        cat['revision'] = self.rc if revision is None else revision
        change(cat)
        return cat

    def compare(self, base, candidate):
        return self.compat.compare(self.root, base, candidate)

    def reject(self, base, candidate, *fragments):
        with self.assertRaises(ValueError) as caught:
            self.compare(base, candidate)
        message = str(caught.exception)
        for fragment in fragments:
            self.assertIn(fragment, message)
        return message


    def test_public_read_exemption_inventory_mutations(self):
        module = self.compat.schema_test()
        self.assertIn('server-public-reads', module.EXEMPTIONS)
        coverage = json.loads((ROOT / 'schemas/permissions/v1/fixtures/coverage.json').read_bytes())
        if not any(e['id'] == 'server-public-reads' for e in coverage['exemptions']):
            coverage['exemptions'].append({'id': 'server-public-reads', 'source': 'docs/specs/server-runtime.md#3',
                                           'authority': 'Public health and embedded static reads only.'})
        module.exemption_check(coverage)
        for mutation in ('remove', 'rename', 'duplicate', 'authority'):
            changed = copy.deepcopy(coverage)
            row = next(e for e in changed['exemptions'] if e['id'] == 'server-public-reads')
            if mutation == 'remove': changed['exemptions'].remove(row)
            elif mutation == 'rename': row['id'] = 'server-public-writes'
            elif mutation == 'duplicate': changed['exemptions'].append(dict(row))
            else: row['authority'] = ' '
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                module.exemption_check(changed)

    def test_strict_migration_reader_rejects_noncanonical_wire_tokens(self):
        for data in (b'{"value":-0}', b'{"value":-1}', b'{"value":1.0}', b'{"value":1e0}',
                     b'{"value":"\\ud800"}', b'{"\\udfff":1}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.compat.decode(data, 'fixture')

    def migration_fixture(self):
        delta = json.loads(_REVIEWED_DELTA_JSON)
        base = json.loads(_REVIEWED_BASE_JSON)
        result = copy.deepcopy(base)
        result['revision'] = delta['revision']
        for row in delta['add_permissions']:
            add(result, copy.deepcopy(row))
        for item in delta['add_uses']:
            entry(result, item['name'])['uses'].append(item['use'])
        return base, delta, result

    def test_reviewed_migration_pins_and_no_base_openapi(self):
        base, delta, result = self.migration_fixture()
        digest = lambda value: hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                                        separators=(',', ':')).encode('ascii')).hexdigest()
        for value, want in ((base, '1966faf9ad11b86f5244747e8847fb56163187fc1c738c709bff466bbcb9615f'),
                            (delta, '09706e63ca1eaf7e1be223b5c456d8cf9cbbb588ba1f317db14658c9acf2b876'),
                            (result, '78a1b1ecaef5fade010e8bdaad85b6d57e968639cbfbc826f17c58e579727621')):
            self.assertEqual(digest(value), want)
        self.assertEqual(json.loads(self.compat._MIGRATION_DELTA_JSON), delta)
        self.assertEqual(len(delta['add_permissions']), 2)
        self.assertEqual(len(delta['add_uses']), 32)
        self.assertEqual(len({p['name'] for p in delta['add_uses']}), 24)
        # Preserve the actual reviewed bytes regardless of future canonical revisions/formatting.
        reviewed_bytes = _REVIEWED_BASE_JSON.encode('ascii')
        self.assertEqual(hashlib.sha256(reviewed_bytes).hexdigest(),
                         '084da0e06df7bbbe0d9c675fae5151733aa98644740be5a5c5765f3177b39a54')
        base_sha = self.commit(reviewed_bytes)
        actual_blob = hashlib.sha1(b'blob ' + str(len(reviewed_bytes)).encode() + b'\0' + reviewed_bytes).hexdigest()
        self.assertEqual(self.git('rev-parse', base_sha + ':' + CATALOGUE), actual_blob)
        self.assertEqual(self.git('ls-tree', base_sha, '--', 'schemas/openapi'), '')
        candidate = self.commit(result)
        # Untracked proposal bytes cannot supply authority, even if malformed.
        self.write('schemas/openapi/v1/catalogue-proposal.json', b'not a proposal')
        report = self.compare(base_sha, candidate)
        self.assertEqual(report['candidate']['catalogue'], result)
        (self.root / 'schemas/openapi/v1/catalogue-proposal.json').unlink()
        self.assertTrue(self.compare(base_sha, self.commit(reviewed_bytes))['unchanged'])
        first = self.commit(result)
        self.assertTrue(self.compare(first, self.commit(result))['unchanged'])
        formatted = self.commit(json.dumps(result, sort_keys=True).encode())
        self.compare(base_sha, formatted)
        self.compare(first, formatted)

    def test_migration_refuses_every_unpinned_catalogue_change(self):
        base, delta, result = self.migration_fixture()
        base_sha = self.commit(base)
        first = delta['add_uses'][0]
        mutations = {
            'partial selector': lambda c: entry(c, first['name'])['uses'].remove(first['use']),
            'extra selector': lambda c: entry(c, first['name'])['uses'].append('api:extra-authority'),
            'selector removal': lambda c: entry(c, first['name'])['uses'].pop(0),
            'selector reassignment': lambda c: (entry(c, first['name'])['uses'].remove(first['use']),
                                              entry(c, PROBE)['uses'].append(first['use'])),
            'immutable scope': lambda c: entry(c, PROBE).update(scope=self.other_scope),
            'new name metadata': lambda c: entry(c, 'identity.providers.create').update(note='Wrong authority.'),
            'new name spelling': lambda c: entry(c, 'identity.providers.create').update(name='identity.providers.add'),
            'old metadata': lambda c: entry(c, PROBE).update(note='Changed metadata.'),
            'old source': lambda c: entry(c, PROBE).update(source='docs/design/mdm.md#1'),
            'reordered selector': lambda c: entry(c, first['name'])['uses'].reverse(),
            'revision 5 replay': lambda c: c.update(revision=5),
        }
        for label, mutate in mutations.items():
            with self.subTest(mutation=label):
                changed = copy.deepcopy(result)
                mutate(changed)
                changed['permissions'].sort(key=lambda p: p['name'])
                self.reject(base_sha, self.commit(changed))
        wrong_base = copy.deepcopy(base)
        entry(wrong_base, PROBE)['note'] = 'Not the reviewed base.'
        self.reject(self.commit(wrong_base), self.commit(result), 'uses changed')
        tombstone_base = copy.deepcopy(base)
        entry(tombstone_base, PROBE).update(status='retired', retired_in=3)
        retired = self.commit(tombstone_base)
        changed = copy.deepcopy(result)
        entry(changed, PROBE).update(status='retired', retired_in=3, note='Changed tombstone.')
        self.reject(retired, self.commit(changed), 'tombstone changed')
        v4 = self.commit(result)
        replay = copy.deepcopy(result)
        replay['revision'] = 5
        entry(replay, first['name'])['uses'].append('api:next-migration')
        self.reject(v4, self.commit(replay), 'uses changed')
        # The unchanged schema blob is mandatory even if both schemas accept the data.
        self.reject(base_sha, self.commit(result, schema=self.schema_bytes + b' '))

    def test_migration_constant_is_strict_and_digest_pinned(self):
        base, delta, result = self.migration_fixture()
        base_sha, candidate = self.commit(base), self.commit(result)
        altered = copy.deepcopy(delta)
        altered['add_uses'][0]['use'] = 'api:extra-authority'
        for value in ('', '{', 'null', '{"revision":4,"revision":4}',
                      _REVIEWED_DELTA_JSON.replace('"revision": 4', '"revision": 4.0'),
                      json.dumps(altered), _REVIEWED_DELTA_JSON + '{}'):
            with self.subTest(delta=value[:60]), patch.object(self.compat, '_MIGRATION_DELTA_JSON', value):
                self.reject(base_sha, candidate)
        with patch.object(self.compat, '_MIGRATION_DELTA_JSON', None):
            self.reject(base_sha, candidate)
        # Corrupt each digest independently; the other pins cannot replace it.
        for name in ('_MIGRATION_BASE_DIGEST', '_MIGRATION_DELTA_DIGEST', '_MIGRATION_RESULT_DIGEST'):
            with self.subTest(pin=name), patch.object(self.compat, name, '0' * 64):
                self.reject(base_sha, candidate)
        # Full recomposition is required in addition to all digest comparisons.
        with patch.object(self.compat, '_recompose_migration', return_value=base):
            self.reject(base_sha, candidate, 'recomputed')

    def test_migration_candidate_proposal_any_object_refused(self):
        base, delta, result = self.migration_fixture()
        base_sha = self.commit(base)
        candidate = self.commit(result)
        proposal = 'schemas/openapi/v1/catalogue-proposal.json'
        for mode in ('100644', '100755', '120000', '160000'):
            with self.subTest(mode=mode):
                oid = base_sha if mode == '160000' else None
                head = self.commit_mode(mode, data=b'{}', oid=oid, path=proposal)
                self.reject(base_sha, head, 'active proposal')
                # Restore the candidate after the helper restores the ordinary test base.
                candidate = self.commit(result)
        self.write(proposal + '/inner', b'{}')
        head = self.commit(result)
        self.reject(base_sha, head, 'active proposal')
        shutil.rmtree(self.root / proposal)
        # A base proposal can be absent or arbitrary; neither supplies the delta.
        self.write(proposal, b'wrong base proposal')
        with_proposal = self.commit(base)
        (self.root / proposal).unlink()
        self.compare(with_proposal, self.commit(result))
        # Candidate-supplied alternate delta cannot authorize an unpinned result.
        wrong = copy.deepcopy(result)
        entry(wrong, PROBE)['uses'].append('api:extra-authority')
        self.write(proposal, json.dumps(delta).encode())
        self.reject(base_sha, self.commit(wrong), 'uses changed')

    def test_migration_event_binding_remains_required(self):
        base, delta, result = self.migration_fixture()
        base_sha, candidate = self.commit(base), self.commit(result)
        event = self.root / 'event.json'
        event.write_text(json.dumps({'ref': 'refs/heads/master', 'before': base_sha, 'after': candidate}))
        env = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_EVENT_PATH': str(event), 'GITHUB_SHA': candidate}
        run = self.run_cli(env, base_sha, candidate)
        self.assertEqual(run.returncode, 0, run.stderr)
        for substitute in ((candidate, candidate), (self.base, candidate), (base_sha, self.base)):
            run = self.run_cli(env, *substitute)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('substitut', run.stderr)

    def test_identical_bytes_and_revision_only_increase_pass(self):
        head = self.commit()
        report = self.compare(self.base, head)
        self.assertEqual((report['base']['sha'], report['candidate']['sha']), (self.base, head))
        self.assertEqual((report['base']['revision'], report['candidate']['revision']), (self.rb, self.rb))
        self.assertEqual(report['base']['blob'], report['candidate']['blob'])
        self.assertEqual(report['base']['blob'], self.git('rev-parse', self.base + ':' + CATALOGUE))
        self.assertEqual(report['base']['schema'], self.git('rev-parse', self.base + ':' + SCHEMA))
        self.assertTrue(report['unchanged'])
        self.assertFalse(report['schema_changed'])
        head = self.commit(self.changed(lambda cat: None))
        report = self.compare(self.base, head)
        self.assertEqual(report['candidate']['revision'], self.rc)
        self.assertFalse(report['unchanged'])

    def test_formatting_and_member_order_keep_revision(self):
        reordered = {'permissions': [dict(reversed(list(p.items()))) for p in self.catalogue['permissions']],
                     'revision': self.rb, 'format_version': 1}
        head = self.commit((json.dumps(reordered, indent=4, separators=(' , ', ' : ')) + '\n\n').encode())
        report = self.compare(self.base, head)
        self.assertFalse(report['unchanged'])
        self.assertEqual(report['candidate']['revision'], self.rb)

    def test_note_source_new_name_retirement_and_uses_order(self):
        def note(cat):
            entry(cat, PROBE)['note'] = 'Corrected wording.'
            entry(cat, PROBE)['source'] = 'docs/design/mdm.md#8.1'
        def new_name(cat):
            add(cat, new_entry(self.rc))
        def retire(cat):
            entry(cat, PROBE).update(status='retired', retired_in=self.rc)
        def uses_reordered(cat):
            row = entry(cat, 'audit.events.export')
            self.assertGreater(len(row['uses']), 1)
            row['uses'].reverse()
        for change in (note, new_name, retire, uses_reordered):
            with self.subTest(change=change.__name__):
                head = self.commit(self.changed(change))
                self.assertEqual(self.compare(self.base, head)['candidate']['revision'], self.rc)
        head = self.commit(self.changed(retire, revision=self.rc + 1))
        self.assertEqual(self.compare(self.base, head)['candidate']['revision'], self.rc + 1)
        # A uses reorder is decoded content, so it needs the revision increase; it is not semantic.
        head = self.commit(self.changed(uses_reordered, revision=self.rb))
        message = self.reject(self.base, head, 'without a revision increase')
        self.assertNotIn('uses changed', message)

    def test_audit_probe_scope_change_at_base_revision_is_rejected(self):
        def probe(cat):
            entry(cat, PROBE)['scope'] = self.other_scope
        head = self.commit(self.changed(probe, revision=self.rb))
        # Both repository copies carry the mutated bytes; compatibility still fails.
        self.assertEqual((self.root / CATALOGUE).read_bytes(), (self.root / EMBEDDED).read_bytes())
        message = self.reject(self.base, head, PROBE + ': scope changed from', repr(self.scope), repr(self.other_scope),
                              'without a revision increase')
        self.assertIn(self.base, message)
        head = self.commit(self.changed(probe))
        message = self.reject(self.base, head, PROBE + ': scope changed from', repr(self.other_scope))
        self.assertNotIn('without a revision increase', message)

    def test_semantic_field_changes_fail_with_bumped_revision(self):
        def delete(cat):
            cat['permissions'] = [p for p in cat['permissions'] if p['name'] != PROBE]
        def approval(cat):
            entry(cat, PROBE).update(rule='always', protection='always', approval='access_policy')
        def owner(cat):
            entry(cat, PROBE)['owner'] = 'devices'
        def uses_added(cat):
            entry(cat, PROBE)['uses'].append('api:restart-device')
        def uses_replaced(cat):
            entry(cat, PROBE)['uses'] = ['createDeviceAction#reboot']
        def introduced(cat):
            entry(cat, PROBE)['introduced'] = self.rc
        def stale_introduced(cat):
            add(cat, new_entry(self.rb))
        def stale_retirement(cat):
            entry(cat, PROBE).update(status='retired', retired_in=self.rb)
        cases = ((delete, PROBE + ': deleted'), (approval, PROBE + ': rule changed from'),
                 (owner, PROBE + ': owner changed from'), (uses_added, PROBE + ': uses changed'),
                 (uses_replaced, PROBE + ': uses changed'), (introduced, PROBE + ': introduced changed from'),
                 (stale_introduced, f'mdm.devices.test: new name introduced {self.rb} must exceed base revision {self.rb}'),
                 (stale_retirement, f'{PROBE}: retired_in {self.rb} must exceed base revision {self.rb}'))
        for change, fragment in cases:
            with self.subTest(change=change.__name__):
                head = self.commit(self.changed(change))
                self.reject(self.base, head, fragment)

    def test_defects_cover_grant_window_tombstones_and_schema_change_directly(self):
        """Rules the v1 schema also rejects keep their own lifecycle defect text."""
        rb, rc = self.rb, self.rc
        defects = self.compat.defects
        candidate = self.changed(lambda cat: entry(cat, PROBE).update(grant='direct'))
        self.assertEqual(defects(self.catalogue, candidate),
                         [f"{PROBE}: grant changed from 'role' to 'direct'; introduce a new name"])
        window = 'mdm.devices.test: new name introduced {} must exceed base revision %d and not exceed %d' % (rb, rc)
        for introduced in (rb, rc + 1):
            candidate = self.changed(lambda cat: add(cat, new_entry(introduced)))
            self.assertEqual(defects(self.catalogue, candidate), [window.format(introduced)])
        self.assertEqual(defects(self.catalogue, self.changed(lambda cat: add(cat, new_entry(rc)))), [])
        retired = self.changed(lambda cat: entry(cat, PROBE).update(status='retired', retired_in=rc))
        self.assertEqual(defects(self.catalogue, retired), [])
        for change in ({'note': 'Edited tombstone.'}, {'retired_in': rc + 1}, {'scope': self.other_scope},
                       {'status': 'active'}):
            cat = copy.deepcopy(retired)
            cat['revision'] = rc + 1
            entry(cat, PROBE).update(change)
            if change == {'status': 'active'}:
                del entry(cat, PROBE)['retired_in']
            self.assertEqual(defects(retired, cat), [TOMBSTONE])
        self.assertEqual(defects(self.catalogue, self.changed(lambda cat: None, revision=rb - 1)),
                         [f'revision decreased from {rb} to {rb - 1}'])
        self.assertEqual(defects(self.catalogue, self.catalogue, schema_changed=True),
                         [f'schema changed without a revision increase (revision {rb}); a validation contract change must be explicit'])
        self.assertEqual(defects(self.catalogue, self.changed(lambda cat: None), schema_changed=True), [])

    def test_tombstone_mutation_and_resurrection_fail(self):
        retired = self.commit(self.changed(lambda cat: entry(cat, PROBE).update(status='retired', retired_in=self.rc)))
        self.compare(self.base, retired)
        retired_cat = json.loads((self.root / CATALOGUE).read_bytes())
        def mutate(cat):
            entry(cat, PROBE)['note'] = 'Edited tombstone.'
        def later(cat):
            entry(cat, PROBE)['retired_in'] = self.rc + 1
        def resurrect(cat):
            entry(cat, PROBE)['status'] = 'active'
            del entry(cat, PROBE)['retired_in']
        for change in (mutate, later, resurrect):
            with self.subTest(change=change.__name__):
                cat = copy.deepcopy(retired_cat)
                cat['revision'] = self.rc + 1
                change(cat)
                head = self.commit(cat)
                self.reject(retired, head, TOMBSTONE)

    def test_revision_decrease_overflow_and_unbumped_note(self):
        head = self.commit(self.changed(lambda cat: entry(cat, PROBE).update(note='Changed without bump.'), revision=self.rb))
        self.reject(self.base, head, 'without a revision increase')
        # A revision-only bump keeps introduced and retired_in valid in both catalogues.
        bumped = self.commit(self.changed(lambda cat: None))
        self.compare(self.base, bumped)
        head = self.commit(self.catalogue_bytes)
        self.reject(bumped, head, f'revision decreased from {self.rc} to {self.rb}')
        head = self.commit(self.changed(lambda cat: None, revision=4294967296))
        self.reject(self.base, head, 'candidate: revision 4294967296 outside 1..4294967295')
        head = self.commit(self.changed(lambda cat: cat.update(format_version=2)))
        self.reject(self.base, head, 'candidate: unsupported format_version 2')

    def test_candidate_schema_cannot_weaken_the_contract(self):
        """R-01: shape, bounds, grammar and grant rules hold independently of the candidate's schema."""
        weak = weakened_schema(self.schema)
        def abuse(cat):
            cat['revision'] = 4294967296
            cat['shadow'] = 1
            entry(cat, PROBE).update(shadow_scope='organization', note='café')
            add(cat, new_entry(4, grant='direct'))
            add(cat, new_entry(4, name='MDM.Bad-Name.é'))
        head = self.commit(self.changed(abuse), schema=weak)
        message = self.reject(self.base, head, 'candidate: revision 4294967296 outside 1..4294967295',
                              "unknown root member 'shadow'", f"{PROBE}: unknown member 'shadow_scope'",
                              f'{PROBE}: note must be 1..512 printable ASCII bytes', 'name grammar',
                              "grant must be 'role'")
        self.assertIn(self.git('rev-parse', head + ':' + SCHEMA), message)
        singles = {
            'overflow': (lambda cat: cat.update(revision=4294967296), 'revision 4294967296 outside'),
            'root member': (lambda cat: cat.update(shadow=1), "unknown root member 'shadow'"),
            'entry member': (lambda cat: entry(cat, PROBE).update(shadow_scope='organization'), "unknown member 'shadow_scope'"),
            'non-ascii note': (lambda cat: entry(cat, PROBE).update(note='café'), 'note must be 1..512 printable ASCII'),
            'long note': (lambda cat: entry(cat, PROBE).update(note='x' * 513), 'note must be 1..512 printable ASCII'),
            'long source': (lambda cat: entry(cat, PROBE).update(source='x' * 161), 'source must be 1..160 printable ASCII'),
            'name grammar': (lambda cat: add(cat, new_entry(self.rc, name='mdm.Devices.test')), 'name grammar'),
            'name length': (lambda cat: add(cat, new_entry(self.rc, name='mdm.' + 'a' * 33 + '.test')), 'name grammar'),
            'grant restriction': (lambda cat: add(cat, new_entry(self.rc, grant='direct')), "grant must be 'role'"),
            'owner mapping': (lambda cat: add(cat, new_entry(self.rc, owner='pki')), 'owner must be one of'),
            'rule agreement': (lambda cat: add(cat, new_entry(self.rc, rule='always')), 'protection/approval must be'),
            'unknown rule': (lambda cat: add(cat, new_entry(self.rc, rule='sometimes')), 'rule must be one of'),
            'unknown scope': (lambda cat: entry(cat, PROBE).update(scope='tenant'), 'scope must be one of'),
            'introduced overflow': (lambda cat: add(cat, new_entry(4294967296)), 'introduced 4294967296 outside 1..4294967295'),
            'introduced zero': (lambda cat: add(cat, new_entry(0)), 'introduced 0 outside 1..4294967295'),
            'duplicate uses': (lambda cat: entry(cat, PROBE)['uses'].append(entry(cat, PROBE)['uses'][0]), 'uses must be 1..32 unique'),
            'empty uses': (lambda cat: entry(cat, PROBE).update(uses=[]), 'uses must be 1..32 unique'),
            'long use': (lambda cat: entry(cat, PROBE).update(uses=['x' * 161]), 'uses must be 1..32 unique'),
            'retired without retired_in': (lambda cat: entry(cat, PROBE).update(status='retired'), "missing member 'retired_in'"),
            'active with retired_in': (lambda cat: entry(cat, PROBE).update(retired_in=self.rc), "unknown member 'retired_in'"),
            'retired_in one': (lambda cat: entry(cat, PROBE).update(status='retired', retired_in=1), 'retired_in 1 outside 2..4294967295'),
            'unsorted names': (lambda cat: cat['permissions'].reverse(), 'names must be unique and strictly ascending'),
            'duplicate names': (lambda cat: cat['permissions'].append(dict(entry(cat, PROBE))), 'names must be unique and strictly ascending'),
            'wrong type': (lambda cat: entry(cat, PROBE).update(uses='api:string'), 'uses must be 1..32 unique'),
            'missing member': (lambda cat: entry(cat, PROBE).pop('owner'), "missing member 'owner'"),
            'non-object entry': (lambda cat: cat['permissions'].append('row'), 'permissions['),
            'empty permissions': (lambda cat: cat.update(permissions=[]), 'permissions must hold 1..2048 entries'),
            'too many permissions': (lambda cat: cat.update(permissions=cat['permissions'] * 7), 'permissions must hold 1..2048 entries'),
            # N-01: unhashable member values are defects, not a TypeError out of invariants().
            'list scope': (lambda cat: entry(cat, PROBE).update(scope=['organization']), 'scope must be one of'),
            'object rule': (lambda cat: entry(cat, PROBE).update(rule={}), 'rule must be one of'),
            'list owner': (lambda cat: entry(cat, PROBE).update(owner=['mdm']), 'owner must be one of'),
            'object status': (lambda cat: entry(cat, PROBE).update(status={}), 'status must be one of'),
            'list grant': (lambda cat: entry(cat, PROBE).update(grant=['role']), 'grant must be one of'),
        }
        for label, (change, fragment) in singles.items():
            with self.subTest(single=label):
                head = self.commit(self.changed(change), schema=weak)
                self.reject(self.base, head, 'candidate: ', fragment)
        # A weakened schema with unchanged catalogue bytes is itself an explicit contract change.
        head = self.commit(self.catalogue_bytes, schema=weak)
        self.reject(self.base, head, 'schema changed without a revision increase')
        head = self.commit(self.changed(lambda cat: None), schema=weak)
        report = self.compare(self.base, head)
        self.assertNotEqual(report['base']['schema'], report['candidate']['schema'])
        self.assertTrue(report['schema_changed'])
        # The candidate's own schema still applies when it is stricter than the base.
        strict = copy.deepcopy(self.schema)
        strict['properties']['revision'] = {'type': 'integer', 'minimum': 1, 'maximum': self.rb}
        head = self.commit(self.changed(lambda cat: None), schema=strict)
        self.reject(self.base, head, 'candidate: schema: $.revision')
        # A candidate the base schema rejects (new verb) passes only with an explicit schema change.
        extended = copy.deepcopy(self.schema)
        pattern = extended['$defs']['permission']['allOf'][6]['properties']['name']['pattern']
        extended['$defs']['permission']['allOf'][6]['properties']['name']['pattern'] = pattern.replace('|withdraw)', '|withdraw|frobnicate)')
        verb = lambda cat: add(cat, new_entry(self.rc, name='mdm.devices.frobnicate'))
        head = self.commit(self.changed(verb), schema=extended)
        self.assertTrue(self.compare(self.base, head)['schema_changed'])
        head = self.commit(self.changed(verb), schema=self.schema)
        self.reject(self.base, head, 'candidate: schema: $.permissions[')

    def test_missing_malformed_and_identical_commits(self):
        head = self.commit(self.changed(lambda cat: None))
        self.reject('f' * 40, head)
        self.reject(self.base, 'f' * 40)
        with self.assertRaises(ValueError): self.compare('HEAD', head)
        with self.assertRaises(ValueError): self.compare(self.base, 'master')
        self.reject(self.base, self.base, 'same commit')
        (self.root / CATALOGUE).unlink()
        absent = self.commit()
        self.reject(absent, head, CATALOGUE + ' absent')
        self.reject(self.base, absent, CATALOGUE + ' absent')
        self.commit(self.changed(lambda cat: None))
        (self.root / SCHEMA).unlink()
        no_schema = self.commit()
        self.reject(self.base, no_schema, SCHEMA + ' absent')
        self.reject(no_schema, head, SCHEMA + ' absent')
        self.write(SCHEMA, self.schema_bytes)
        revision = b'"revision": ' + str(self.rb).encode()
        self.assertIn(revision, self.catalogue_bytes)
        malformed = {
            'duplicate key': b'{"format_version":1,"revision":3,"revision":3,"permissions":[]}\n',
            'truncated': self.catalogue_bytes[:-20],
            'trailing value': self.catalogue_bytes + b'{}\n',
            'fraction revision': self.catalogue_bytes.replace(revision, revision + b'.0', 1),
            'exponent revision': self.catalogue_bytes.replace(revision, revision + b'e0', 1),
            'bool introduced': self.catalogue_bytes.replace(b'"introduced": 1', b'"introduced": true', 1),
            'BOM': b'\xef\xbb\xbf' + self.catalogue_bytes,
            'invalid UTF-8': self.catalogue_bytes.replace(b'"note": "', b'"note": "\xff', 1),
            'unknown field': self.catalogue_bytes.replace(b'"format_version": 1,', b'"format_version": 1, "extra": 1,', 1),
            'oversized': self.catalogue_bytes[:-2] + b' ' * (1 << 20) + b'}\n',
            'deep nesting': b'[' * 100000,
            'depth 13': b'{"a":' + b'[' * 12 + b']' * 12 + b'}',
            'scalar root': b'1\n',
            'empty': b'',
        }
        for label, data in malformed.items():
            with self.subTest(malformed=label):
                self.assertNotEqual(data, self.catalogue_bytes)
                bad = self.commit(data)
                self.reject(bad, head)
                self.reject(self.base, bad)
        schemas = {'bad type': b'{"type": 5}\n', 'bad regex': b'{"type": "object", "patternProperties": {"(unclosed": {}}}\n',
                   'not object': b'[]\n', 'duplicate key': b'{"type": "object", "type": "object"}\n',
                   'deep nesting': b'[' * 100000, 'invalid JSON': b'{'}
        for label, schema in schemas.items():
            with self.subTest(schema=label):
                bad = self.commit(self.changed(lambda cat: None), schema=schema)
                # N-02: a candidate schema failure still names the candidate commit and catalogue blob.
                self.reject(self.base, bad, 'candidate schema', f'candidate commit {bad}',
                            'catalogue blob ' + self.git('rev-parse', bad + ':' + CATALOGUE))
        gitlink = self.commit_mode('160000', oid=self.base, path=SCHEMA)
        self.reject(self.base, gitlink, f'candidate commit {gitlink}', SCHEMA, 'must be a regular file blob')

    def test_unhashable_members_return_defects_directly(self):
        """N-01: invariants() reports unhashable values as defects through the library contract."""
        for field, value in (('scope', ['organization']), ('rule', {}), ('owner', ['mdm']), ('protection', {}),
                             ('approval', []), ('grant', {}), ('status', [])):
            with self.subTest(field=field):
                cat = self.changed(lambda cat: entry(cat, PROBE).update({field: value}))
                found = self.compat.invariants(cat)
                self.assertTrue(any(d.startswith(f'{PROBE}: {field} must be one of') for d in found), found)

    def test_vocabulary_matches_the_live_schema(self):
        """N-04: the schema-independent vocabulary cannot drift from schemas/permissions/v1."""
        c, schema = self.compat, self.schema
        permission = schema['$defs']['permission']
        props = permission['properties']
        for field, values in c.ENUMS.items():
            self.assertEqual(values, set(props[field]['enum']), field)
        self.assertEqual(set().union(*c.OWNERS.values()), set(props['owner']['enum']))
        self.assertEqual(c.ROOT_FIELDS, set(schema['properties']))
        self.assertEqual(c.ROOT_FIELDS, set(schema['required']))
        self.assertEqual(c.ENTRY_FIELDS, set(permission['required']))
        self.assertEqual(c.ENTRY_FIELDS | {'retired_in'}, set(props))
        self.assertEqual(schema['properties']['revision']['maximum'], c.MAX_REVISION)
        self.assertEqual(props['introduced']['maximum'], c.MAX_REVISION)
        self.assertEqual(props['retired_in']['maximum'], c.MAX_REVISION)
        self.assertEqual(schema['properties']['permissions']['maxItems'], c.MAX_ENTRIES)
        name = schema['$defs']['name']
        self.assertEqual((name['minLength'], name['maxLength']), c.NAME_LENGTH)
        anchored = '^' + c.NAME.pattern.removesuffix(r'\Z') + r'$(?![\s\S])'
        self.assertEqual(name['pattern'], anchored)
        uses = props['uses']
        self.assertEqual((uses['minItems'], uses['maxItems'], uses['items']['maxLength']), c.USES)
        for field, limit in c.TEXT_BYTES.items():
            self.assertEqual(props[field]['maxLength'], limit, field)
        printable = '^' + c.PRINTABLE.pattern.removesuffix(r'\Z') + r'$(?![\s\S])'
        for spec in (uses['items'], props['source'], props['note']):
            self.assertEqual(spec['pattern'], printable)
        rules, owners, grants, namespaces = {}, {}, {}, None
        conditional = None
        for clause in permission['allOf']:
            cond = clause.get('if', {}).get('properties', {})
            then = clause.get('then', {}).get('properties', {})
            if 'rule' in cond and 'const' in cond['rule']:
                rules[cond['rule']['const']] = (then['protection']['const'], then['approval']['const'])
            elif 'rule' in cond:
                conditional = (set(cond['rule']['not']['enum']), (then['protection']['const'], then['approval']['const']))
            elif 'name' in cond and 'pattern' in cond['name']:
                owners[cond['name']['pattern'].removeprefix('^').removesuffix(r'\.')] = set(then['owner']['enum'])
            elif 'name' in cond and 'const' in cond['name']:
                node = clause
                while 'if' in node:
                    grants[node['if']['properties']['name']['const']] = node['then']['properties']['grant']['const']
                    node = node['else']
                self.assertEqual(node['properties']['grant']['const'], 'role')
            elif 'name' in clause.get('properties', {}):
                namespaces = clause['properties']['name']['pattern'].split(')', 1)[0].removeprefix('^(').split('|')
        self.assertEqual(c.GRANTS, grants)
        self.assertEqual(c.OWNERS, owners)
        self.assertEqual(set(c.OWNERS), set(namespaces))
        self.assertEqual(conditional[0], set(rules))
        rules.update({rule: conditional[1] for rule in set(props['rule']['enum']) - conditional[0]})
        self.assertEqual(c.RULES, rules)

    def test_catalogue_path_object_modes(self):
        """R-02/R-06/R-08: index modes come from Git plumbing, not host filesystem features."""
        blob = self.git('rev-parse', self.base + ':' + CATALOGUE)
        executable = self.commit_mode('100755', oid=blob)
        self.assertTrue(self.compare(self.base, executable)['unchanged'])
        linked = self.commit_mode('120000', data=b'../../../' + EMBEDDED.encode())
        self.reject(self.base, linked, CATALOGUE, 'must be a regular file blob')
        self.reject(linked, executable, 'must be a regular file blob')
        gitlink = self.commit_mode('160000', oid=self.base)
        self.reject(self.base, gitlink, 'must be a regular file blob')
        (self.root / CATALOGUE).unlink()
        (self.root / CATALOGUE).mkdir()
        (self.root / CATALOGUE / 'inner.json').write_bytes(self.catalogue_bytes)
        tree = self.commit()
        self.assertTrue(self.git('ls-tree', tree, '--', CATALOGUE).startswith('040000 tree'))
        self.reject(self.base, tree, 'must be a regular file blob')
        shutil.rmtree(self.root / CATALOGUE)
        self.commit(self.changed(lambda cat: None))
        schema_link = self.commit_mode('120000', oid=self.git('rev-parse', self.base + ':' + SCHEMA), path=SCHEMA)
        self.reject(self.base, schema_link, SCHEMA, 'must be a regular file blob')

    def run_cli(self, env, base, candidate):
        full_env = dict(os.environ, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', **env)
        return subprocess.run([sys.executable, '-B', str(Path(self.compat.__file__)), '--root', '.',
                               '--base-sha', base, '--candidate-sha', candidate],
                              cwd=self.root, env=full_env, capture_output=True, text=True)

    def test_cli_binds_push_event_and_rejects_substitution(self):
        middle = self.commit(self.changed(lambda cat: None))
        head = self.commit(self.changed(lambda cat: None, revision=self.rc + 1))
        event = self.root / 'event.json'
        event.write_text(json.dumps({'ref': 'refs/heads/master', 'before': self.base, 'after': head}))
        env = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_EVENT_PATH': str(event), 'GITHUB_SHA': head}
        run = self.run_cli(env, self.base, head)
        self.assertEqual(run.returncode, 0, run.stderr)
        for value in (self.base, head, str(self.rb), str(self.rc + 1), self.git('rev-parse', head + ':' + CATALOGUE),
                      self.git('rev-parse', head + ':' + SCHEMA)):
            self.assertIn(value, run.stdout)
        # A valid ancestor substituted for the event base is still rejected.
        for base, candidate in ((middle, head), (self.base, middle), (head, head)):
            with self.subTest(base=base, candidate=candidate):
                run = self.run_cli(env, base, candidate)
                self.assertNotEqual(run.returncode, 0)
                self.assertIn('substitut', run.stderr)
        run = self.run_cli(dict(env, GITHUB_EVENT_NAME='workflow_dispatch'), self.base, head)
        self.assertNotEqual(run.returncode, 0)
        run = self.run_cli(env, 'HEAD', head)
        self.assertNotEqual(run.returncode, 0)
        run = self.run_cli({k: v for k, v in env.items() if k != 'GITHUB_EVENT_PATH'}, self.base, head)
        self.assertEqual(run.returncode, 1)
        self.assertIn('catalogue compatibility failed', run.stderr)
        self.assertNotIn('Traceback', run.stderr)
        probe_head = self.commit(self.changed(lambda cat: entry(cat, PROBE).update(scope=self.other_scope), revision=self.rb))
        event.write_text(json.dumps({'ref': 'refs/heads/master', 'before': self.base, 'after': probe_head}))
        run = self.run_cli(dict(env, GITHUB_SHA=probe_head), self.base, probe_head)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn(PROBE + ': scope changed from', run.stderr)
        self.assertIn(self.base, run.stdout)
        # R-04: invalid candidate schema and deep nesting fail cleanly with the base already logged.
        for label, catalogue, schema in (('bad schema', self.changed(lambda cat: None), b'{"type": 5}\n'),
                                         ('bad regex', self.changed(lambda cat: None), b'{"type": "object", "patternProperties": {"(unclosed": {}}}\n'),
                                         ('deep nesting', b'[' * 100000, self.schema_bytes)):
            with self.subTest(clean_failure=label):
                bad = self.commit(catalogue, schema=schema)
                event.write_text(json.dumps({'ref': 'refs/heads/master', 'before': self.base, 'after': bad}))
                run = self.run_cli(dict(env, GITHUB_SHA=bad), self.base, bad)
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertIn('catalogue compatibility failed', run.stderr)
                self.assertNotIn('Traceback', run.stderr)
                self.assertIn(self.base, run.stdout)

    def test_cli_pull_request_uses_event_base_not_merge_base(self):
        self.git('checkout', '-q', '-b', 'fork')
        head = self.commit(self.changed(lambda cat: None))
        self.git('checkout', '-q', 'master')
        self.write('docs/other.md', b'master moved\n')
        base = self.commit()
        self.git('merge', '-q', '--no-ff', 'fork', '-m', 'Integration')
        tested = self.git('rev-parse', 'HEAD')
        event = self.root / 'event.json'
        event.write_text(json.dumps({'pull_request': {'base': {'sha': base, 'ref': 'master'}, 'head': {'sha': head}}}))
        env = {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_EVENT_PATH': str(event), 'GITHUB_SHA': tested}
        run = self.run_cli(env, base, tested)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(base, run.stdout)
        self.assertIn(tested, run.stdout)
        merge_base = self.git('merge-base', base, head)
        self.assertEqual(merge_base, self.base)
        for substitute in ((merge_base, tested), (base, head), (head, tested)):
            with self.subTest(substitute=substitute):
                run = self.run_cli(env, *substitute)
                self.assertNotEqual(run.returncode, 0)
                self.assertIn('substitut', run.stderr)

    def test_design_workflow_wires_the_blocking_check(self):
        data = yaml.load((ROOT / '.github/workflows/design.yml').read_text(), Loader=yaml.BaseLoader)
        steps = data['jobs']['validate']['steps']
        checkout = next(s for s in steps if s.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout['with'].get('fetch-depth'), '0')
        step = next(s for s in steps if s.get('run') == COMMAND)
        self.assertEqual(step.get('env'), {'BASE_SHA': '${{ fromJSON(inputs.route).baseSha }}',
                                           'CANDIDATE_SHA': '${{ fromJSON(inputs.route).testedSha }}'})
        self.assertEqual(step.get('shell'), 'bash --noprofile --norc -p -e -o pipefail {0}')
        self.assertEqual(step.get('working-directory'), '.')
        self.assertNotIn('if', step)
        self.assertNotIn('continue-on-error', step)
        self.assertIn(COMMAND, inventory.DESIGN_COMMANDS)
        self.assertIn('catalogue-compat', inventory.checks('design'))
        proof = next(s for s in steps if s.get('id') == 'proof')
        self.assertIn('catalogue-compat', json.loads(proof['env']['CHECKS']))
        self.assertEqual(check_policy.check(ROOT), [])
        with tempfile.TemporaryDirectory(prefix='ci-compat-policy-') as tmp:
            root = Path(tmp)
            shutil.copytree(ROOT / '.github', root / '.github')
            shutil.copytree(ROOT / 'scripts/ci', root / 'scripts/ci')
            shutil.copytree(ROOT / 'schemas/ci', root / 'schemas/ci')
            path = root / '.github/workflows/design.yml'
            for mutation in ('remove', 'conditional', 'tolerated'):
                with self.subTest(mutation=mutation):
                    mutated = copy.deepcopy(data)
                    mutated_steps = mutated['jobs']['validate']['steps']
                    target = next(s for s in mutated_steps if s.get('run') == COMMAND)
                    if mutation == 'remove': mutated_steps.remove(target)
                    elif mutation == 'conditional': target['if'] = 'false'
                    else: target['continue-on-error'] = 'true'
                    path.write_text(yaml.safe_dump(mutated, sort_keys=False))
                    errors = check_policy.check(root)
                    self.assertTrue(any('catalogue_compat' in error for error in errors), errors)


if __name__ == '__main__': unittest.main()

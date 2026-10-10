# Report template

The format of `ReportTemplate`, the declarative resource behind console reports, scheduled reports, dashboard panels and the extension `content` format `report`. The console side (rendering, export, dashboards) is in `../design/console.md` section 5.10. Required machine-readable schema: `schemas/report/v1alpha1/report-template.json` (JSON Schema 2020-12), absent. Complete the schema and catalogue contracts in `../analysis.md` section 3 before implementing report validation, generated types or report-content extensions. Decision: BE-11.

A template names data, never code: no SQL, no scripts, no expressions beyond the filter operators below, and no markup. The server resolves every dataset through the report API's source catalogue under the authority of the operator who runs it, so a template never reads more than that operator can read through `/api/v1`.

## 1. Resource

```yaml
apiVersion: ricevanta.io/v1alpha1
kind: ReportTemplate
metadata:
  name: dlp-findings-by-category
  description: DLP findings grouped by classification category and channel
spec:
  title: { en: DLP findings by category, vi: Phát hiện DLP theo nhóm dữ liệu }
  parameters:
    - { name: period, type: time_range, default: last_30d }
    - { name: groups, type: device_groups, default: all }
    - { name: severities, type: enum_list, field: dlp.findings/severity, default: [high, critical] }
  datasets:
    - name: totals
      source: dlp.findings
      filter:
        time: { param: period }
        device_groups: { param: groups }
      measures:
        - { name: findings, fn: count }
        - { name: devices, fn: count_distinct, field: device_uid }
    - name: by_category
      source: dlp.findings
      filter:
        time: { param: period }
        device_groups: { param: groups }
        severity: { in: { param: severities } }
      group_by: [classification, channel]
      measures:
        - { name: findings, fn: count }
      order_by: [ { field: findings, desc: true } ]
      limit: 100
  layout:
    - { type: kpi, dataset: totals, measure: findings, label: { en: Findings, vi: Phát hiện } }
    - { type: kpi, dataset: totals, measure: devices, label: { en: Devices, vi: Thiết bị } }
    - { type: chart, chart: bar, dataset: by_category, x: classification, y: findings }
    - { type: table, dataset: by_category, columns: [classification, channel, findings] }
    - { type: text, text: { en: Counts include monitor-mode decisions., vi: Số liệu gồm cả quyết định ở chế độ giám sát. } }
```

## 2. Fields

| Field | Rule |
|---|---|
| `metadata.name` | DNS-1123 label, unique per organization; first-party templates use the `rv-` prefix |
| `spec.title`, `label`, `text` | Localized string: a map from BCP 47 language tag to plain text, `en` required; the console shows the operator's locale and falls back to `en`. Text renders as text, never as HTML |
| `spec.parameters[]` | `name`, `type`, optional `default`. Types: `time_range` (absolute start and end, or one of `last_24h`, `last_7d`, `last_30d`, `last_90d`, `this_month`, `previous_month`), `device_groups` (`all` or a list of group names), `enum_list` (values of the named catalogue field), `string` (at most 256 characters, usable only in `eq` and `prefix` filters) |
| `spec.datasets[]` | At most 10. `name`, `source` (catalogue id), `filter`, optional `group_by` (at most 3 groupable fields), `measures` (1 to 8), `order_by`, `limit` (default 100, at most 10,000 rows) |
| `filter` | A map from catalogue field to one operator: a literal or `{param: <name>}` for equality, or one of `in`, `not_in`, `gte`, `lte`, `between`, `prefix`, `exists`. Every operand is a literal or a parameter reference. `time` and `device_groups` are reserved keys that every source accepts |
| `measures[]` | `name`, `fn` (`count`, `count_distinct`, `sum`, `min`, `max`, `avg`, `p50`, `p95`), and `field` where `fn` needs one; the catalogue declares which functions each field admits |
| `spec.layout[]` | Ordered blocks: `heading` (`text`), `text` (`text`), `kpi` (`dataset`, `measure`, `label`), `chart` (`chart` one of `bar`, `stacked_bar`, `line`, `area`, `pie`, `heatmap`; `dataset`, `x`, `y`, optional `series`), `table` (`dataset`, `columns`) |
| Size | At most 64 KiB per template |

## 3. Source catalogue

The report API publishes one catalogue entry per source: its id, the read permission it requires, its time field, and per field the type, whether it is filterable or groupable, and the measure functions it admits. Each owning server module (BE-04) exposes its sources through a Go interface that both describes the fields and executes a dataset request under the given operator scope; `events` validates, orchestrates and stores runs and never queries another module's schema. The `getReportCatalogue` operation serves the merged catalogue, and `schemas/report/v1alpha1/catalogue.json` is the required snapshot for offline validation in `ricevanta apply`. That catalogue file is absent. Define its typed fields and permissions with validation fixtures before implementing offline validation. The source ids every v1.0.0 server serves:

| Source | Owner module | Content |
|---|---|---|
| `devices`, `devices.software` | `devices`, `mdm` | Device records, lifecycle state, OS, ownership; installed software |
| `mdm.compliance` | `mdm` | Baseline and compliance results per device and item |
| `edr.alerts`, `edr.response_actions` | `detection` | Alerts with rule, ATT&CK technique and status; response actions and outcomes |
| `dlp.findings` | `dlp` | Decisions with channel, action, classification and the category `reference` (DLP-03); never snippets |
| `lineage.edges` | `lineage` | Edge counts by type, confidence band, and observed or inferred |
| `pki.certificates` | `pki` | Certificates by profile, issuer, status and expiry |
| `radius.authentications` | `radius` | Accepts and rejects by gateway, profile and reason |
| `agents.versions`, `agents.health` | `devices`, `events` | Agent and component versions and update state; footprint against budget (AG-09) |
| `audit.events` | `audit` | Administrative actions by actor, action and result |

A dataset that names an unknown source, field, operator or measure fails validation. A source added in a later release extends the catalogue additively within `v1alpha1`.

## 4. Execution

- Running a template requires the `events.reports.run` permission and the read permission of every source it names. The server applies the operator's device-group scope (BE-02) to every dataset, so two operators running one template see results bounded by their own rights, and a run records each source read permission, the resolved immutable device and other entity uids its result covers, and any required organization-wide scope as its authorization footprint. Device-group names alone do not describe a historical result after membership changes.
- A run sends each dataset to its source's owning module through the interface of section 3, with the operator's scope, a 60-second timeout and the row limit; the module reads PostgreSQL or the raw store as the source declares. `events` stores the result rows, the resolved parameters, the template digest and the operator as a report run in the blob store (`../design/backend.md` section 5). The console renders runs, never templates without a run.
- Every reader, including the runner, must be enabled, hold every current source read permission the run required and have current effective scope covering its recorded authorization footprint. The source owners check current entity access through their interfaces before `listReportRuns` returns even run metadata, before `getReportRun` returns rows, and before any dataset download, export or dashboard cache is served. A permission loss, scope narrowing or entity move outside that scope refuses the whole stored result; the caller can create a newly scoped run. Schedule ownership, a notification link and a prior successful run grant no later read authority.
- Report-result blobs stay in a private server-only prefix. Downloads stream through an authenticated API that applies the same current check to each request, including ranges and retries; no public object URL or reusable storage bearer link bypasses it. Authorization caches key on operator, current permission/scope version and run footprint digest, and the API refuses a stale cache entry. The console discards its cached run on a session or permission change. Already delivered copies remain in the reader's custody.
- A schedule (`createReportSchedule`) names a template, parameter values, a cron expression in UTC and notifier connectors (`../design/extensions.md` section 6.1). `jobs` executes it as the schedule's operator, with that operator's current permissions at each run; when that operator is disabled or loses a source permission, the run fails with an audit event and the schedule pauses. When a different operator edits a schedule's template, parameters, cron expression or notifiers (`updateReportSchedule`), the schedule runs as the editor from then on, and the edit is audited. Notifiers receive a link to the run, never its rows.
- Report runs are kept for 90 days by default, configurable per server.

## 5. Delivery and validation

Templates arrive through the console, `/api/v1`, GitOps (one resource per file under `reports/` in the directory of `policy-envelope.md` section 8) and extensions whose `content` component declares the format `report` (`../design/extensions.md` section 3.1). Every path validates against the JSON Schema and then against the catalogue, with the same validator. The schema and typed catalogue with per-source permission, fields, operators and measure constraints must exist with positive and negative fixtures before implementing these delivery paths. First-party templates ship with the server under the `rv-` prefix and are read-only; operators copy them to change them. Schedules are API objects, not GitOps resources, because each carries an operator identity.

## 6. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: a template can be shared, reviewed and shipped in an extension without granting code execution; execution is bounded by the runner's permissions, and later reads check each reader's current rights against the stored footprint; one format serves reports, schedules and dashboard panels.

Trade-offs: immutable authorization footprints add metadata, and scope changes require a new run when the old result cannot be read in full; declarative datasets cannot join across sources; a report that needs a join places two datasets side by side, or the owning module adds a source.

Dependencies: JSON Schema 2020-12 and the server validator selected for the policy envelope (`../design/backend.md` section 2); notifier connectors for delivery.

Limits: 10 datasets per template, 10,000 rows per dataset and a 60-second timeout per dataset; PDF output is the browser's print of the console view (`../design/console.md` section 5.10).

Alternatives considered: SQL in templates, as in Metabase native questions (rejected: it bypasses module schema ownership, BE-04, and the operator's device-group scope); Go `text/template` or JavaScript in templates (rejected: code execution in the server or the console from content an extension can ship); embedding Grafana for reporting (rejected: a second service with its own authentication, against the minimal-infrastructure rule of blueprint section 5); server-side PDF rendering (not chosen: a headless browser or a PDF layout library in the server binary for output the browser's print already produces).

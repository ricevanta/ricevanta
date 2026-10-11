"""Check Task 1 workflow triggers, cancellation and the server race split."""

from copy import deepcopy
from fnmatch import fnmatchcase
from pathlib import Path
import re
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ("design", "server", "agent", "console")
PR_TYPES = {"opened", "synchronize", "reopened", "ready_for_review", "edited"}
PR_CANCEL = "${{ github.event_name == 'pull_request' }}"
RACE_COMMAND = "go test -race -count=1 ./..."


def load_workflow(path):
    # BaseLoader keeps GitHub's unquoted `on` key and scalar expressions intact.
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def concurrency_errors(name, workflow):
    """Require PR-only cancellation and unique groups for master work."""
    scopes = [(name, workflow["concurrency"])]
    errors = []
    for job_id, job in workflow.get("jobs", {}).items():
        if "concurrency" not in job:
            continue
        prefix = name + "-" + job_id
        # Reject all matrix job concurrency rather than infer row identities
        # from static, include-only or dynamically generated matrices.
        if "matrix" in job.get("strategy", {}):
            errors.append("matrix job concurrency is forbidden: " + prefix)
        scopes.append((prefix, job["concurrency"]))
    for prefix, concurrency in scopes:
        expected = (prefix + "-${{ github.event_name }}-"
                    "${{ github.event.pull_request.number || github.run_id }}")
        if (not isinstance(concurrency, dict)
                or concurrency.get("group") != expected
                or concurrency.get("cancel-in-progress") != PR_CANCEL):
            errors.append("unsafe concurrency: " + prefix)
    return errors


def uses_secrets(value):
    """Reject secrets tokens conservatively, including whole-object references."""
    if isinstance(value, dict):
        return any(uses_secrets(key) or uses_secrets(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return any(uses_secrets(item) for item in value)
    return isinstance(value, str) and bool(re.search(r"\bsecrets\b", value, re.IGNORECASE))


def diagnosis_errors(path, workflow, *, landing):
    """Check only the temporary diagnosis exception, never normal CI admission."""
    errors = []
    if landing:
        errors.append("remove diagnosis workflow before landing to master")
    if not re.fullmatch(r"diagnose-[a-z0-9-]+\.yml", path.name):
        errors.append("diagnosis filename must identify the slice")
    events = workflow.get("on", {})
    if set(events) != {"push"}:
        errors.append("diagnosis must use push only")
    push = events.get("push", {})
    if any(selector in push for selector in ("tags", "tags-ignore", "branches-ignore")):
        errors.append("diagnosis must not use tag or branch exclusion selectors")
    branches = push.get("branches", [])
    if (len(branches) != 1 or not branches[0].startswith("wip/")
            or not branches[0][4:] or any(c in branches[0] for c in "*?[]!+{}")):
        errors.append("diagnosis must target one exact wip branch")
    if workflow.get("permissions") != {"contents": "read"}:
        errors.append("diagnosis must use read-only permissions")
    for job_id, job in workflow.get("jobs", {}).items():
        if not job_id.startswith("diagnose-") or not job.get("name", "").startswith("Diagnose "):
            errors.append("diagnosis jobs must have distinct names")
        if "permissions" in job and job["permissions"] != {"contents": "read"}:
            errors.append("diagnosis job must use read-only permissions")
    if uses_secrets(workflow):
        errors.append("diagnosis must not use secrets")
    if "ci-required" in str(workflow):
        errors.append("diagnosis must not claim the required check")
    return errors


class TriggerTests(unittest.TestCase):
    def test_normal_events_are_pr_and_master_push_only(self):
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                events = load_workflow(ROOT / f".github/workflows/{name}.yml")["on"]
                self.assertEqual(set(events), {"push", "pull_request"})
                self.assertEqual(events["push"]["branches"], ["master"])
                self.assertEqual(events["pull_request"]["branches"], ["master"])
                self.assertEqual(set(events["pull_request"]["types"]), PR_TYPES)
                self.assertNotIn("branches-ignore", events["push"])
                self.assertNotIn("tags", events["push"])
                self.assertNotIn("tags-ignore", events["push"])
                self.assertNotIn("branches-ignore", events["pull_request"])

    def test_design_runs_for_each_unwatched_path_only_change(self):
        workflow = load_workflow(ROOT / ".github/workflows/design.yml")
        for event in ("pull_request", "push"):
            for changed_path in ("LICENSE", "DCO", ".gitignore",
                                 ".github/workflows/server.yml",
                                 ".github/workflows/agent.yml",
                                 ".github/workflows/console.yml"):
                with self.subTest(event=event, changed_path=changed_path):
                    trigger = workflow["on"][event]
                    self.assertTrue(any(fnmatchcase(changed_path, pattern)
                                        for pattern in trigger.get("paths", ["**"])))
                    self.assertNotIn("paths", trigger)
                    self.assertNotIn("paths-ignore", trigger)
        self.assertNotIn("if", workflow["jobs"]["validate"])
        for step in workflow["jobs"]["validate"]["steps"]:
            self.assertNotIn("if", step)

    def test_job_concurrency_cannot_cancel_master_work(self):
        for name in WORKFLOWS:
            workflow = load_workflow(ROOT / f".github/workflows/{name}.yml")
            with self.subTest(workflow=name):
                self.assertEqual(concurrency_errors(name, workflow), [])
        workflow = load_workflow(ROOT / ".github/workflows/server.yml")
        safe = deepcopy(workflow)
        safe["jobs"]["race"]["concurrency"] = {
            "group": "server-race-${{ github.event_name }}-"
                     "${{ github.event.pull_request.number || github.run_id }}",
            "cancel-in-progress": PR_CANCEL,
        }
        self.assertEqual(concurrency_errors("server", safe), [])
        for concurrency in (
                {"group": "server-race-all-events", "cancel-in-progress": "true"},
                {"group": "server-race-all-events", "cancel-in-progress": "false"},
                {"group": "server-race-${{ github.ref }}", "cancel-in-progress": PR_CANCEL},
                "server-race-all-events"):
            with self.subTest(concurrency=concurrency):
                mutated = deepcopy(workflow)
                mutated["jobs"]["race"]["concurrency"] = concurrency
                self.assertTrue(concurrency_errors("server", mutated))

    def test_matrix_jobs_reject_job_concurrency(self):
        workflow = load_workflow(ROOT / ".github/workflows/server.yml")
        native_rows = workflow["jobs"]["loader-gate-a"]["strategy"]["matrix"]["os"]
        self.assertEqual(native_rows, ["ubuntu-24.04", "windows-2025", "macos-15"])
        matrices = (
            {"os": native_rows},
            {"include": [{"os": os, "arch": arch} for os, arch in
                         zip(native_rows, ("x64", "x64", "arm64"))]},
            {"os": native_rows, "mode": ["unit", "race"]},
            "${{ fromJSON(needs.route.outputs.matrix) }}",
        )
        for matrix in matrices:
            with self.subTest(matrix=matrix):
                mutated = deepcopy(workflow)
                job = mutated["jobs"]["loader-gate-a"]
                job["strategy"]["matrix"] = matrix
                # The same master run ID gives every native row this group.
                job["concurrency"] = {
                    "group": "server-loader-gate-a-${{ github.event_name }}-"
                             "${{ github.event.pull_request.number || github.run_id }}",
                    "cancel-in-progress": PR_CANCEL,
                }
                self.assertTrue(concurrency_errors("server", mutated))

    def test_normal_pushes_target_only_master(self):
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                events = load_workflow(ROOT / f".github/workflows/{name}.yml")["on"]
                self.assertEqual(events["push"]["branches"], ["master"])

    def test_master_runs_are_never_cancelled(self):
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                concurrency = load_workflow(ROOT / f".github/workflows/{name}.yml")["concurrency"]
                self.assertEqual(concurrency["cancel-in-progress"], PR_CANCEL)

    def test_only_same_pr_runs_share_a_cancelling_group(self):
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                concurrency = load_workflow(ROOT / f".github/workflows/{name}.yml")["concurrency"]
                self.assertEqual(concurrency["group"],
                                 name + "-${{ github.event_name }}-"
                                 "${{ github.event.pull_request.number || github.run_id }}")
                self.assertEqual(concurrency["cancel-in-progress"], PR_CANCEL)

    def test_server_race_is_an_independent_job(self):
        jobs = load_workflow(ROOT / ".github/workflows/server.yml")["jobs"]
        self.assertIn("validate", jobs)
        self.assertIn("race", set(jobs))
        validate, race = jobs["validate"], jobs["race"]
        self.assertEqual(validate["timeout-minutes"], "20")
        self.assertEqual(race["timeout-minutes"], "20")
        self.assertNotIn("needs", race)
        self.assertNotIn("if", race)
        self.assertNotIn("continue-on-error", race)
        self.assertEqual(race["runs-on"], "ubuntu-24.04")
        self.assertEqual(race["defaults"]["run"]["working-directory"], "server")
        race_runs = [step.get("run", "") for step in race["steps"]]
        self.assertEqual(race_runs.count(RACE_COMMAND), 1)
        for step in race["steps"]:
            self.assertNotIn("if", step)
            self.assertNotIn("continue-on-error", step)
        validate_runs = [step.get("run", "") for step in validate["steps"]]
        self.assertFalse(any("-race" in run for run in validate_runs))
        for command in ("go test -count=1 ./...", "go vet ./...",
                        "go test -run '^$' -bench '^BenchmarkValidate$' "
                        "-benchmem -benchtime=100x ./internal/signing/ed25519key"):
            self.assertIn(command, validate_runs)
        self.assertTrue(any("gofmt -l ." in run for run in validate_runs))
        self.assertTrue(any(step.get("uses", "").startswith("actions/setup-go@")
                            for step in race["steps"]))

    def test_workflows_keep_read_only_tokens_and_pinned_checkouts(self):
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                workflow = load_workflow(ROOT / f".github/workflows/{name}.yml")
                self.assertEqual(workflow["permissions"], {"contents": "read"})
                for job in workflow["jobs"].values():
                    if "permissions" in job:
                        self.assertEqual(job["permissions"], {"contents": "read"})
                    for step in job.get("steps", []):
                        action = step.get("uses", "")
                        if action and not action.startswith("./"):
                            self.assertRegex(action, r"@[0-9a-f]{40}$")
                        if action.startswith("actions/checkout@"):
                            self.assertEqual(step["with"]["persist-credentials"], "false")


class DiagnosisExceptionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ci-diagnosis-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "diagnose-ci-triggers.yml"
        self.path.write_text("""name: Diagnose CI triggers
on:
  push:
    branches: [wip/ci-triggers]
permissions:
  contents: read
jobs:
  diagnose-ci-triggers:
    name: Diagnose CI triggers
    runs-on: ubuntu-24.04
    steps:
      - run: echo synthetic diagnosis
""", encoding="utf-8")
        self.workflow = load_workflow(self.path)

    def test_temporary_exact_branch_diagnosis_is_allowed(self):
        self.assertEqual(diagnosis_errors(self.path, self.workflow, landing=False), [])

    def test_diagnosis_is_rejected_for_landing(self):
        self.assertIn("remove diagnosis workflow before landing to master",
                      diagnosis_errors(self.path, self.workflow, landing=True))

    def test_diagnosis_cannot_widen_the_exception(self):
        mutations = []
        for branches in (["wip/**"], ["master"], ["wip/a", "wip/b"]):
            workflow = deepcopy(self.workflow)
            workflow["on"]["push"]["branches"] = branches
            mutations.append(workflow)
        for key, value in (("permissions", {"contents": "write"}),
                           ("name", "ci-required")):
            workflow = deepcopy(self.workflow)
            workflow[key] = value
            mutations.append(workflow)
        workflow = deepcopy(self.workflow)
        workflow["jobs"]["diagnose-ci-triggers"]["secrets"] = "inherit"
        mutations.append(workflow)
        for index, workflow in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertTrue(diagnosis_errors(self.path, workflow, landing=False))

    def test_diagnosis_rejects_tag_selectors(self):
        for selector in ("tags", "tags-ignore", "branches-ignore"):
            with self.subTest(selector=selector):
                workflow = deepcopy(self.workflow)
                workflow["on"]["push"][selector] = ["**"]
                self.assertTrue(diagnosis_errors(self.path, workflow, landing=False))

    def test_diagnosis_rejects_secrets_at_every_scope(self):
        for expression in ("${{ secrets.REVIEW_TOKEN }}",
                           "${{ secrets['REVIEW_TOKEN'] }}",
                           '${{ secrets ["REVIEW_TOKEN"] }}',
                           "${{ toJSON(secrets) }}",
                           "${{ SECRETS.REVIEW_TOKEN }}",
                           "${{ toJSON(SeCrEtS) }}",
                           "${{ SECRETS }}",
                           "${{ contains(toJSON(secrets), 'x') }}",
                           "${{ secrets == null }}",
                           "${{ false || secrets }}",
                           "${{ format('}}', toJSON(SECRETS)) }}",
                           "${{\n toJSON(Secrets)\n }}"):
            for scope in ("workflow", "job", "step"):
                with self.subTest(expression=expression, scope=scope):
                    workflow = deepcopy(self.workflow)
                    target = workflow
                    if scope == "job":
                        target = workflow["jobs"]["diagnose-ci-triggers"]
                    elif scope == "step":
                        target = workflow["jobs"]["diagnose-ci-triggers"]["steps"][0]
                    target["env"] = {"LEAK": expression}
                    self.assertTrue(diagnosis_errors(self.path, workflow, landing=False))
        workflow = deepcopy(self.workflow)
        workflow["secrets"] = "inherit"
        self.assertTrue(diagnosis_errors(self.path, workflow, landing=False))

    def test_no_diagnosis_workflow_is_left_in_the_landing_tree(self):
        self.assertEqual(list((ROOT / ".github/workflows").glob("diagnose-*.yml")), [])


if __name__ == "__main__":
    unittest.main()

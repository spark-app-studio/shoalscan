"""--policy-ref: the configuration, baseline and repository rules come from the base branch.

Needs git and the installed Opengrep (see test_end_to_end.py).
"""

import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_end_to_end import SAMPLE, TOOLS, tools_ready

from shoalscan import gitref
from shoalscan.cli import main
from shoalscan.errors import SetupError

RULE = """rules:
- id: no-pickle-loads
  pattern: pickle.loads(...)
  message: Do not unpickle untrusted data.
  languages: [python]
  severity: ERROR
  metadata:
    category: security
"""


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout


@unittest.skipUnless(shutil.which("git") and tools_ready(), "needs git and the installed Opengrep")
class PolicyRefTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.repo = base / "repo"
        shutil.copytree(SAMPLE, self.repo)
        (self.repo / ".shoalscan.toml").write_text(
            'baseline = "baseline.toml"\nexcludes = ["generated"]\n'
            '[opengrep]\ncommunity_rules = false\nrule_dirs = ["security-rules"]\n'
            "[limits]\nmax_target_bytes = 2000\njobs = 2\n",
            encoding="utf-8",
        )
        (self.repo / "security-rules").mkdir()
        (self.repo / "security-rules" / "pickle.yaml").write_text(RULE, encoding="utf-8")
        (self.repo / "src" / "load.py").write_text(
            "import pickle\n\ndef load(b):\n    return pickle.loads(b)\n", encoding="utf-8"
        )
        (self.repo / "big_unchanged.py").write_text("x = 1\n" * 600, encoding="utf-8")
        self.out = base / "out"
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")
        code, _, err = self.cli("baseline", "init", "--issue", "#1", "--reason", "initial")
        self.assertEqual(code, 0, err)
        git(self.repo, "add", "baseline.toml")
        git(self.repo, "commit", "-q", "-m", "baseline")
        git(self.repo, "checkout", "-q", "-b", "change")

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, *args: str, policy: bool = False):
        extra = ["--policy-ref", "refs/heads/main"] if policy else []
        common = ["--repo", str(self.repo), "--out", str(self.out)]
        if args[0] in ("scan", "baseline"):
            common += ["--tools-dir", str(TOOLS)]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*args, *common, *extra])
        return code, out.getvalue(), err.getvalue()

    def rename(self, old: str, new: str) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(["baseline", "rename-path", old, new, "--repo", str(self.repo)])

    def commit(self, message: str) -> None:
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", message)

    def run_policy(self):
        code, _, err = self.cli("scan", policy=True)
        self.assertEqual(code, 0, err)
        code, out, err = self.cli("check", policy=True)
        line = [x for x in out.splitlines() if x.startswith("SHOALSCAN_SUMMARY ")]
        return code, (json.loads(line[0].split(" ", 1)[1]) if line else {}), out + err

    def test_unchanged_change_passes(self):
        code, summary, out = self.run_policy()
        self.assertEqual(code, 0, out)
        self.assertEqual(summary["policy_ref"], "refs/heads/main")
        # An unchanged file over the size limit is reported, not failed.
        self.assertGreaterEqual(summary["unscanned"]["skipped"], 1)
        self.assertEqual(summary["unscanned"]["changed_and_unscanned"], 0)

    def test_change_cannot_relax_its_own_policy(self):
        # The change excludes src/, deletes the repository rule and empties the baseline.
        (self.repo / ".shoalscan.toml").write_text(
            'baseline = "baseline.toml"\nexcludes = ["src", "security-rules"]\n[opengrep]\ncommunity_rules = false\n',
            encoding="utf-8",
        )
        (self.repo / "security-rules" / "pickle.yaml").unlink()
        (self.repo / "src" / "more.py").write_text(
            "import pickle\n\ndef more(b):\n    return pickle.loads(b)\n", encoding="utf-8"
        )
        self.commit("relax")
        code, summary, out = self.run_policy()
        self.assertEqual(code, 1, out)
        self.assertIn("POLICY CHANGES", out)
        self.assertIn('-excludes = ["generated"]', out)
        # The base branch's rule still ran on the new file.
        self.assertIn("repo.security-rules.no-pickle-loads", out)
        self.assertEqual(summary["new_blocking"], 1)

    def test_baseline_may_only_shrink(self):
        entries = (self.repo / "baseline.toml").read_text(encoding="utf-8")
        (self.repo / "baseline.toml").write_text(
            entries
            + (
                '\n[[finding]]\ntool = "opengrep"\nrule = "x"\npath = "src/new.py"\nfingerprint = "f:0"\nissue = '
                '"#9"\nreason = "sneaky"\n'
            ),
            encoding="utf-8",
        )
        self.commit("add an entry")
        code, summary, out = self.run_policy()
        self.assertEqual(code, 1)
        self.assertEqual(summary["baseline_additions"], 1)
        self.assertIn("separate, reviewed change on the base branch", out)

        # Changing an entry's reason is a change too.
        git(self.repo, "checkout", "-q", "main", "--", "baseline.toml")
        (self.repo / "baseline.toml").write_text(
            entries.replace('reason = "initial"', 'reason = "edited"', 1), encoding="utf-8"
        )
        self.commit("edit an entry")
        code, summary, _ = self.run_policy()
        self.assertEqual((code, summary["baseline_additions"]), (1, 1))

    def test_fix_and_remove_entry_passes(self):
        (self.repo / "src" / "load.py").write_text(
            "import json\n\ndef load(b):\n    return json.loads(b)\n", encoding="utf-8"
        )
        text = (self.repo / "baseline.toml").read_text(encoding="utf-8")
        blocks = text.split("\n[[finding]]\n")
        kept = [b for b in blocks if "no-pickle-loads" not in b]
        (self.repo / "baseline.toml").write_text("\n[[finding]]\n".join(kept), encoding="utf-8")
        self.commit("fix")
        code, summary, out = self.run_policy()
        self.assertEqual(code, 0, out)
        self.assertEqual(summary["stale"], 0)

    def test_changed_file_that_was_not_scanned_fails(self):
        (self.repo / "src" / "huge.py").write_text("y = 2\n" * 600, encoding="utf-8")
        (self.repo / "generated").mkdir()
        (self.repo / "generated" / "huge.py").write_text("y = 2\n" * 600, encoding="utf-8")
        self.commit("big files")
        code, summary, out = self.run_policy()
        self.assertEqual(code, 1, out)
        self.assertEqual(summary["unscanned"]["changed_and_unscanned"], 1)
        self.assertIn("src/huge.py", out)
        self.assertNotIn("generated/huge.py  (", out)
        # The excluded changed file is listed loudly, but does not fail.
        self.assertIn("CHANGED BUT NOT SCANNED", out)
        self.assertIn("  generated/huge.py", out)
        self.assertEqual(summary["unscanned"]["changed_but_excluded"], 1)

    def explicit_policy(self) -> tuple[list[str], list[str]]:
        """The base branch's configuration and baseline as files outside the repository, as the scan worker passes
        them for a pull request."""
        outside = Path(self.tmp.name) / "registered"
        outside.mkdir(exist_ok=True)
        (outside / "policy.toml").write_text(git(self.repo, "show", "main:.shoalscan.toml"), encoding="utf-8")
        (outside / "baseline.toml").write_text(git(self.repo, "show", "main:baseline.toml"), encoding="utf-8")
        return ["--config", str(outside / "policy.toml")], ["--baseline", str(outside / "baseline.toml")]

    def run_explicit(self):
        config, baseline = self.explicit_policy()
        code, _, err = self.cli("scan", *config, "--rules-commit", "refs/heads/main")
        self.assertEqual(code, 0, err)
        code, out, err = self.cli("check", *config, *baseline, "--changed-since", "refs/heads/main")
        line = [x for x in out.splitlines() if x.startswith("SHOALSCAN_SUMMARY ")]
        return code, (json.loads(line[0].split(" ", 1)[1]) if line else {}), out + err

    def test_rules_commit_keeps_the_base_rules_when_the_change_deletes_them(self):
        # The change deletes the repository rule, relaxes its own policy and adds a new finding.
        (self.repo / ".shoalscan.toml").write_text(
            'baseline = "baseline.toml"\nexcludes = ["src"]\n[opengrep]\ncommunity_rules = false\n', encoding="utf-8"
        )
        (self.repo / "security-rules" / "pickle.yaml").unlink()
        (self.repo / "src" / "more.py").write_text(
            "import pickle\n\ndef more(b):\n    return pickle.loads(b)\n", encoding="utf-8"
        )
        self.commit("relax")
        code, summary, out = self.run_explicit()
        self.assertEqual(code, 1, out)
        self.assertIn("repo.security-rules.no-pickle-loads", out)
        self.assertEqual(summary["new_blocking"], 1)
        self.assertIn("compared with the merge base of HEAD and", out)
        findings = json.loads((self.out / "findings.json").read_text())
        self.assertEqual(findings["policy"]["rules_commit"], git(self.repo, "rev-parse", "main").strip())

    def test_changed_since_fails_a_changed_file_that_was_not_scanned(self):
        (self.repo / "src" / "huge.py").write_text("y = 2\n" * 600, encoding="utf-8")
        self.commit("big file")
        code, summary, out = self.run_explicit()
        self.assertEqual(code, 1, out)
        self.assertEqual(summary["unscanned"]["changed_and_unscanned"], 1)
        # Without --changed-since the same check only reports it.
        config, baseline = self.explicit_policy()
        code, out, err = self.cli("check", *config, *baseline)
        self.assertEqual(code, 0, out + err)

    def test_changed_since_fails_a_suppression_the_change_added(self):
        marker = "no" + "sem"
        (self.repo / "src" / "more.py").write_text(
            f"import pickle\n\ndef more(b):\n    return pickle.loads(b)  # {marker}: "
            "repo.security-rules.no-pickle-loads #12 trusted input\n",
            encoding="utf-8",
        )
        self.commit("silence it")
        code, summary, out = self.run_explicit()
        self.assertEqual(code, 1, out)
        self.assertEqual((summary["new_suppressions"], summary["new_blocking"]), (1, 0))
        self.assertIn("New inline suppressions on lines the change added (1)", out)
        self.assertIn("src/more.py:4", out)
        details = json.loads((self.out / "check.json").read_text())
        self.assertEqual(details["new_suppressions"][0]["path"], "src/more.py")
        # Without --changed-since (a trusted branch) a valid suppression is only counted.
        config, baseline = self.explicit_policy()
        code, out, err = self.cli("check", *config, *baseline)
        self.assertEqual(code, 0, out + err)

    def test_changed_since_fails_new_code_under_a_marker_that_was_already_there(self):
        # The base branch holds a valid marker above a harmless line; the change puts new code on that line, which
        # Opengrep then silences, though the change added no marker.
        marker = "no" + "sem"
        git(self.repo, "checkout", "-q", "main")
        (self.repo / "src" / "old.py").write_text(
            f"import pickle\n\ndef old(b):\n    # {marker}: repo.security-rules.no-pickle-loads #12 trusted\n"
            "    return b\n",
            encoding="utf-8",
        )
        self.commit("a marker on main")
        git(self.repo, "checkout", "-q", "-B", "change")
        (self.repo / "src" / "old.py").write_text(
            f"import pickle\n\ndef old(b):\n    # {marker}: repo.security-rules.no-pickle-loads #12 trusted\n"
            "    return pickle.loads(b)\n",
            encoding="utf-8",
        )
        self.commit("new code under the old marker")
        code, summary, out = self.run_explicit()
        self.assertEqual(code, 1, out)
        self.assertEqual((summary["new_suppressions"], summary["new_blocking"]), (1, 0))
        self.assertIn("src/old.py:5  (repo.security-rules.no-pickle-loads; a finding opengrep silenced)", out)
        findings = json.loads((self.out / "findings.json").read_text())
        self.assertEqual(findings["silenced_total"], len(findings["silenced_list"]))
        self.assertIn(("src/old.py", 5), [(e["path"], e["start"]) for e in findings["silenced_list"]])

    def test_silenced_findings_cannot_be_told_from_a_cut_list(self):
        from shoalscan.cli import _new_silenced

        span = {"tool": "trivy", "rule": "AVD-1", "path": "a.tf", "start": 4, "end": 9}
        with self.assertRaisesRegex(SetupError, "did not list every finding an inline comment silenced"):
            _new_silenced({"silenced_total": 2, "silenced_list": [span]}, {"a.tf"}, lambda p: {5}, [])
        with self.assertRaisesRegex(SetupError, "did not list every finding"):
            _new_silenced({}, {"a.tf"}, lambda p: {5}, [])
        meta = {"silenced_total": 1, "silenced_list": [span]}
        # Any added line inside the block counts; none, or an unchanged file, does not.
        self.assertEqual(_new_silenced(meta, {"a.tf"}, lambda p: {9}, [])[0]["line"], 4)
        self.assertEqual(_new_silenced(meta, {"a.tf"}, lambda p: {10}, []), [])
        self.assertEqual(_new_silenced(meta, set(), lambda p: {5}, []), [])
        # A new marker right above it already counts the same thing.
        self.assertEqual(_new_silenced(meta, {"a.tf"}, lambda p: {5}, [{"path": "a.tf", "line": 3}]), [])

    def test_new_suppressions_cannot_be_told_from_a_cut_list(self):
        from shoalscan.cli import _new_suppressions

        meta = {"suppressions": {"total": 3}, "suppression_list": [{"path": "a.py", "line": 1}]}
        with self.assertRaisesRegex(SetupError, "did not list every inline suppression"):
            _new_suppressions(meta, {"a.py"}, lambda path: {1})
        meta["suppressions"]["total"] = 1
        self.assertEqual(_new_suppressions(meta, {"a.py"}, lambda path: {1}), [{"path": "a.py", "line": 1}])
        self.assertEqual(_new_suppressions(meta, {"a.py"}, lambda path: {2}), [])
        self.assertEqual(_new_suppressions(meta, {"b.py"}, lambda path: {1}), [])

    def test_changed_since_reports_stale_entries_without_failing(self):
        # The change fixes the baselined finding. Its baseline is managed outside it, so it cannot remove the
        # entry: the stale entry is reported, and is no reason to fail the change.
        (self.repo / "src" / "load.py").write_text(
            "import json\n\ndef load(b):\n    return json.loads(b)\n", encoding="utf-8"
        )
        self.commit("fix")
        code, summary, out = self.run_explicit()
        self.assertEqual(code, 0, out)
        self.assertGreaterEqual(summary["stale"], 1)
        self.assertIn("They do not fail this change", out)
        config, baseline = self.explicit_policy()
        code, out, err = self.cli("check", *config, *baseline)
        self.assertEqual(code, 1, out + err)

    def test_rules_commit_needs_an_explicit_configuration(self):
        code, _, err = self.cli("scan", "--rules-commit", "refs/heads/main")
        self.assertEqual(code, 2)
        self.assertIn("--rules-commit needs --config", err)
        config, _ = self.explicit_policy()
        code, _, err = self.cli("scan", *config, "--rules-commit", "main")
        self.assertEqual(code, 2)
        self.assertIn("ambiguous", err)

    def test_a_tag_cannot_shadow_the_policy_ref(self):
        base = git(self.repo, "rev-parse", "refs/heads/main").strip()
        git(self.repo, "update-ref", "refs/remotes/origin/main", base)
        # A change commits a relaxed policy and tags it with the branch's names.
        (self.repo / ".shoalscan.toml").write_text(
            'excludes = ["src"]\n[opengrep]\ncommunity_rules = false\n', encoding="utf-8"
        )
        self.commit("relaxed")
        relaxed = git(self.repo, "rev-parse", "HEAD").strip()
        git(self.repo, "tag", "origin/main", relaxed)
        git(self.repo, "tag", "main", relaxed)
        # Plain git would pick the tag for the short names.
        self.assertEqual(git(self.repo, "rev-parse", "origin/main^{commit}").strip(), relaxed)
        for short in ("origin/main", "main", base[:12]):
            with self.subTest(ref=short), self.assertRaises(SetupError):
                gitref.resolve_commit(self.repo, short)
        self.assertEqual(gitref.resolve_commit(self.repo, "refs/remotes/origin/main"), base)
        self.assertEqual(gitref.resolve_commit(self.repo, "refs/heads/main"), base)
        self.assertEqual(gitref.resolve_commit(self.repo, base), base)
        with self.assertRaises(SetupError):
            gitref.resolve_commit(self.repo, "refs/tags/main")
        with self.assertRaises(SetupError):
            gitref.resolve_commit(self.repo, "refs/remotes/origin/absent")

    def test_check_refuses_findings_for_another_tree(self):
        code, _, err = self.cli("scan", policy=True)
        self.assertEqual(code, 0, err)
        # An uncommitted edit after the scan.
        (self.repo / "src" / "load.py").write_text("x = 1\n", encoding="utf-8")
        code, _, err = self.cli("check", policy=True)
        self.assertEqual(code, 2)
        self.assertIn("do not match the current tree", err)
        # A commit after the scan.
        self.commit("later")
        code, _, err = self.cli("check", policy=True)
        self.assertEqual(code, 2)
        # Scanning again makes them match (the check then fails only because
        # the fixed finding's baseline entry is stale).
        self.assertEqual(self.cli("scan", policy=True)[0], 0)
        code, out, err = self.cli("check", policy=True)
        self.assertEqual(code, 1, err)
        self.assertIn("Stale baseline entries (1)", out)

    def test_partial_parsing_against_added_lines(self):
        # An existing JS file, then a change that breaks a line far from the
        # one it edits, and one that breaks the line it adds.
        body = ["function f%d() { return %d; }" % (n, n) for n in range(1, 41)]
        (self.repo / "src" / "app.js").write_text("\n".join(body) + "\n", encoding="utf-8")
        self.commit("js")
        git(self.repo, "update-ref", "refs/heads/main", "HEAD")
        broken = list(body)
        broken[4] = "const y = @@@ broken ;;; <<<"
        (self.repo / "src" / "app.js").write_text("\n".join(broken) + "\n", encoding="utf-8")
        code, summary, out = self.run_policy()
        self.assertEqual(code, 1, out)
        self.assertEqual(summary["unscanned"]["changed_and_unscanned"], 1)
        self.assertIn("overlap added lines", out)

        # The gap stays where it was; the change now edits only a later line.
        self.commit("broken line")
        git(self.repo, "update-ref", "refs/heads/main", "HEAD")
        edited = list(broken)
        edited[35] = "function f36() { return 360; }"
        (self.repo / "src" / "app.js").write_text("\n".join(edited) + "\n", encoding="utf-8")
        code, summary, out = self.run_policy()
        self.assertEqual(code, 0, out)
        self.assertEqual(summary["unscanned"]["changed_partially_parsed_warnings"], 1)

    def test_parse_warn_only_comes_from_the_base_branch(self):
        docker_rule = (
            "rules:\n  - id: dockerfile-user-root\n    languages: [dockerfile]\n    severity: WARNING\n"
            "    message: the image runs as root\n    pattern: USER root\n"
        )
        (self.repo / "security-rules" / "docker.yaml").write_text(docker_rule, encoding="utf-8")
        service = self.repo / "services" / "api"
        service.mkdir(parents=True)
        good = "FROM alpine:3.20\nRUN echo ok\nRUN echo two\nUSER app\n"
        (service / "Dockerfile").write_text(good, encoding="utf-8")
        self.commit("dockerfile")
        git(self.repo, "update-ref", "refs/heads/main", "HEAD")
        # A change the experimental Dockerfile parser leaves mostly unparsed, over the added lines.
        broken = (
            "FROM alpine:3.20\nRUN echo $(( 1 + )) ; fi ; done ; esac ;; ))) {{\nRUN cat <<- 'X' | sh\n\techo [[ -n "
            '"${a:?}" ]]\nX\nRUN echo ok\nUSER app\n'
        )
        (service / "Dockerfile").write_text(broken, encoding="utf-8")
        code, summary, out = self.run_policy()
        self.assertEqual(code, 1, out)
        self.assertEqual(summary["unscanned"]["changed_and_unscanned"], 1)

        # The change cannot make its own file warn-only.
        config = (self.repo / ".shoalscan.toml").read_text(encoding="utf-8")
        (self.repo / ".shoalscan.toml").write_text('parse_warn_only = ["**/Dockerfile"]\n' + config, encoding="utf-8")
        code, summary, out = self.run_policy()
        self.assertEqual(code, 1, out)
        self.assertIn("POLICY CHANGES", out)
        self.assertEqual(summary["unscanned"].get("changed_partially_parsed_warn_only"), 0)

        # Once the base branch sets it, the same change only warns, loudly.
        (service / "Dockerfile").write_text(good, encoding="utf-8")
        self.commit("warn-only policy")
        git(self.repo, "update-ref", "refs/heads/main", "HEAD")
        (service / "Dockerfile").write_text(broken, encoding="utf-8")
        code, summary, out = self.run_policy()
        self.assertEqual(code, 0, out)
        self.assertEqual(summary["unscanned"]["changed_partially_parsed_warn_only"], 1)
        self.assertIn("PARTIALLY PARSED (warn-only by policy): services/api/Dockerfile \u2014", out)
        self.assertIn("overlaps added lines: yes", out)

        # A skipped file still fails: this one is over max_target_bytes.
        (service / "Dockerfile").write_text(good + "RUN echo padding-padding-padding\n" * 80, encoding="utf-8")
        code, summary, out = self.run_policy()
        self.assertEqual(code, 1, out)
        self.assertEqual(summary["unscanned"]["changed_and_unscanned"], 1)

    def test_a_helm_template_with_a_syntax_error_only_warns_when_listed(self):
        yaml_rule = (
            "rules:\n  - id: privileged-container\n    languages: [yaml]\n    severity: WARNING\n"
            '    message: a privileged container\n    pattern: "privileged: true"\n'
        )
        (self.repo / "security-rules" / "k8s.yaml").write_text(yaml_rule, encoding="utf-8")
        templates = self.repo / "deploy" / "chart" / "templates"
        templates.mkdir(parents=True)
        body = (
            'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ include "app.fullname" . }}\nspec:\n  {{- if '
            ".Values.replicas }}\n  replicas: {{ .Values.replicas }}\n  {{- end }}\n"
        )
        (templates / "deployment.yaml").write_text(body, encoding="utf-8")
        self.commit("chart")
        git(self.repo, "update-ref", "refs/heads/main", "HEAD")
        (templates / "deployment.yaml").write_text(body + "  minReadySeconds: 5\n", encoding="utf-8")
        code, summary, out = self.run_policy()
        self.assertEqual(code, 1, out)
        self.assertEqual(summary["unscanned"]["changed_and_unscanned"], 1)

        # The base branch lists Helm templates as warn-only: the same change now warns, loudly.
        (templates / "deployment.yaml").write_text(body, encoding="utf-8")
        config = (self.repo / ".shoalscan.toml").read_text(encoding="utf-8")
        (self.repo / ".shoalscan.toml").write_text(
            'parse_warn_only = ["deploy/**/templates/*.yaml"]\n' + config, encoding="utf-8"
        )
        self.commit("warn-only templates")
        git(self.repo, "update-ref", "refs/heads/main", "HEAD")
        (templates / "deployment.yaml").write_text(body + "  minReadySeconds: 5\n", encoding="utf-8")
        code, summary, out = self.run_policy()
        self.assertEqual(code, 0, out)
        self.assertEqual(summary["unscanned"]["changed_syntax_error_warn_only"], 1)
        self.assertIn("SYNTAX ERROR (warn-only by policy): deploy/chart/templates/deployment.yaml", out)

    def test_python_syntax_error_without_error_entry_is_fine(self):
        (self.repo / "src" / "broken.py").write_text("def f(:\n    return 1\n", encoding="utf-8")
        self.commit("broken python")
        code, summary, out = self.run_policy()
        self.assertEqual((code, summary["unscanned"]["changed_and_unscanned"]), (0, 0), out)

    def test_pure_move_with_rename_path_passes(self):
        git(self.repo, "mv", "src/load.py", "src/loader.py")
        self.assertEqual(self.rename("src/load.py", "src/loader.py"), 0)
        self.commit("move")
        code, summary, out = self.run_policy()
        self.assertEqual(code, 0, out)
        self.assertEqual((summary["baseline_moves"], summary["baseline_additions"]), (1, 0))
        self.assertIn("BASELINE MOVES", out)

    def test_move_with_an_edited_entry_fails(self):
        git(self.repo, "mv", "src/load.py", "src/loader.py")
        self.rename("src/load.py", "src/loader.py")
        text = (self.repo / "baseline.toml").read_text(encoding="utf-8")
        (self.repo / "baseline.toml").write_text(
            text.replace('reason = "initial"', 'reason = "moved"'), encoding="utf-8"
        )
        self.commit("move and edit")
        code, summary, _ = self.run_policy()
        self.assertEqual(code, 1)
        self.assertEqual(summary["baseline_moves"], 0)
        self.assertGreater(summary["baseline_additions"], 0)

    def test_scan_and_check_must_use_the_same_policy(self):
        code, _, err = self.cli("scan")
        self.assertEqual(code, 0, err)
        code, _, err = self.cli("check", policy=True)
        self.assertEqual(code, 2)
        self.assertIn("different policy", err)


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(shutil.which("git") and tools_ready(), "needs git and the installed Opengrep")
class AdoptionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.repo = base / "repo"
        self.out = base / "out"
        shutil.copytree(SAMPLE, self.repo)
        (self.repo / ".shoalscan.toml").unlink()
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "before shoalscan")
        git(self.repo, "checkout", "-q", "-b", "adopt")

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(
                [*args, "--repo", str(self.repo), "--out", str(self.out), "--policy-ref", "refs/heads/main"]
                + (["--tools-dir", str(TOOLS)] if args[0] == "scan" else [])
            )
        return code, out.getvalue() + err.getvalue()

    def write_policy(self, config=True, baseline=True):
        if config:
            (self.repo / ".shoalscan.toml").write_text(
                'baseline = "baseline.toml"\n[opengrep]\ncommunity_rules = false\n', encoding="utf-8"
            )
        if baseline:
            (self.repo / "baseline.toml").write_text("version = 1\n", encoding="utf-8")

    def test_first_adoption_uses_the_change_policy_loudly(self):
        self.write_policy()
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "adopt")
        code, out = self.cli("scan")
        self.assertEqual(code, 0, out)
        self.assertIn("ADOPTION", out)
        code, out = self.cli("check")
        self.assertIn("ADOPTION", out)
        # ERROR findings still block.
        self.assertEqual(code, 1, out)
        self.assertIn('"adoption":true', out)

    def test_config_without_baseline_on_the_base_is_refused(self):
        self.write_policy(baseline=False)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "config only")
        git(self.repo, "update-ref", "refs/heads/main", "HEAD")
        code, out = self.cli("scan")
        self.assertEqual(code, 2)
        self.assertIn("but not both", out)

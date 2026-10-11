"""The SARIF file: Opengrep's results with repository-relative paths and fingerprints, and no copies of the code."""

import json
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401 - puts src/ on the import path

from shoalscan.sarif import FINGERPRINT_KEY, build_sarif, rewrite_opengrep_sarif

SECRET_LINE = 'token = "ghp_' + 'R2xq7Wd9TbKz4LmN8pQs3VhY6cJf1aEu5oGi"'


def opengrep_sarif(root: Path) -> dict:
    region = {"startLine": 3, "startColumn": 9, "snippet": {"text": SECRET_LINE}}
    location = {
        "physicalLocation": {
            "artifactLocation": {"uri": f"file://{root}/src/app.py"},
            "region": region,
            "contextRegion": {"startLine": 2, "endLine": 4, "snippet": {"text": SECRET_LINE}},
        }
    }
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Opengrep OSS",
                        "rules": [{"id": "r", "help": {"text": "Do not hard-code tokens."}}],
                    }
                },
                "invocations": [{"commandLine": "opengrep scan /tmp/secret-path", "executionSuccessful": True}],
                "results": [
                    {
                        "ruleId": "r",
                        "message": {"text": "A token is hard-coded."},
                        "locations": [location],
                        "relatedLocations": [{"physicalLocation": {"region": {"snippet": {"text": SECRET_LINE}}}}],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "location": {
                                                    "physicalLocation": {"region": {"snippet": {"text": SECRET_LINE}}}
                                                }
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ],
            }
        ],
    }


class RewriteTests(unittest.TestCase):
    def test_snippets_are_removed_and_locations_kept(self):
        root = Path("/work/repo")
        doc = rewrite_opengrep_sarif(opengrep_sarif(root), root, {("r", "src/app.py", 3, 9): "abc:0"})
        text = json.dumps(doc)
        self.assertNotIn("snippet", text)
        self.assertNotIn("ghp_", text)
        result = doc["runs"][0]["results"][0]
        phys = result["locations"][0]["physicalLocation"]
        self.assertEqual(phys["artifactLocation"], {"uri": "src/app.py", "uriBaseId": "%SRCROOT%"})
        self.assertEqual((phys["region"]["startLine"], phys["contextRegion"]["endLine"]), (3, 4))
        self.assertEqual(result["partialFingerprints"], {FINGERPRINT_KEY: "abc:0"})
        self.assertEqual(result["message"]["text"], "A token is hard-coded.")
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["rules"][0]["help"]["text"], "Do not hard-code tokens.")
        self.assertNotIn("commandLine", doc["runs"][0]["invocations"][0])

    def test_the_written_file_has_no_snippets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "opengrep.sarif"
            source.write_text(json.dumps(opengrep_sarif(root)))
            text = build_sarif(source, root, {}, [])
        self.assertNotIn("snippet", text)
        self.assertNotIn("ghp_", text)


if __name__ == "__main__":
    unittest.main()

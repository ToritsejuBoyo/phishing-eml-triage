#!/usr/bin/env python3
"""
Standard validation harness for phishing-eml-triage.

Asserts the known-correct verdict for each synthetic fixture, plus the workspace
rules the library enforces (read-only, stdlib-only, zero emoji, defanged output).

Run:  python tests/validate-skill.py
"""

import ast
import importlib.util
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, "scripts")
FIXTURES = os.path.join(HERE, "fixtures")
sys.path.insert(0, SCRIPTS)

_spec = importlib.util.spec_from_file_location(
    "parse_eml_ioc", os.path.join(SCRIPTS, "parse_eml_ioc.py"))
engine = importlib.util.module_from_spec(_spec)
sys.modules["parse_eml_ioc"] = engine
_spec.loader.exec_module(engine)


def analyse_fixture(name, mask=False):
    path = os.path.join(FIXTURES, name)
    with open(path, "rb") as fh:
        return engine.analyse(fh.read(), path, mask_recipients=mask)


def indicators(report):
    return " | ".join(f["indicator"].lower() for f in report["findings"])


class BecFixture(unittest.TestCase):
    """Authenticated relay, DMARC misalignment, Reply-To to free webmail."""

    @classmethod
    def setUpClass(cls):
        cls.r = analyse_fixture("fixture-bec-reply-to-divergence.eml")

    def test_classified_as_bec(self):
        self.assertEqual("Business Email Compromise (BEC)", self.r["verdict"])

    def test_high_confidence(self):
        self.assertEqual("High", self.r["confidence"])

    def test_dmarc_alignment_failure_detected(self):
        self.assertIn("dmarc alignment failure", indicators(self.r))

    def test_reply_to_divergence_is_high_severity(self):
        hits = [f for f in self.r["findings"] if "reply-to divergence" in f["indicator"].lower()]
        self.assertTrue(hits, "Reply-To divergence was not detected")
        self.assertEqual("HIGH", hits[0]["severity"],
                         "free-webmail Reply-To must be HIGH severity")

    def test_bec_lure_text_detected(self):
        self.assertIn("bec/payment-fraud lure", indicators(self.r))

    def test_spf_and_dkim_pass_but_do_not_align(self):
        auth = self.r["authentication"]
        self.assertEqual("pass", auth["spf"])
        self.assertEqual("pass", auth["dkim"])
        self.assertFalse(auth["dmarc_aligned_pass"],
                         "a pass on an unaligned domain must not count as a DMARC pass")


class ClickFixFixture(unittest.TestCase):
    """No link, no attachment: the payload is an instruction to the victim."""

    @classmethod
    def setUpClass(cls):
        cls.r = analyse_fixture("fixture-clickfix-no-link.eml")

    def test_classified_as_command_execution_lure(self):
        self.assertEqual("Malware Delivery / Command Execution Lure", self.r["verdict"])

    def test_detected_without_any_url_or_attachment(self):
        self.assertEqual([], self.r["urls"], "fixture should contain no URLs")
        self.assertEqual([], self.r["attachments"], "fixture should contain no attachments")

    def test_run_dialog_instruction_detected(self):
        self.assertIn("windows run dialog", indicators(self.r))

    def test_encoded_powershell_detected(self):
        self.assertIn("encoded or hidden powershell", indicators(self.r))

    def test_fake_human_verification_detected(self):
        self.assertIn("human-verification", indicators(self.r))

    def test_homoglyph_sender_domain_detected(self):
        text = indicators(self.r)
        self.assertTrue(
            "homoglyph" in text or "typosquat" in text or "display-name impersonation" in text,
            "rnicrosoft-verify.com should trigger a lookalike or impersonation finding")

    def test_high_confidence(self):
        self.assertEqual("High", self.r["confidence"])


class LegitForwardedFixture(unittest.TestCase):
    """The classic false positive: spf=fail from forwarding, aligned dkim=pass."""

    @classmethod
    def setUpClass(cls):
        cls.r = analyse_fixture("fixture-legit-forwarded.eml")

    def test_not_classified_as_phishing(self):
        self.assertEqual("Legitimate / False Positive", self.r["verdict"],
                         "forwarded legitimate mail must not be called phishing")

    def test_forwarding_signature_identified(self):
        self.assertIn("forwarding signature", indicators(self.r))

    def test_spf_failure_alone_does_not_raise_score(self):
        self.assertEqual("fail", self.r["authentication"]["spf"])
        self.assertTrue(self.r["authentication"]["dkim_aligned"])
        self.assertLessEqual(self.r["risk_score"], 4,
                             "forwarding must not accumulate a phishing score")


class DefangingRules(unittest.TestCase):
    """Rule 1: no live clickable indicator may ever reach output."""

    def test_url_defanging_is_targeted_not_blanket(self):
        out = engine.defang_url("https://evil.example/login.php?a=1")
        self.assertTrue(out.startswith("hxxps://"))
        self.assertIn("[.]", out)
        self.assertNotIn("https://", out)

    def test_defang_does_not_corrupt_prose(self):
        # The previous scaffold replaced every "." in the whole document, which
        # destroyed ordinary sentences. Defanging must apply only to indicators.
        prose = "The user reported it. We checked the headers. No action needed."
        self.assertEqual(prose, engine._scrub(prose))

    def test_ip_and_domain_defanged(self):
        self.assertEqual("203[.]0[.]113[.]5", engine.defang_ip("203.0.113.5"))
        self.assertEqual("evil[.]com", engine.defang_domain("evil.com"))

    def test_email_defanged(self):
        self.assertEqual("a[at]evil[.]com", engine.defang_email("a@evil.com"))

    def test_no_live_scheme_in_any_rendered_report(self):
        for name in sorted(os.listdir(FIXTURES)):
            if not name.endswith(".eml"):
                continue
            with self.subTest(fixture=name):
                md = engine.render_markdown(analyse_fixture(name))
                self.assertNotIn("http://", md)
                self.assertNotIn("https://", md.replace(
                    "https://keepachangelog.com", "").replace(
                    "https://semver.org", ""))


class CredentialRedaction(unittest.TestCase):
    """Credentials inside a reply chain are never operational evidence."""

    def test_password_in_body_is_redacted_but_indicators_survive(self):
        raw = (
            b"From: <attacker@evil.example>\r\n"
            b"To: <victim@corp.example.com>\r\n"
            b"Subject: test\r\n"
            b"\r\n"
            b"Previous message said password=Hunter2SecretValue and the\r\n"
            b"server was 8.8.8.8 with key AKIAIOSFODNN7EXAMPLE\r\n"
        )
        report = engine.analyse(raw, "inline.eml")
        blob = engine.render_markdown(report)
        self.assertNotIn("Hunter2SecretValue", blob, "password leaked into report")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", blob, "cloud key leaked into report")

    def test_recipient_masking_only_with_sanitize(self):
        plain = analyse_fixture("fixture-bec-reply-to-divergence.eml")
        masked = analyse_fixture("fixture-bec-reply-to-divergence.eml", mask=True)
        self.assertNotIn("MASKED-RECIPIENTS", plain["headers"]["to"])
        self.assertIn("MASKED-RECIPIENTS", masked["headers"]["to"])

    def test_attacker_indicators_are_preserved(self):
        r = analyse_fixture("fixture-clickfix-no-link.eml")
        self.assertTrue(r["iocs"]["sender_addresses"],
                        "sender IOC must survive: it is the deliverable")


class WorkspaceRules(unittest.TestCase):
    """Library-wide rules enforced by CI."""

    def test_stdlib_only(self):
        stdlib = set(sys.stdlib_module_names)
        local = {p[:-3] for p in os.listdir(SCRIPTS) if p.endswith(".py")}
        for folder in (SCRIPTS, HERE):
            for name in os.listdir(folder):
                if not name.endswith(".py"):
                    continue
                path = os.path.join(folder, name)
                with open(path, encoding="utf-8") as fh:
                    tree = ast.parse(fh.read())
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        mods = [a.name.split(".")[0] for a in node.names]
                    elif isinstance(node, ast.ImportFrom):
                        mods = [(node.module or "").split(".")[0]] if node.level == 0 else []
                    else:
                        continue
                    for mod in mods:
                        if mod and mod not in stdlib and mod not in local:
                            self.fail("third-party import '%s' in %s" % (mod, name))

    def test_no_network_calls_in_engine(self):
        with open(os.path.join(SCRIPTS, "parse_eml_ioc.py"), encoding="utf-8") as fh:
            src = fh.read()
        for banned in ("urllib.request", "http.client", "socket.create_connection",
                       "requests.", "ftplib", "smtplib.SMTP("):
            self.assertNotIn(banned, src, "engine must make no network call (%s)" % banned)

    def test_no_emoji_in_shipped_text(self):
        emoji = re.compile(
            "[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F000-\U0001F2FF]")
        for folder in (ROOT, os.path.join(ROOT, "references"), os.path.join(ROOT, "assets")):
            if not os.path.isdir(folder):
                continue
            for name in os.listdir(folder):
                if not name.endswith(".md"):
                    continue
                with open(os.path.join(folder, name), encoding="utf-8") as fh:
                    body = fh.read()
                with self.subTest(doc=name):
                    self.assertIsNone(emoji.search(body), "emoji found in %s" % name)

    def test_skill_md_references_every_bundled_file(self):
        with open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as fh:
            skill = fh.read()
        for folder in ("scripts", "references", "assets"):
            path = os.path.join(ROOT, folder)
            if not os.path.isdir(path):
                continue
            for name in os.listdir(path):
                if name.startswith("__") or name.endswith(".pyc"):
                    continue
                with self.subTest(resource="%s/%s" % (folder, name)):
                    self.assertIn(name, skill,
                                  "%s/%s is never referenced from SKILL.md" % (folder, name))

    def test_frontmatter_complete(self):
        with open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as fh:
            text = fh.read()
        match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
        self.assertIsNotNone(match, "SKILL.md has no frontmatter")
        front = match.group(1)
        for field in ("name", "description", "license", "version", "metadata"):
            self.assertRegex(front, r"(?m)^%s:" % field, "frontmatter missing %s" % field)
        desc = re.search(r"(?ms)^description:\s*(?:>-?|\|-?)?\s*\n?(.*?)(?=^[a-z_]+:|\Z)", front)
        flat = " ".join(desc.group(1).split())
        self.assertRegex(flat, r"(?i)\buse when\b", "description lacks a trigger clause")

    def test_msg_support_is_not_promised(self):
        # .msg is OLE2 and cannot be parsed with the stdlib, so the skill must not
        # claim support it cannot deliver.
        with open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as fh:
            skill = fh.read()
        front = re.match(r"^---\n(.*?)\n---\n", skill, re.DOTALL).group(1)
        desc = re.search(
            r"(?ms)^description:\s*(?:>-?|\|-?)?\s*\n?(.*?)(?=^[a-z_]+:|\Z)", front)
        flat = " ".join(desc.group(1).split()).lower()
        self.assertNotIn(".msg", flat, "description must not promise .msg support")
        # The body must still state the limitation explicitly, so an agent does not
        # silently mis-handle a .msg the user supplies.
        self.assertIn("out of scope", skill.lower())


class Determinism(unittest.TestCase):
    def test_repeated_analysis_is_stable(self):
        for name in sorted(n for n in os.listdir(FIXTURES) if n.endswith(".eml")):
            with self.subTest(fixture=name):
                a, b = analyse_fixture(name), analyse_fixture(name)
                a.pop("generated_utc", None)
                b.pop("generated_utc", None)
                self.assertEqual(a, b)


if __name__ == "__main__":
    print("=" * 74)
    print("VALIDATION HARNESS: phishing-eml-triage")
    print("=" * 74)
    unittest.main(verbosity=2)

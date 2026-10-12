"""OpenID Connect sign-in: the configuration, RS256 checks, ID token rules, discovery and the login state."""

import base64
import json
import time
import unittest

import fake_idp
import helpers  # noqa: F401 - puts src/ on the import path
from fake_idp import FakeIdP, b64, rsa_key, sign_jwt

from shoalscan.dashboard import oidc
from shoalscan.errors import SetupError


class ConfigTests(unittest.TestCase):
    BASE = {
        "issuer": "https://idp.example/dex",
        "client_id": "shoalscan",
        "client_secret": "a-long-secret",
        "redirect_uri": "https://dash.example:8443/oidc/callback",
    }

    def test_a_good_configuration(self):
        config = oidc.validate(self.BASE)
        self.assertEqual(config.issuer, "https://idp.example/dex")
        self.assertEqual((config.admin_claim, config.admin_value), ("groups", "shoal-admin"))
        self.assertIn("openid", config.scopes)
        oidc.validate(dict(self.BASE, issuer="http://127.0.0.1:5556/dex"))  # plain http only on this machine

    def test_an_issuer_keeps_its_trailing_slash(self):
        # The issuer is compared exactly as the provider publishes it, so a trailing slash stays.
        config = oidc.validate(dict(self.BASE, issuer="https://idp.example/dex/"))
        self.assertEqual(config.issuer, "https://idp.example/dex/")
        self.assertEqual(oidc.discovery_url(config.issuer), "https://idp.example/dex/.well-known/openid-configuration")
        self.assertEqual(
            oidc.discovery_url("https://idp.example"), "https://idp.example/.well-known/openid-configuration"
        )
        with self.assertRaises(SetupError):
            oidc.validate(dict(self.BASE, issuer="https://idp.example/dex/?x=1"))

    def test_bad_configurations_are_refused(self):
        bad = [
            {"issuer": "http://idp.example/dex"},
            {"issuer": "https://user:pw@idp.example"},
            {"issuer": "https://idp.example/?x=1"},
            {"client_id": "two words"},
            {"client_secret": "short"},
            {"redirect_uri": "https://dash.example/other"},
            {"redirect_uri": "http://dash.example/oidc/callback"},
            {"admin_claim": "a b"},
            {"admin_value": ""},
            {"scopes": ["email"]},
            {"surprise": True},
        ]
        for change in bad:
            with self.subTest(change=change), self.assertRaises(SetupError):
                oidc.validate(dict(self.BASE, **change))
        for ca_file in ("relative.pem", "/no/such/file.pem"):
            with self.subTest(ca_file=ca_file), self.assertRaises(SetupError):
                oidc.validate(dict(self.BASE), ca_file=ca_file)

    def test_save_and_load_keep_it_private(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.assertIsNone(oidc.load(state))
            config = oidc.validate(dict(self.BASE, display_name='Dex "demo"'))
            oidc.save(state, config)
            self.assertEqual(oidc.load(state), config)
            self.assertEqual((state / oidc.CONFIG_FILE).stat().st_mode & 0o777, 0o600)
            (state / oidc.CONFIG_FILE).chmod(0o644)
            with self.assertRaisesRegex(SetupError, "chmod 600"):
                oidc.load(state)


class SignatureTests(unittest.TestCase):
    def test_rs256(self):
        n, e, _ = rsa_key()
        head, body, sig = sign_jwt({"a": 1}).split(".")
        signature = fake_idp.base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        self.assertTrue(oidc.rs256_verify(n, e, f"{head}.{body}".encode(), signature))
        self.assertFalse(oidc.rs256_verify(n, e, f"{head}.{body}x".encode(), signature))
        self.assertFalse(
            oidc.rs256_verify(n, e, f"{head}.{body}".encode(), signature[:-1] + bytes([signature[-1] ^ 1]))
        )
        self.assertFalse(oidc.rs256_verify(n, e, f"{head}.{body}".encode(), signature[1:]))
        self.assertFalse(oidc.rs256_verify(n, e, f"{head}.{body}".encode(), (n + 1).to_bytes(256, "big")))


class IdTokenTests(unittest.TestCase):
    def setUp(self):
        n, e, _ = rsa_key()
        self.config = oidc.validate(
            {
                "issuer": "https://idp.example",
                "client_id": "shoalscan",
                "client_secret": "a-long-secret",
                "redirect_uri": "https://dash.example/oidc/callback",
            }
        )
        self.provider = oidc.Provider(
            "https://idp.example", "a", "t", "https://idp.example/keys", {"k1": (n, e)}, time.monotonic()
        )
        self.now = time.time()
        self.claims = {
            "iss": "https://idp.example",
            "aud": "shoalscan",
            "sub": "u1",
            "iat": int(self.now),
            "exp": int(self.now) + 300,
            "nonce": "N",
        }

    def verify(self, token, nonce="N"):
        return oidc.verify_id_token(self.provider, self.config, token, nonce, now=self.now)

    def test_a_good_token(self):
        self.assertEqual(self.verify(sign_jwt(self.claims))["sub"], "u1")
        self.assertEqual(self.verify(sign_jwt(dict(self.claims, aud=["shoalscan", "x"], azp="shoalscan")))["sub"], "u1")
        self.assertEqual(self.verify(sign_jwt(dict(self.claims, azp="shoalscan")))["sub"], "u1")

    def test_every_rule_is_enforced(self):
        bad = {
            "another issuer": sign_jwt(dict(self.claims, iss="https://evil.example")),
            "another audience": sign_jwt(dict(self.claims, aud="someone-else")),
            "several audiences, no azp": sign_jwt(dict(self.claims, aud=["shoalscan", "x"])),
            "one audience, another azp": sign_jwt(dict(self.claims, azp="someone-else")),
            "several audiences, another azp": sign_jwt(dict(self.claims, aud=["shoalscan", "x"], azp="x")),
            "expired": sign_jwt(dict(self.claims, exp=int(self.now) - 600)),
            "from the future": sign_jwt(dict(self.claims, iat=int(self.now) + 600)),
            "not yet valid": sign_jwt(dict(self.claims, nbf=int(self.now) + 600)),
            "no nonce": sign_jwt({k: v for k, v in self.claims.items() if k != "nonce"}),
            "no subject": sign_jwt(dict(self.claims, sub="")),
            "HS256": sign_jwt(self.claims, alg="HS256"),
            "not a JWT": "a.b",
        }
        head, body, _ = sign_jwt(self.claims).split(".")
        bad["alg none"] = f"{b64(json.dumps({'alg': 'none', 'kid': 'k1'}).encode())}.{body}."
        bad["bad signature"] = (
            f"{head}.{b64(json.dumps(dict(self.claims, sub='admin')).encode())}.{sign_jwt(self.claims).split('.')[2]}"
        )
        for name, token in bad.items():
            with self.subTest(name=name), self.assertRaises(oidc.OidcError):
                self.verify(token)
        with self.assertRaises(oidc.OidcError):
            self.verify(sign_jwt(self.claims), nonce="other")

    def test_admin_claims(self):
        is_admin = oidc.is_admin
        self.assertTrue(is_admin(self.config, {"groups": ["dev", "shoal-admin"]}))
        self.assertFalse(is_admin(self.config, {"groups": ["dev"]}))
        self.assertFalse(is_admin(self.config, {}))
        flag = oidc.validate(
            {
                **self.config.__dict__,
                "scopes": list(self.config.scopes),
                "admin_claim": "shoal-admin",
                "admin_value": "true",
            }
        )
        self.assertTrue(is_admin(flag, {"shoal-admin": True}))
        self.assertFalse(is_admin(flag, {"shoal-admin": False}))
        self.assertFalse(is_admin(flag, {"shoal-admin": "yes"}))


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.idp = FakeIdP()

    def tearDown(self):
        self.idp.close()

    def test_discovery_keys_and_the_client(self):
        config = self.idp.config()
        provider = oidc.discover(config)
        self.assertEqual(provider.token_endpoint, f"{self.idp.issuer}/token")
        self.assertIn("k1", provider.keys)
        self.assertGreaterEqual(len(provider.checks), 5)
        self.assertIn("accepted the client", oidc.check_client(provider, config))
        with self.assertRaisesRegex(oidc.OidcError, "invalid_client"):
            oidc.check_client(provider, self.idp.config(client_secret="the-wrong-secret"))

    def test_a_provider_that_cannot_be_trusted(self):
        original = self.idp.discovery
        for change in (
            {"issuer": "https://evil.example"},
            {"id_token_signing_alg_values_supported": ["HS256"]},
            {"token_endpoint": "http://evil.example/token"},
            {"code_challenge_methods_supported": ["plain"]},
            {"scopes_supported": ["openid"]},
        ):
            self.idp.discovery = lambda change=change: {**original(), **change}
            with self.subTest(change=change), self.assertRaises(oidc.OidcError):
                oidc.discover(self.idp.config())

    def test_the_issuer_must_match_exactly(self):
        # Configured with a trailing slash the provider does not publish: refused, not quietly normalised.
        with self.assertRaisesRegex(oidc.OidcError, "issuer"):
            oidc.discover(self.idp.config(issuer=f"{self.idp.issuer}/"))
        original = self.idp.discovery
        self.idp.discovery = lambda: {**original(), "issuer": f"{self.idp.issuer}/"}
        with self.assertRaisesRegex(oidc.OidcError, "issuer"):
            oidc.discover(self.idp.config())
        self.assertEqual(oidc.discover(self.idp.config(issuer=f"{self.idp.issuer}/")).issuer, f"{self.idp.issuer}/")

    def test_nothing_listening(self):
        with self.assertRaisesRegex(oidc.OidcError, "not reachable"):
            oidc.discover(
                oidc.validate(
                    {
                        "issuer": "http://127.0.0.1:9",
                        "client_id": "x",
                        "client_secret": "a-long-secret",
                        "redirect_uri": "https://d.example/oidc/callback",
                    }
                )
            )


class LoginStateTests(unittest.TestCase):
    def test_each_state_works_once_and_expires(self):
        logins = oidc.Logins()
        state, pending, sealed = logins.start()
        self.assertEqual(logins.finish(state, sealed), pending)
        self.assertIsNone(logins.finish(state, sealed))  # a replayed callback
        state, pending, sealed = logins.start(now=time.time() - oidc.LOGIN_SECONDS - 1)
        self.assertIsNone(logins.finish(state, sealed))
        self.assertIsNone(logins.finish(None, sealed))
        self.assertIsNone(logins.finish(state, None))

    def test_the_server_keeps_nothing_until_a_login_comes_back(self):
        logins = oidc.Logins()
        started = [logins.start() for _ in range(3000)]
        self.assertEqual(len(logins._used), 0)
        # Starting many logins crowds out none: the first one still works.
        state, pending, sealed = started[0]
        self.assertEqual(logins.finish(state, sealed), pending)

    def test_the_cookie_is_bound_to_its_state_and_cannot_be_forged(self):
        logins = oidc.Logins()
        state, _, sealed = logins.start()
        other_state, _, other_sealed = logins.start()
        self.assertIsNone(logins.finish(other_state, sealed))  # another login's state
        payload, tag = sealed.split(".")
        body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        body["t"] = time.time() + 3600  # a longer life, under the old tag
        changed = base64.urlsafe_b64encode(json.dumps(body).encode()).rstrip(b"=").decode()
        for bad in (f"{changed}.{tag}", f"{payload}.{tag[:-2]}AA", payload, f"{payload}.", "x" * 5000, "a.b.c"):
            with self.subTest(bad=bad[:30]):
                self.assertIsNone(logins.finish(state, bad))
        # A cookie from another process (another key) is refused.
        self.assertIsNone(oidc.Logins().finish(other_state, other_sealed))
        self.assertIsNotNone(logins.finish(state, sealed))

    def test_used_states_are_bounded(self):
        logins = oidc.Logins()
        before = oidc.MAX_USED_STATES
        oidc.MAX_USED_STATES = 5
        try:
            for _ in range(20):
                state, _, sealed = logins.start()
                self.assertIsNotNone(logins.finish(state, sealed))
            self.assertLessEqual(len(logins._used), 5)
        finally:
            oidc.MAX_USED_STATES = before
        # Used states are forgotten once their login could no longer finish anyway.
        state, _, sealed = logins.start(now=time.time() - oidc.LOGIN_SECONDS + 1)
        self.assertIsNotNone(logins.finish(state, sealed))
        self.assertIsNone(logins.finish(state, sealed, now=time.time() + 5))
        later, _, later_sealed = logins.start(now=time.time() + 5)
        self.assertIsNotNone(logins.finish(later, later_sealed, now=time.time() + 5))
        self.assertNotIn(state, logins._used)

    def test_the_authorization_url_carries_pkce(self):
        n, e, _ = rsa_key()
        config = oidc.validate(
            {
                "issuer": "https://idp.example",
                "client_id": "shoalscan",
                "client_secret": "a-long-secret",
                "redirect_uri": "https://dash.example/oidc/callback",
            }
        )
        provider = oidc.Provider("https://idp.example", "https://idp.example/auth", "t", "k", {"k1": (n, e)})
        state, pending, sealed = oidc.Logins().start()
        url = oidc.authorization_url(provider, config, state, pending)
        from urllib.parse import parse_qs, urlsplit

        q = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        self.assertEqual(
            (q["response_type"], q["code_challenge_method"], q["state"], q["nonce"]),
            ("code", "S256", state, pending.nonce),
        )
        self.assertEqual(q["redirect_uri"], "https://dash.example/oidc/callback")
        self.assertNotIn(pending.verifier, url)
        self.assertNotIn(sealed, url)


if __name__ == "__main__":
    unittest.main()

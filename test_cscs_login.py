from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch

from cscs_login import CONSENT, REALM, CscsLogin
from switch_login import SwitchLogin, totp


class CscsConsentTests(TestCase):
    def test_submits_the_current_keycloakify_consent(self):
        login = self.page(CONSENT + "?client_id=authx-cli")
        with patch.object(login, "request") as request:
            login.accept_consent()
        request.assert_called_once_with(
            "POST", CONSENT + "?client_id=authx-cli", {"code": "test-code", "accept": "Yes"}
        )

    def test_refuses_consent_for_another_client_or_host(self):
        for target in (CONSENT + "?client_id=waldur", "https://other.example/consent?client_id=authx-cli"):
            with self.subTest(target=target):
                login = self.page(target)
                with patch.object(login, "request") as request:
                    with self.assertRaisesRegex(RuntimeError, "CSCS SSH CLI"):
                        login.accept_consent()
                request.assert_not_called()

    @staticmethod
    def page(action):
        login = CscsLogin()
        escaped_action = action.replace("/", r"\/")
        login.page = SimpleNamespace(
            url=REALM + "/login-actions/required-action",
            text=f'''
                <script>
                const kcContext = {{
                    "url": {{ "oauthAction": "{escaped_action}" }},
                    "oauth": {{ "code": "test-code" }}
                }};
                kcContext.pageId = "login-oauth-grant.ftl";
                </script>
            ''',
        )
        return login


class SwitchLoginTests(TestCase):
    def test_generates_a_six_digit_totp(self):
        # The six-digit suffix of the RFC 6238 SHA-1 test at t=59.
        self.assertEqual(totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", now=59), "287082")

    def test_never_forwards_switch_credentials_to_cscs(self):
        login = SwitchLogin()
        redirect = SimpleNamespace(status_code=307, headers={"Location": REALM + "/device"})
        with patch.object(login.session, "request", return_value=redirect) as request:
            with self.assertRaisesRegex(RuntimeError, "credentials require"):
                login.request("POST", "https://login.eduid.ch/login", {"j_password": "test-password"})
        self.assertEqual(request.call_count, 1)


if __name__ == "__main__":
    main()

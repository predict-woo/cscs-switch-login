"""Run cscs-key with automatic SWITCH edu-ID device approval."""

import json
import os
import re
import subprocess
import sys
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import requests

from switch_login import SWITCH_HOST, SwitchLogin


REALM = "https://auth.cscs.ch/auth/realms/cscs"
DEVICE = REALM + "/device"
SIGN_IN = REALM + "/login-actions/authenticate"
BROKER = REALM + "/broker/switch/login"
CONSENT = REALM + "/login-actions/consent"
CLIENT = "authx-cli"


def client_action(url, endpoint):
    return url.partition("?")[0] == endpoint and parse_qs(urlsplit(url).query).get("client_id") == [CLIENT]


def theme_values(page, field):
    # Keycloakify renders links and forms from server-supplied JavaScript strings.
    key = re.escape(field)
    pattern = rf'(?:"{key}"\s*:|\bkcContext\.{key}\s*=)\s*("(?:\\.|[^"\\])*")'
    for script in page.find_all("script", src=False):
        source = script.string or ""
        if "const kcContext =" in source:
            return [json.loads(literal) for literal in re.findall(pattern, source)]
    return []


class CscsLogin(SwitchLogin):
    def approve_device(self, link):
        if link.partition("?")[0] != DEVICE or not parse_qs(urlsplit(link).query).get("user_code"):
            raise RuntimeError("Expected a CSCS device verification link")

        # Keycloak offers a continuation form to clients without Kerberos.
        self.request("GET", link, accepted_status=(401,))
        if not client_action(self.page.url, SIGN_IN):
            raise RuntimeError("Expected the CSCS SSH CLI sign-in page")
        if self.page.status_code == 401:
            form = self.field_form("continue")
            if not client_action(self.form_action(form), SIGN_IN):
                raise RuntimeError("Unexpected CSCS continuation form")
            self.submit(form, {"continue": form.select_one('[name="continue"]').get("value", "")})

        page = self.document()
        switch_link = page.select_one('a[href*="/broker/switch/login"]')
        links = [switch_link["href"]] if switch_link else theme_values(page, "loginUrl")
        urls = [urljoin(self.page.url, link) for link in links]
        brokers = [url for url in urls if client_action(url, BROKER)]
        if len(brokers) != 1:
            raise RuntimeError("CSCS did not offer SWITCH edu-ID for this request")
        self.request("GET", brokers[0])
        if urlsplit(self.page.url).hostname != SWITCH_HOST:
            raise RuntimeError("CSCS did not redirect to SWITCH edu-ID")
        self.authenticate_switch()

        if self.page.url.partition("?")[0] != DEVICE + "/status":
            self.accept_consent()
        if self.page.url.partition("?")[0] != DEVICE + "/status":
            raise RuntimeError("CSCS did not return to the device status page")

    def accept_consent(self):
        page = self.document()
        form = page.select_one('form:has([name="accept"])')
        if form is not None:
            if not client_action(self.form_action(form), CONSENT) or not form.select_one('input[name="code"][type="hidden"]'):
                raise RuntimeError("Expected approval for the CSCS SSH CLI")
            self.submit(form, {"accept": form.select_one('[name="accept"]').get("value", "")})
            return

        actions = theme_values(page, "oauthAction")
        codes = theme_values(page, "code")
        if "login-oauth-grant.ftl" not in theme_values(page, "pageId") or len(actions) != 1 or len(codes) != 1:
            raise RuntimeError("The expected CSCS approval page did not load")
        action = urljoin(self.page.url, actions[0])
        if not client_action(action, CONSENT) or not codes[0]:
            raise RuntimeError("Expected approval for the CSCS SSH CLI")
        self.request("POST", action, {"code": codes[0], "accept": "Yes"})


def run_cscs(args):
    env = os.environ.copy()
    env.pop("CSCS_API_KEY", None)
    command = ["cscs-key", "--headless", *(args or ["list"])]
    with subprocess.Popen(command, stderr=subprocess.PIPE, text=True, env=env) as process:
        needs_code = False
        try:
            for line in process.stderr:
                message = line.strip()
                if message == DEVICE:
                    needs_code = True
                    continue
                if needs_code and message.startswith("And enter the code: "):
                    code = message.removeprefix("And enter the code: ")
                    message = DEVICE + "?" + urlencode({"user_code": code})
                if message.startswith(DEVICE + "?"):
                    login = CscsLogin()
                    with login.session:
                        login.approve_device(message)
                    needs_code = False
                elif message == "Authentication successful!" or message.startswith("Public SSH certificate successfully"):
                    print(message, file=sys.stderr, flush=True)
            return process.wait()
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    try:
        status = run_cscs(sys.argv[1:])
        if status:
            print(f"cscs-key exited with status {status}.", file=sys.stderr)
        return status if status >= 0 else 128 - status
    except requests.RequestException as exc:
        status = exc.response.status_code if exc.response is not None else type(exc).__name__
        print(f"HTTP login failed ({status}).", file=sys.stderr)
    except FileNotFoundError:
        print("Install cscs-key and ensure it is on your PATH.", file=sys.stderr)
    except (KeyError, ValueError):
        print("The login server returned unexpected authentication data.", file=sys.stderr)
    except RuntimeError as exc:
        print(f"CSCS login stopped. {exc}", file=sys.stderr)
    except KeyboardInterrupt:
        return 130
    return 1


if __name__ == "__main__":
    sys.exit(main())

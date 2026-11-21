"""SWITCH edu-ID form handling for the CSCS device login."""

import base64
from getpass import getpass
import hmac
import os
from pathlib import Path
import struct
import sys
import time
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup
from dotenv import dotenv_values
import requests


SWITCH_HOST = "login.eduid.ch"
LOGIN_HOSTS = {"auth.cscs.ch", SWITCH_HOST}
SWITCH_FIELDS = {"j_username", "j_password", "j_otp"}
ENV_FILE = Path(__file__).with_name(".env")


def totp(secret, now=None):
    secret = "".join(secret.split()).upper().rstrip("=")
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    if not key:
        raise ValueError("Empty TOTP secret")
    counter = int(time.time() if now is None else now) // 30
    digest = hmac.digest(key, struct.pack(">Q", counter), "sha1")
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


class SwitchLogin:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
        })
        self.page = None

    def request(self, method, url, data=None, *, accepted_status=()):
        referer = self.page.url if self.page is not None else None
        for _ in range(20):
            destination = urlsplit(url)
            if (destination.scheme != "https" or destination.hostname not in LOGIN_HOSTS
                    or destination.port not in (None, 443)
                    or destination.username is not None or destination.password is not None):
                raise RuntimeError("Unexpected authentication destination")
            if data and SWITCH_FIELDS.intersection(data):
                if destination.hostname != SWITCH_HOST or method != "POST":
                    raise RuntimeError("SWITCH credentials require a POST to login.eduid.ch")

            headers = {}
            if referer:
                source = urlsplit(referer)
                origin = f"{source.scheme}://{source.netloc}"
                same_origin = (source.scheme, source.netloc) == (destination.scheme, destination.netloc)
                headers["Referer"] = referer if same_origin else origin + "/"
                if method == "POST":
                    headers["Origin"] = origin
            response = self.session.request(
                method, url, data=data, headers=headers, timeout=30, allow_redirects=False,
            )
            print(f"{method} {destination.hostname}{destination.path} -> {response.status_code}",
                  file=sys.stderr, flush=True)
            if response.status_code in (301, 302, 303, 307, 308):
                referer = url
                url = urljoin(url, response.headers["Location"])
                if response.status_code == 303 or (response.status_code in (301, 302) and method == "POST"):
                    method, data = "GET", None
                continue
            if response.status_code not in accepted_status:
                response.raise_for_status()
            self.page = response
            return
        raise RuntimeError("Too many authentication redirects")

    def document(self):
        return BeautifulSoup(self.page.text, "html.parser")

    def find_form(self, selector):
        return self.document().select_one(f"form:has({selector})")

    def field_form(self, name):
        form = self.find_form(f'[name="{name}"]')
        if form is None:
            raise RuntimeError(f"Expected form field {name!r} is missing")
        return form

    def form_action(self, form):
        return urljoin(self.page.url, form.get("action", ""))

    def submit(self, form, values):
        if form.get("method", "get").upper() != "POST":
            raise RuntimeError("Expected a POST form")
        data = {
            field["name"]: field.get("value", "")
            for field in form.select("input[name]:not([disabled])")
            if field.get("type", "text").lower() not in {"submit", "button", "checkbox", "radio"}
        }
        self.request("POST", self.form_action(form), {**data, **values})

    def storage(self, form):
        # Each device login starts with empty browser local storage.
        values = {
            field["name"]: "true"
            for field in form.select('input[name="shib_idp_ls_supported"], input[name^="shib_idp_ls_success."]')
        }
        self.submit(form, values)

    def authenticate_switch(self):
        storage = self.find_form('input[name="shib_idp_ls_supported"]')
        if storage is not None:
            self.storage(storage)

        email_form = self.field_form("j_username")
        defaults = dotenv_values(ENV_FILE, interpolate=False)
        username = os.environ.get("SWITCH_EDU_ID") or defaults.get("SWITCH_EDU_ID") or getpass("SWITCH email: ")
        password = (os.environ.get("SWITCH_EDU_PASSWORD") or defaults.get("SWITCH_EDU_PASSWORD")
                    or getpass("SWITCH password: "))
        self.submit(email_form, {"j_username": username, "_eventId_submit": ""})

        password_link = self.document().select_one('a[href*="_eventId=SwitchToPassword"]')
        if password_link is not None:
            self.request("GET", urljoin(self.page.url, password_link["href"]))
        self.submit(self.field_form("j_password"), {
            "j_username": username, "j_password": password, "_eventId_proceed": "",
        })

        otp_form = self.find_form('input[name="j_otp"]')
        if otp_form is not None:
            secret = (os.environ.get("SWITCH_EDU_TOTP_SECRET") or defaults.get("SWITCH_EDU_TOTP_SECRET")
                      or getpass("SWITCH TOTP setup secret: "))
            remaining = 30 - time.time() % 30
            if remaining < 3:
                time.sleep(remaining + 0.1)
            self.submit(otp_form, {"j_otp": totp(secret), "_eventId_submit": ""})
            if self.find_form('input[name="j_otp"]') is not None:
                raise RuntimeError("SWITCH did not accept the one-time code")

        storage = self.find_form('input[name^="shib_idp_ls_success."]')
        if storage is not None:
            self.storage(storage)

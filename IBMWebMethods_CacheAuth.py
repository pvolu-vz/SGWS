import os, sys, time, json
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
import pyotp

def must_env(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        sys.stderr.write(f"Missing environment variable: {name}\n")
        sys.exit(2)
    return v


def origin_of(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def parse_form(html: str, base_url: str):
    """Return (absolute_action_url, dict_of_inputs) for the FIRST <form>."""
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    if not form:
        return None, {}
    action = form.get("action") or base_url
    action_abs = urljoin(base_url, action)
    vals = {}
    for inp in form.find_all("input"):
        name = inp.get("name")
        if name:
            vals[name] = inp.get("value", "")
    return action_abs, vals


def looks_like_otp(html: str) -> bool:
    s = html.lower()
    needles = ['name="otp"', 'name="totp"', "mfa", "two-factor", "one-time", "verification code"]
    return any(n in s for n in needles)


def get_cookie_value_for_host(sess: requests.Session, host: str, name: str) -> str:
    for c in sess.cookies:
        if c.domain.lstrip(".").endswith(host) and c.name.lower() == name.lower():
            return c.value
    return ""


def cookie_header_for_host(sess: requests.Session, host: str) -> str:
    """Build a Cookie header for a host (workaround if Path scoping prevents sends)."""
    pairs = []
    for c in sess.cookies:
        if c.domain.lstrip(".").endswith(host):
            pairs.append(f"{c.name}={c.value}")
    return "; ".join(pairs)

def logging_in_extract_json():
    TENANT_BASE     = must_env("TENANT_BASE").rstrip("/")
    IM_USERNAME     = must_env("IM_USERNAME")
    IM_PASSWORD     = must_env("IM_PASSWORD")
    IM_TOTP_SECRET  = must_env("IM_TOTP_SECRET")
    API_PATH        = os.environ.get("API_PATH", "/api/searchUser?first=0&max=10")

    sess = requests.Session()
    sess.headers.update({
        "User-Agent": "PythonLoginClient/1.0 (+automation)",
        "Accept-Language": "en-US,en;q=0.9",
    })

    # 1) Kick off at tenant; this will bounce to IdP
    start_url = f"{TENANT_BASE}/sso/login"
    r = sess.get(start_url, timeout=30)
    r.raise_for_status()

    # If already authenticated, skip to API
    if r.ok and r.url.startswith(TENANT_BASE) and "logout" in r.text.lower():
        pass
    else:
        # 2) Password step
        pw_action, pw_vals = parse_form(r.text, r.url)
        if not pw_action:
            sys.stderr.write("Could not locate password form\n")
            sys.exit(1)

        pw_vals["username"] = IM_USERNAME
        pw_vals["password"] = IM_PASSWORD
        pw_vals.setdefault("rememberMe", "on")

        pw_hdr = {
            "Referer": r.url,
            "Origin": origin_of(pw_action),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        r = sess.post(pw_action, data=pw_vals, headers=pw_hdr, timeout=30)
        if r.status_code != 200 or not looks_like_otp(r.text):
            sys.stderr.write(f"Expected OTP page (200) after password; got {r.status_code}\n")
            sys.stderr.write(r.text[:900] + "...\n")
            sys.exit(1)

        # 3) OTP step
        otp_action, otp_vals = parse_form(r.text, r.url)
        if not otp_action:
            otp_action = r.url

        code_now = pyotp.TOTP(IM_TOTP_SECRET).now()
        otp_vals["otp"] = code_now
        otp_vals.setdefault("login", "Log in")

        otp_hdr = {
            "Referer": r.url,
            "Origin": origin_of(otp_action),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        # capture Location with ?code=... without auto-follow
        r = sess.post(otp_action, data=otp_vals, headers=otp_hdr, timeout=30, allow_redirects=False)

        if r.status_code // 100 != 3 or not r.headers.get("Location"):
            # try +30s skew once
            code_next = pyotp.TOTP(IM_TOTP_SECRET).at(int(time.time()) + 30)
            otp_vals["otp"] = code_next
            r = sess.post(otp_action, data=otp_vals, headers=otp_hdr, timeout=30, allow_redirects=False)
            if r.status_code // 100 != 3 or not r.headers.get("Location"):
                sys.stderr.write(f"OTP did not return a 302 with Location; got {r.status_code}\n")
                sys.exit(1)

        code_url = urljoin(r.url, r.headers["Location"])

        # 4) GET the code URL; follow a couple of redirects to mint cookies
        hop = 0
        resp = sess.get(code_url, timeout=30, allow_redirects=False)
        while resp.is_redirect and hop < 3:
            nxt = resp.headers.get("Location")
            if not nxt:
                break
            next_url = urljoin(resp.url, nxt)
            resp = sess.get(next_url, timeout=30, allow_redirects=False)
            hop += 1

        # Touch "/" to encourage Path=/ cookies if first mint was scoped to /sso
        sess.get(f"{TENANT_BASE}/", timeout=30)

    # 5) Call protected API
    api_url = f"{TENANT_BASE}{API_PATH}"
    host = urlparse(TENANT_BASE).netloc
    xsrf = get_cookie_value_for_host(sess, host, "XSRF-TOKEN")

    api_headers = {
        "Accept": "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": TENANT_BASE,
        "Referer": f"{TENANT_BASE}/app/home",
    }
    if xsrf:
        api_headers["X-XSRF-TOKEN"] = xsrf

    # Fallback: manual Cookie header (bypasses strict Path scoping)
    manual_cookie = cookie_header_for_host(sess, host)
    if manual_cookie:
        api_headers["Cookie"] = manual_cookie

    resp = sess.get(api_url, headers=api_headers, timeout=30)
    if resp.status_code == 200:
        #sys.stdout.write(resp.text)  # raw JSON to stdout
        try:
            return resp.json()
        except Exception as e:
            resp.text
    else:
        return (f"ERROR {resp.status_code}\n{resp.text}\n")
        
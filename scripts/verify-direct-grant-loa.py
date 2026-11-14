#!/usr/bin/env python3
"""Live check of continuum-direct-grant-loa on a throwaway Keycloak (dev/spike only).

Starts its own Keycloak container (never the shared :8180 one) with target/continuum-keycloak-spi.jar
mounted, imports three throwaway realms and drives the token endpoint (grant_type=password):
  - dgloa        : nominal flow (username, password, conditional OTP, continuum-direct-grant-loa loa=2)
  - dgloa-drift  : same flow but the OTP sub-flow DISABLED (drift) -> must never give acr=2
  - dgloa-nocfg  : LoA authenticator without config -> must never give acr=2
Removes the container afterwards. Usage: mvn -q package && python scripts/verify-direct-grant-loa.py
The authenticator is shelved (ADR 0014, 2026-11-14): off unless the SPI option raise-loa=true. DGLOA_ENABLED=true (default)
starts Keycloak with that option; DGLOA_ENABLED=false checks the shipped default (password + OTP -> acr 1).
Env: KC_IMAGE (quay.io/keycloak/keycloak:26.3), KC_PORT (8183), KC_CONTAINER (keycloak-identity-loa).
"""
import base64, hashlib, hmac, json, os, struct, subprocess, sys, tempfile, time, urllib.error, urllib.parse, urllib.request

IMAGE = os.environ.get("KC_IMAGE", "quay.io/keycloak/keycloak:26.3")
PORT = os.environ.get("KC_PORT", "8183")
NAME = os.environ.get("KC_CONTAINER", "keycloak-identity-loa")
BASE = f"http://localhost:{PORT}"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENABLED = os.environ.get("DGLOA_ENABLED", "true").lower() == "true"
HIGH = "2" if ENABLED else "1"
JAR = os.path.join(ROOT, "target", "continuum-keycloak-spi.jar")
CLIENT, SECRET = "bff-spike", "spike-only-secret"           # throwaway realm, dev only
PASSWORD, OTP_SECRET = "Spike-Only-Passw0rd!", "spike-only-totp-seed-0123456789"


def realm(name, otp_flow_requirement="CONDITIONAL", loa_config=True):
    flow = "dg-loa"
    executions = [
        {"authenticator": "direct-grant-validate-username", "requirement": "REQUIRED", "priority": 10, "authenticatorFlow": False, "userSetupAllowed": False},
        {"authenticator": "direct-grant-validate-password", "requirement": "REQUIRED", "priority": 20, "authenticatorFlow": False, "userSetupAllowed": False},
        {"flowAlias": "dg-loa-otp", "requirement": otp_flow_requirement, "priority": 30, "authenticatorFlow": True, "userSetupAllowed": False},
        {"authenticator": "continuum-direct-grant-loa", "requirement": "REQUIRED", "priority": 40, "authenticatorFlow": False, "userSetupAllowed": False},
    ]
    configs = []
    if loa_config:
        executions[3]["authenticatorConfig"] = "dg-loa-2"
        configs.append({"alias": "dg-loa-2", "config": {"loa": "2", "requiredAuthenticators": "direct-grant-validate-otp"}})
    otp_cred = {
        "type": "otp", "userLabel": "spike",
        "secretData": json.dumps({"value": OTP_SECRET}),
        "credentialData": json.dumps({"subType": "totp", "digits": 6, "counter": 0, "period": 30, "algorithm": "HmacSHA1"}),
    }
    pwd = {"type": "password", "value": PASSWORD, "temporary": False}
    return {
        "realm": name, "enabled": True,
        "directGrantFlow": flow,  # realm binding: client overrides by alias are not resolvable at --import-realm
        "authenticationFlows": [
            {"alias": flow, "providerId": "basic-flow", "topLevel": True, "builtIn": False, "authenticationExecutions": executions},
            {"alias": "dg-loa-otp", "providerId": "basic-flow", "topLevel": False, "builtIn": False, "authenticationExecutions": [
                {"authenticator": "conditional-user-configured", "requirement": "REQUIRED", "priority": 10, "authenticatorFlow": False, "userSetupAllowed": False},
                {"authenticator": "direct-grant-validate-otp", "requirement": "REQUIRED", "priority": 20, "authenticatorFlow": False, "userSetupAllowed": False},
            ]},
        ],
        "authenticatorConfig": configs,
        "clients": [{
            "clientId": CLIENT, "enabled": True, "publicClient": False, "secret": SECRET,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": True, "serviceAccountsEnabled": False,
            "attributes": {"acr.loa.map": json.dumps({"1": 1, "2": 2})},
            "defaultClientScopes": ["basic", "acr"],
        }],
        "users": [
            {"username": "otp.user", "enabled": True, "email": "otp.user@spike.invalid", "emailVerified": True,
             "firstName": "Otp", "lastName": "User", "credentials": [pwd, otp_cred]},
            {"username": "pwd.user", "enabled": True, "email": "pwd.user@spike.invalid", "emailVerified": True,
             "firstName": "Pwd", "lastName": "User", "credentials": [pwd]},
        ],
    }


def totp(offset=0):
    counter = int(time.time() // 30) + offset
    digest = hmac.new(OTP_SECRET.encode(), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def token(realm_name, **form):
    data = {"client_id": CLIENT, "client_secret": SECRET, "scope": "openid"}
    data.update(form)
    req = urllib.request.Request(f"{BASE}/realms/{realm_name}/protocol/openid-connect/token",
                                 data=urllib.parse.urlencode(data).encode(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def claims(jwt):
    part = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def password_login(realm_name, user, password=PASSWORD, otp=None):
    form = {"grant_type": "password", "username": user, "password": password}
    if otp is not None:
        form["totp"] = otp
    return token(realm_name, **form)


results = []


def check(label, ok, detail=""):
    results.append(ok)
    print(("OK   " if ok else "FAIL ") + label + (f"  [{detail}]" if detail and not ok else ""))


def acr_of(resp):
    status, body = resp
    return claims(body["access_token"]).get("acr") if status == 200 else f"HTTP {status} {body.get('error')}"


def wait_ready():
    for _ in range(90):
        try:
            with urllib.request.urlopen(f"{BASE}/realms/dgloa-nocfg/.well-known/openid-configuration", timeout=5):
                return
        except Exception:
            time.sleep(2)
    raise SystemExit("Keycloak did not become ready")


def main():
    if not os.path.isfile(JAR):
        raise SystemExit("build first: mvn -q package")
    tmp = tempfile.mkdtemp(prefix="dgloa-")
    for r in (realm("dgloa"), realm("dgloa-drift", otp_flow_requirement="DISABLED"), realm("dgloa-nocfg", loa_config=False)):
        with open(os.path.join(tmp, r["realm"] + "-realm.json"), "w", encoding="utf-8") as f:
            json.dump(r, f)
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", NAME, "-p", f"{PORT}:8080",
                    "-v", f"{JAR}:/opt/keycloak/providers/continuum-keycloak-spi.jar:ro",
                    "-v", f"{tmp}:/opt/keycloak/data/import:ro",
                    IMAGE, "start-dev", "--import-realm",
                    f"--spi-authenticator--continuum-direct-grant-loa--raise-loa={str(ENABLED).lower()}"], check=True, capture_output=True)
    try:
        wait_ready()
        # Nominal flow
        ok = password_login("dgloa", "otp.user", otp=totp())
        check(f"password + valid OTP -> acr {HIGH} (enabled={ENABLED})", acr_of(ok) == HIGH, acr_of(ok))
        if ok[0] == 200:
            ref = token("dgloa", grant_type="refresh_token", refresh_token=ok[1]["refresh_token"])
            check(f"refresh keeps acr {HIGH}", acr_of(ref) == HIGH, acr_of(ref))
        r = password_login("dgloa", "otp.user")
        check("OTP user without OTP -> refused", r[0] == 401 and r[1].get("error") == "invalid_grant", acr_of(r))
        r = password_login("dgloa", "otp.user", otp="000000" if totp() != "000000" else "111111")
        check("wrong OTP -> refused", r[0] == 401, acr_of(r))
        r = password_login("dgloa", "otp.user", password="wrong-" + PASSWORD, otp=totp())
        check("wrong password + valid OTP -> refused", r[0] == 401, acr_of(r))
        r = password_login("dgloa", "pwd.user")
        check("user without OTP -> acr 1", acr_of(r) == "1", acr_of(r))
        r = password_login("dgloa", "pwd.user", password="wrong-" + PASSWORD)
        check("user without OTP, wrong password -> refused", r[0] == 401, acr_of(r))
        # Drift: OTP step disabled -> never acr 2
        r = password_login("dgloa-drift", "otp.user", otp=totp())
        check("drift (OTP sub-flow disabled) -> acr 1, not 2", acr_of(r) == "1", acr_of(r))
        # Missing config -> never acr 2
        r = password_login("dgloa-nocfg", "otp.user", otp=totp())
        check("no LoA config -> acr 1, not 2", acr_of(r) == "1", acr_of(r))
    finally:
        if not os.environ.get("KC_KEEP"):  # KC_KEEP=1 keeps the container for `docker logs`
            subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
    print(f"{sum(results)}/{len(results)} OK")
    sys.exit(0 if results and all(results) else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
warp-pool — держит N туннелей до Cloudflare WARP (WireGuard, AmneziaWG или MASQUE) и сам их чинит.

Каждый туннель — отдельный интерфейс (wpool1..N) со своим WARP-аккаунтом,
своей таблицей маршрутизации и правилом `ip rule oif <iface>`. Xray использует
их через freedom-outbound с sockopt.interface, трафик через демон не идёт.

Логика починки туннеля:
  FAIL_THRESHOLD неудачных проб подряд
    -> сменить эндпоинт (до ENDPOINT_TRIES раз, ключи те же)
    -> перерегистрировать аккаунт (не чаще REG_COOLDOWN на туннель
       и не больше MAX_REG_PER_HOUR на весь хост)
  Если лежат ВСЕ туннели сразу — это сеть хоста, а не WARP: ничего не трогаем.

Команды:  run (по умолчанию) | status | xray | down | import N PRIVKEY V4 [V6] | import N USQUE_CONFIG.json
"""
import base64
import json
import logging
import os
import random
import signal
import subprocess
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path


def env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------- настройки
TUNNELS = env_int("WARP_TUNNELS", 3)
# ENGINE=wg  — ядерный WireGuard хоста (быстро, переживает рестарт контейнера без разрыва)
# ENGINE=awg — AmneziaWG в userspace (amneziawg-go в контейнере): мусорные пакеты перед handshake,
#              ТСПУ не узнаёт WireGuard. Для РФ-хостов. Параметры S/H совместимы с Cloudflare.
# ENGINE=masque — WARP по MASQUE (usque в контейнере). По умолчанию HTTP/2 поверх TCP/443 с подменённым
#              SNI: там, где ТСПУ режет любой UDP до Cloudflare (WG/AWG/QUIC умирают после ~20 пакетов).
ENGINE = os.environ.get("ENGINE", "wg").strip().lower()
if ENGINE not in ("wg", "awg", "masque"):
    sys.exit(f"ENGINE={ENGINE}: допустимо wg, awg или masque")
USERSPACE = ENGINE in ("awg", "masque")  # туннель живёт, пока жив процесс в контейнере
WG_BIN = "awg" if ENGINE == "awg" else "wg"
AWG_JC = env_int("AWG_JC", 4)
AWG_JMIN = env_int("AWG_JMIN", 40)
AWG_JMAX = env_int("AWG_JMAX", 70)
MASQUE_HTTP2 = env_bool("MASQUE_HTTP2", True)                       # 0 — HTTP/3 (QUIC, UDP)
MASQUE_SNI = os.environ.get("MASQUE_SNI", "www.cloudflare.com").strip()  # пусто — родной consumer-masque.*
MASQUE_ENDPOINT = os.environ.get("MASQUE_ENDPOINT", "").strip()     # пусто — 162.159.198.2 (h2) / из аккаунта (h3)
MASQUE_PORT = env_int("MASQUE_PORT", 443)
# Регистрация аккаунтов: напрямую, через HTTP-прокси и/или через уже живой туннель пула.
REG_DIRECT = env_bool("REG_DIRECT", True)
REG_PROXY = os.environ.get("REG_PROXY", "").strip()      # напр. http://127.0.0.1:10809 (HTTP-инбаунд xray → каскад)
REG_VIA_TUNNEL = env_bool("REG_VIA_TUNNEL", True)
WARP_PEER_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
IFACE_PREFIX = os.environ.get("IFACE_PREFIX", "wpool")
TABLE_BASE = env_int("TABLE_BASE", 5100)          # таблица = TABLE_BASE + N
RULE_PRIO_BASE = env_int("RULE_PRIO_BASE", 5100)  # приоритет ip rule = RULE_PRIO_BASE + N
MTU = env_int("MTU", 1280)
KEEPALIVE = env_int("KEEPALIVE", 25)
ENABLE_IPV6 = env_bool("ENABLE_IPV6", True)

# ENDPOINTS=auto (по умолчанию) — адреса берутся сами из подсетей WARP, нерабочие запоминаются.
# ENDPOINTS=ip:port,ip:port,... — фиксированный список, как раньше.
_EP_RAW = os.environ.get("ENDPOINTS", "auto").strip()
AUTO_ENDPOINTS = _EP_RAW.lower() in ("", "auto")
FIXED_ENDPOINTS = [] if AUTO_ENDPOINTS else [e.strip() for e in _EP_RAW.split(",") if e.strip()]
# для перевода старого state.json (endpoint_idx) — список по умолчанию прошлых версий
LEGACY_ENDPOINTS = ("162.159.192.1:2408,162.159.193.10:2408,162.159.195.1:2408,188.114.96.1:1701,188.114.97.1:1701,"
                    "188.114.98.1:2408,188.114.99.1:2408,162.159.192.5:1701,162.159.193.1:1701,162.159.195.10:1701").split(",")
AUTO_SUBNETS = [x.strip() for x in os.environ.get(
    "AUTO_SUBNETS",
    "162.159.192.0/24,162.159.193.0/24,162.159.195.0/24,188.114.96.0/24,188.114.97.0/24,188.114.98.0/24,188.114.99.0/24",
).split(",") if x.strip()]
AUTO_PORTS = [int(x) for x in os.environ.get(
    "AUTO_PORTS", "2408,1701,500,4500,854,878,894,908,928,987,1002,2371,7559,8854").split(",") if x.strip()]
BAD_ENDPOINT_TTL = env_int("BAD_ENDPOINT_TTL", 6 * 3600)  # сколько не выдавать эндпоинт, на котором туннель лёг
BAD_PORT_AFTER = env_int("BAD_PORT_AFTER", 3)            # столько разных IP легли на одном порту → порт в бан

PROBE_URL = os.environ.get("PROBE_URL", "https://www.cloudflare.com/cdn-cgi/trace")
PROBE_INTERVAL = env_int("PROBE_INTERVAL", 30)
PROBE_TIMEOUT = env_int("PROBE_TIMEOUT", 8)
FAIL_THRESHOLD = env_int("FAIL_THRESHOLD", 3)
ENDPOINT_TRIES = env_int("ENDPOINT_TRIES", 2)
ACTION_COOLDOWN = env_int("ACTION_COOLDOWN", 120)
REG_COOLDOWN = env_int("REG_COOLDOWN", 600)
MAX_REG_PER_HOUR = env_int("MAX_REG_PER_HOUR", 6)

HOST_NAME = os.environ.get("HOST_NAME", os.uname().nodename)
SUMMARY_INTERVAL = env_int("SUMMARY_INTERVAL", 600)
DEAD_ACCOUNT_AFTER = env_int("DEAD_ACCOUNT_AFTER", 300)  # сек без единого handshake → аккаунт битый

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
STATE_PATH = DATA_DIR / "state.json"
STATUS_PATH = DATA_DIR / "status.json"
RUN_DIR = Path(os.environ.get("RUN_DIR", "/run/warp-pool"))

DRY_RUN = env_bool("DRY_RUN", False)
MAX_LOOPS = env_int("MAX_LOOPS", 0)  # 0 = бесконечно; >0 только для тестов
DRY_FAIL_PLAN = os.environ.get("DRY_FAIL_PLAN", "")  # тесты: "1:3-8,*:12-14" (туннель:циклы)

API = "https://api.cloudflareclient.com/v0a4471"
API_HEADERS = {
    "User-Agent": "WARP for Android",
    "CF-Client-Version": "a-6.35-4471",
    "Content-Type": "application/json; charset=UTF-8",
}

log = logging.getLogger("warp-pool")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")


def now() -> float:
    return time.time()


def iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or now(), timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- shell
class CmdError(RuntimeError):
    pass


def run(cmd: list[str], check: bool = True, stdin: str | None = None) -> str:
    if DRY_RUN:
        log.debug("DRY: %s", " ".join(cmd))
        return ""
    p = subprocess.run(cmd, input=stdin, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise CmdError(f"{' '.join(cmd)} -> rc={p.returncode}: {p.stderr.strip()}")
    return p.stdout


def ok(cmd: list[str]) -> bool:
    if DRY_RUN:
        return False
    return subprocess.run(cmd, capture_output=True).returncode == 0


def keypair() -> tuple[str, str]:
    if DRY_RUN:
        return (base64.b64encode(os.urandom(32)).decode(), base64.b64encode(os.urandom(32)).decode())
    priv = run([WG_BIN, "genkey"]).strip()
    pub = run([WG_BIN, "pubkey"], stdin=priv + "\n").strip()
    return priv, pub


# ---------------------------------------------------------------- Cloudflare API
class RegError(RuntimeError):
    pass


def api(method: str, path: str, body: dict | None = None, token: str | None = None,
        route: str = "direct") -> dict:
    """Запрос к API WARP через curl. route: direct | proxy | <имя интерфейса туннеля>."""
    cmd = ["curl", "-sS", "--connect-timeout", "8", "-m", "20", "-X", method, "-w", "\n%{http_code}"]
    for k, v in API_HEADERS.items():
        cmd += ["-H", f"{k}: {v}"]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    if route == "proxy":
        cmd += ["-x", REG_PROXY]
    elif route != "direct":
        cmd += ["--interface", route]
    if body is not None:
        cmd += ["--data-binary", "@-"]
    cmd.append(f"{API}/{path}")
    p = subprocess.run(cmd, input=json.dumps(body) if body is not None else None, capture_output=True, text=True)
    if p.returncode != 0:
        raise RegError(f"{route}: curl rc={p.returncode} {p.stderr.strip()[:150]}")
    raw, _, code = p.stdout.rpartition("\n")
    if not code.startswith("2"):
        raise RegError(f"{route}: HTTP {code} {raw[:150]}")
    return json.loads(raw) if raw.strip() else {}


def register_account(routes: list[str]) -> dict:
    """Новый WARP-аккаунт. Пробует маршруты по очереди. Приватный ключ живёт только в state.json."""
    if not routes:
        raise RegError("нет маршрутов для регистрации (REG_DIRECT=0, нет REG_PROXY и живых туннелей)")
    priv, pub = keypair()
    if DRY_RUN:
        return {"id": f"dry-{random.randint(1000, 9999)}", "token": "dry", "private_key": priv,
                "peer_public_key": WARP_PEER_KEY,
                "v4": "172.16.0.2", "v6": "2606:4700:110:8000::1", "registered_at": iso(), "route": routes[0]}
    body = {
        "key": pub, "install_id": "", "fcm_token": "",
        "tos": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "type": "Android", "model": "PC", "locale": "en_US",
    }
    errors = []
    for route in routes:
        try:
            res = api("POST", "reg", body, route=route)
            acc_id, token = res["id"], res["token"]
            cfg = res.get("config") or api("GET", f"reg/{acc_id}", token=token, route=route)["config"]
            try:  # на старых версиях API аккаунт создавался выключенным
                api("PATCH", f"reg/{acc_id}", {"warp_enabled": True}, token=token, route=route)
            except RegError as e:
                log.debug("PATCH warp_enabled: %s", e)
            addrs, peer = cfg["interface"]["addresses"], cfg["peers"][0]
            acc = {"id": acc_id, "token": token, "private_key": priv,
                   "peer_public_key": peer["public_key"],
                   "v4": addrs["v4"], "v6": addrs.get("v6"), "registered_at": iso(), "route": route}
            return enroll_masque(acc, route) if ENGINE == "masque" else acc
        except (RegError, KeyError, ValueError, CmdError) as e:
            errors.append(str(e))
    raise RegError("; ".join(errors))


def ec_keypair() -> tuple[str, str]:
    """P-256 для MASQUE: (SEC1 DER, PKIX DER) в base64 — так их ждут usque и API."""
    pem = run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout"])
    der = lambda args: base64.b64encode(subprocess.run(  # noqa: E731
        ["openssl", "ec", "-outform", "DER", *args], input=pem.encode(), capture_output=True, check=True).stdout).decode()
    return der([]), der(["-pubout"])


def enroll_masque(acc: dict, route: str) -> dict:
    """Перевести аккаунт на MASQUE: свой P-256 ключ вместо WireGuard. ID/токен/адреса те же."""
    if DRY_RUN:
        return {**acc, "type": "masque", "peer_public_key": "dry-pem", "endpoint_v4": "162.159.198.1"}
    priv, pub = ec_keypair()
    res = api("PATCH", f"reg/{acc['id']}", {"key": pub, "key_type": "secp256r1", "tunnel_type": "masque"},
              token=acc["token"], route=route)
    cfg = res["config"]
    addrs, peer = cfg["interface"]["addresses"], cfg["peers"][0]
    return {**acc, "type": "masque", "private_key": priv, "peer_public_key": peer["public_key"],
            "v4": addrs["v4"], "v6": addrs.get("v6"),
            "endpoint_v4": peer["endpoint"]["v4"].rsplit(":", 1)[0],
            "endpoint_v6": peer["endpoint"].get("v6", "").rsplit(":", 1)[0].strip("[]")}


def is_engine_account(acc: dict | None) -> bool:
    """Аккаунт подходит движку: у MASQUE свой тип ключа, WG-аккаунт для него не годится, и наоборот."""
    return bool(acc) and (acc.get("type") == "masque") == (ENGINE == "masque")


def masque_endpoint(acc: dict | None = None) -> str:
    ep = MASQUE_ENDPOINT or ("162.159.198.2" if MASQUE_HTTP2 else (acc or {}).get("endpoint_v4") or "162.159.198.1")
    return f"{ep}:{MASQUE_PORT}"


def unregister_account(acc: dict, routes: list[str]) -> None:
    if DRY_RUN or not acc or not acc.get("id"):
        return
    for route in routes:
        try:
            api("DELETE", f"reg/{acc['id']}", token=acc["token"], route=route)
            return
        except RegError as e:  # гигиена, не критично
            log.debug("DELETE reg %s: %s", acc.get("id"), e)


# ---------------------------------------------------------------- интерфейсы
_PROCS: dict[str, subprocess.Popen] = {}
_PROC_KEYS: dict[str, str] = {}  # masque: с каким приватным ключом запущен usque


def create_iface(name: str, acc: dict | None = None) -> None:
    """wg: ядерный интерфейс. awg: процесс amneziawg-go, который создаёт tun с этим именем.
    masque: процесс usque с конфигом аккаунта; без аккаунта — пустой tun-заглушка."""
    if ENGINE == "wg":
        run(["ip", "link", "add", "dev", name, "type", "wireguard"])
        return
    if ENGINE == "masque" and not acc:
        run(["ip", "tuntap", "add", "dev", name, "mode", "tun"])
        return
    if ENGINE == "masque":
        cmd = ["usque", "-c", str(masque_conf(name, acc)), "nativetun", "-n", name, "-I", "-m", str(MTU),
               "-P", str(MASQUE_PORT), "--always-reconnect"]
        if MASQUE_HTTP2:
            cmd.append("--http2")
        if MASQUE_SNI:
            cmd += ["-s", MASQUE_SNI]
    else:
        cmd = ["amneziawg-go", "-f", name]
    if DRY_RUN:
        log.debug("DRY: %s", " ".join(cmd))
        return
    old = _PROCS.pop(name, None)
    if old and old.poll() is None:
        old.terminate()
        try:
            old.wait(5)
        except subprocess.TimeoutExpired:
            old.kill()
    _PROCS[name] = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _PROC_KEYS[name] = (acc or {}).get("private_key", "")
    for _ in range(50):
        if ok(["ip", "link", "show", "dev", name]):
            return
        time.sleep(0.1)
    raise CmdError(f"{cmd[0]} не создал интерфейс {name}")


def masque_conf(name: str, acc: dict) -> Path:
    """Конфиг usque (читается при старте процесса). Лежит в RUN_DIR внутри контейнера, права 0600."""
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    conf = RUN_DIR / f"{name}.json"
    ep = masque_endpoint(acc).rsplit(":", 1)[0]
    conf.write_text(json.dumps({
        "private_key": acc["private_key"], "endpoint_pub_key": acc["peer_public_key"],
        "endpoint_v4": ep if not MASQUE_HTTP2 else acc.get("endpoint_v4", ""),
        "endpoint_v6": acc.get("endpoint_v6", ""),
        "endpoint_h2_v4": ep if MASQUE_HTTP2 else "", "endpoint_h2_v6": "",
        "id": acc.get("id") or "", "access_token": acc.get("token") or "", "license": "",
        "ipv4": acc["v4"], "ipv6": acc.get("v6") or "",
    }))
    conf.chmod(0o600)
    return conf


def iface_alive(name: str) -> bool:
    if not ok(["ip", "link", "show", "dev", name]):
        return False
    if USERSPACE:  # tun без своего процесса — мёртвая оболочка
        pr = _PROCS.get(name)
        return bool(pr and pr.poll() is None)
    return True


def awg_interface_lines() -> str:
    if ENGINE != "awg":
        return ""
    # S1..S4=0 и H1..H4=1..4 — стандартный WireGuard, иначе Cloudflare не поймёт; мусор только Jc/Jmin/Jmax.
    return (f"Jc = {AWG_JC}\nJmin = {AWG_JMIN}\nJmax = {AWG_JMAX}\n"
            "S1 = 0\nS2 = 0\nS3 = 0\nS4 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n")


# ---------------------------------------------------------------- события
def notify(event: str, tunnel: str | None, message: str, pool: "Pool | None" = None) -> None:
    lvl = logging.WARNING if event in ("register_failed", "rotation_blocked", "all_down") else logging.INFO
    log.log(lvl, "[%s] %s%s", event, f"{tunnel}: " if tunnel else "", message)


# ---------------------------------------------------------------- туннель
class Tunnel:
    def __init__(self, n: int, st: dict):
        self.n = n
        self.name = f"{IFACE_PREFIX}{n}"
        self.table = TABLE_BASE + n
        self.prio = RULE_PRIO_BASE + n
        self.account: dict | None = st.get("account")
        self.endpoint: str | None = st.get("endpoint") or _migrate_endpoint(st.get("endpoint_idx"))
        self.last_reg: float = st.get("last_reg", 0.0)
        self.rotations: int = st.get("rotations", 0)
        # оперативное состояние
        self.fails = 0
        self.endpoint_changes = 0
        self.last_action = 0.0
        self.last_ok: float | None = None
        self.latency_ms: int | None = None
        self.colo: str | None = None
        self.exit_ip: str | None = None
        self.up = False
        self.degraded = False  # был признан лежащим — чтобы сообщить о восстановлении
        self.applied_at = 0.0  # когда интерфейс получил текущие ключи
        self.blocked_notified = 0.0

    def persist(self) -> dict:
        return {"account": self.account, "endpoint": self.endpoint,
                "last_reg": self.last_reg, "rotations": self.rotations}

    def summary(self) -> dict:
        return {"tunnel": self.name, "up": self.up, "latency_ms": self.latency_ms,
                "colo": self.colo, "exit_ip": self.exit_ip, "endpoint": self.endpoint,
                "fails": self.fails, "rotations": self.rotations,
                "last_ok": iso(self.last_ok) if self.last_ok else None,
                "account_since": (self.account or {}).get("registered_at")}

    # --- сеть
    def apply(self) -> None:
        """Создать/обновить интерфейс, ключи, адреса и policy routing. Идемпотентно."""
        acc = self.account
        assert acc, "нет аккаунта"
        if ENGINE == "masque":
            if not iface_alive(self.name) or _PROC_KEYS.get(self.name) != acc["private_key"]:
                run(["ip", "link", "del", "dev", self.name], check=False)
                create_iface(self.name, acc)
            self.endpoint = masque_endpoint(acc)
            run(["ip", "-4", "addr", "flush", "dev", self.name])
            run(["ip", "-4", "addr", "add", f"{acc['v4']}/32", "dev", self.name])
            run(["ip", "link", "set", "dev", self.name, "mtu", str(MTU), "up"])
            self.applied_at = now()
            self._ensure_routes(set_v6_addr=True)
            return
        if not iface_alive(self.name):
            run(["ip", "link", "del", "dev", self.name], check=False)
            create_iface(self.name)
        elif self._same_keys():
            # Рестарт контейнера: интерфейс уже с этими ключами — не рвём сессию, только проверяем маршруты.
            live_ep = self._live_endpoint()
            if not self.endpoint and live_ep:
                self.endpoint = live_ep
            elif self.endpoint and live_ep != self.endpoint:
                self.set_endpoint()
            self._ensure_routes()
            self.applied_at = now()
            return

        RUN_DIR.mkdir(parents=True, exist_ok=True)
        conf = RUN_DIR / f"{self.name}.conf"
        conf.write_text(
            "[Interface]\n"
            f"PrivateKey = {acc['private_key']}\n"
            f"{awg_interface_lines()}\n"
            "[Peer]\n"
            f"PublicKey = {acc['peer_public_key']}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            f"Endpoint = {self.endpoint}\n"
            f"PersistentKeepalive = {KEEPALIVE}\n"
        )
        conf.chmod(0o600)
        try:
            run([WG_BIN, "setconf", self.name, str(conf)])  # заменяет конфиг целиком, старый peer уходит
        finally:
            conf.unlink(missing_ok=True)

        run(["ip", "-4", "addr", "flush", "dev", self.name])
        run(["ip", "-4", "addr", "add", f"{acc['v4']}/32", "dev", self.name])
        run(["ip", "link", "set", "dev", self.name, "mtu", str(MTU), "up"])
        self.applied_at = now()
        self._ensure_routes(set_v6_addr=True)

    def _live_endpoint(self) -> str | None:
        out = run([WG_BIN, "show", self.name, "endpoints"], check=False).split()
        return out[1] if len(out) >= 2 and out[1] != "(none)" else None

    def _same_keys(self) -> bool:
        if DRY_RUN:
            return False
        cur_priv = run([WG_BIN, "show", self.name, "private-key"], check=False).strip()
        peers = run([WG_BIN, "show", self.name, "peers"], check=False).split()
        return cur_priv == self.account["private_key"] and peers == [self.account["peer_public_key"]]

    def _ensure_routes(self, set_v6_addr: bool = False) -> None:
        acc = self.account
        run(["ip", "link", "set", "dev", self.name, "up"])
        run(["ip", "-4", "route", "replace", "default", "dev", self.name, "table", str(self.table)])
        self._ensure_rule("-4")
        global ENABLE_IPV6
        if ENABLE_IPV6 and acc.get("v6"):
            try:
                if set_v6_addr:
                    run(["ip", "-6", "addr", "flush", "dev", self.name, "scope", "global"])
                    run(["ip", "-6", "addr", "add", f"{acc['v6']}/128", "dev", self.name])
                run(["ip", "-6", "route", "replace", "default", "dev", self.name, "table", str(self.table)])
                self._ensure_rule("-6")
            except CmdError as e:
                ENABLE_IPV6 = False
                log.warning("IPv6 в туннелях отключён (на хосте нет IPv6?): %s", e)

    def _ensure_rule(self, fam: str) -> None:
        if DRY_RUN:
            return
        rules = run(["ip", fam, "rule", "show", "pref", str(self.prio)], check=False)
        if f"oif {self.name}" in rules and f"lookup {self.table}" in rules:
            return
        run(["ip", fam, "rule", "del", "pref", str(self.prio)], check=False)
        run(["ip", fam, "rule", "add", "pref", str(self.prio), "oif", self.name, "lookup", str(self.table)])

    def ensure_blackhole(self) -> None:
        """Туннель без аккаунта: интерфейс без peer + маршрут в него. Xray, привязанный к нему,
        не выйдет напрямую с IP хоста — пакеты просто пропадут (fail-closed)."""
        if not iface_alive(self.name):
            run(["ip", "link", "del", "dev", self.name], check=False)
            create_iface(self.name)
        run(["ip", "link", "set", "dev", self.name, "mtu", str(MTU), "up"])
        run(["ip", "-4", "route", "replace", "default", "dev", self.name, "table", str(self.table)])
        self._ensure_rule("-4")
        run(["ip", "-6", "route", "replace", "default", "dev", self.name, "table", str(self.table)], check=False)
        if ENABLE_IPV6:
            self._ensure_rule("-6")

    def set_endpoint(self) -> None:
        run([WG_BIN, "set", self.name, "peer", self.account["peer_public_key"], "endpoint", self.endpoint])

    def teardown(self) -> None:
        for fam in ("-4", "-6"):
            run(["ip", fam, "rule", "del", "pref", str(self.prio)], check=False)
            run(["ip", fam, "route", "flush", "table", str(self.table)], check=False)
        run(["ip", "link", "del", "dev", self.name], check=False)

    def handshake_age(self) -> int | None:
        """Секунд с последнего handshake; None — handshake с этим ключом не было ни разу."""
        if DRY_RUN:
            return 5
        if ENGINE == "masque":  # у usque нет счётчика handshake; битый аккаунт ловится по соседям
            return 0
        out = run([WG_BIN, "show", self.name, "latest-handshakes"], check=False).split()
        if len(out) >= 2 and out[1].isdigit() and int(out[1]) > 0:
            return int(now()) - int(out[1])
        return None

    # --- проба
    def probe(self, loop_no: int) -> bool:
        if DRY_RUN:
            up = not dry_should_fail(self.n, loop_no)
            self.latency_ms, self.colo, self.exit_ip = (random.randint(20, 90), "FRA", "104.28.0.1") if up else (None, None, None)
            return up
        p = subprocess.run(
            ["curl", "-sS", "--interface", self.name, "-m", str(PROBE_TIMEOUT),
             "-w", "\n__t=%{time_total}", PROBE_URL],
            capture_output=True, text=True)
        fields = dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)
        up = p.returncode == 0 and fields.get("warp") in ("on", "plus")
        if up:
            self.latency_ms = int(float(fields.get("__t", "0")) * 1000)
            self.colo, self.exit_ip = fields.get("colo"), fields.get("ip")
        else:
            self.latency_ms = None
            log.debug("%s: probe fail rc=%s warp=%s err=%s", self.name, p.returncode,
                      fields.get("warp"), p.stderr.strip()[:200])
        return up


def dry_should_fail(n: int, loop_no: int) -> bool:
    """DRY_FAIL_PLAN="1:3-8,*:12-14" — туннель 1 лежит на циклах 3..8, все — на 12..14."""
    for part in filter(None, DRY_FAIL_PLAN.split(",")):
        who, rng = part.split(":")
        a, b = (int(x) for x in rng.split("-"))
        if (who == "*" or int(who) == n) and a <= loop_no <= b:
            return True
    return False


# ---------------------------------------------------------------- эндпоинты
def _subnet(ep: str) -> str:
    return ep.rsplit(":", 1)[0].rsplit(".", 1)[0]


def _port(ep: str) -> str:
    return ep.rsplit(":", 1)[1]


def _migrate_endpoint(idx) -> str | None:
    """Старый state хранил индекс в списке; переводим в адрес."""
    if idx is None:
        return None
    lst = FIXED_ENDPOINTS or LEGACY_ENDPOINTS
    return lst[int(idx) % len(lst)]


class EndpointBook:
    """Какие эндпоинты работали (good) и какие временно в бане (bad). Живёт в state.json."""

    def __init__(self, st: dict):
        self.good: dict[str, float] = dict(st.get("good", {}))
        self.bad: dict[str, float] = dict(st.get("bad", {}))

    def dump(self) -> dict:
        self._prune()
        return {"good": self.good, "bad": self.bad}

    def stats(self) -> dict:
        self._prune()
        ports = sorted({_port(e) for e in self.bad if self.port_banned(_port(e))})
        return {"mode": "auto" if AUTO_ENDPOINTS else "fixed", "known_good": len(self.good),
                "banned": sorted(self.bad), "banned_ports": ports}

    def _prune(self) -> None:
        t = now()
        self.bad = {e: u for e, u in self.bad.items() if u > t}
        if len(self.good) > 50:
            self.good = dict(sorted(self.good.items(), key=lambda kv: kv[1], reverse=True)[:50])

    def size(self) -> int:
        if ENGINE == "masque":  # эндпоинт у MASQUE один на всех — менять нечего
            return 1
        return len(FIXED_ENDPOINTS) if FIXED_ENDPOINTS else 10**6

    def port_banned(self, port: str) -> bool:
        t = now()
        ips = {e.rsplit(":", 1)[0] for e, u in self.bad.items() if u > t and _port(e) == port}
        return AUTO_ENDPOINTS and len(ips) >= BAD_PORT_AFTER

    def is_bad(self, ep: str) -> bool:
        return self.bad.get(ep, 0) > now() or self.port_banned(_port(ep))

    def mark_good(self, ep: str | None) -> None:
        if ep and ENGINE != "masque":
            self.good[ep] = now()
            self.bad.pop(ep, None)

    def mark_bad(self, ep: str | None) -> None:
        if not ep:
            return
        self.good.pop(ep, None)
        self.bad[ep] = now() + BAD_ENDPOINT_TTL
        log.info("[endpoint_banned] %s не выдаётся %d ч%s", ep, BAD_ENDPOINT_TTL // 3600,
                 f"; порт {_port(ep)} в бане целиком" if self.port_banned(_port(ep)) else "")

    def pick(self, busy: set, avoid_subnets: set, after: str | None) -> str:
        ok = lambda e: e not in busy and not self.is_bad(e)  # noqa: E731
        if FIXED_ENDPOINTS:
            lst = FIXED_ENDPOINTS
            start = lst.index(after) + 1 if after in lst else 0
            ring = [lst[(start + i) % len(lst)] for i in range(len(lst))]
            for cond in (lambda e: ok(e) and _subnet(e) not in avoid_subnets, ok, lambda e: e not in busy):
                for e in ring:
                    if cond(e):
                        return e
            return ring[0]
        # auto: сначала проверенные рабочие, потом случайные новые
        for e, _ in sorted(self.good.items(), key=lambda kv: kv[1], reverse=True):
            if ok(e) and _subnet(e) not in avoid_subnets:
                return e
        ports = [p for p in AUTO_PORTS if not self.port_banned(str(p))] or AUTO_PORTS
        for attempt in range(400):
            net = random.choice(AUTO_SUBNETS)
            base = net.split("/")[0].rsplit(".", 1)[0]
            e = f"{base}.{random.randint(1, 254)}:{random.choice(ports)}"
            if ok(e) and (attempt >= 200 or _subnet(e) not in avoid_subnets):
                return e
        return f"{AUTO_SUBNETS[0].split('/')[0].rsplit('.', 1)[0]}.1:2408"


# ---------------------------------------------------------------- пул
class Pool:
    def __init__(self):
        st = self._load()
        self.tunnels = [Tunnel(n, st.get("tunnels", {}).get(str(n), {})) for n in range(1, TUNNELS + 1)]
        self.reg_times: deque[float] = deque(st.get("reg_times", []))
        self.book = EndpointBook(st.get("endpoints", {}))
        self.all_down_notified = 0.0
        self.stopping = False
        self.last_summary = 0.0
        self.last_up_set: tuple | None = None

    # --- состояние
    @staticmethod
    def _load() -> dict:
        try:
            return json.loads(STATE_PATH.read_text())
        except FileNotFoundError:
            return {}
        except Exception as e:  # noqa: BLE001
            log.error("state.json повреждён (%s), начинаю с чистого листа", e)
            return {}

    def save(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "tunnels": {str(t.n): t.persist() for t in self.tunnels},
            "reg_times": list(self.reg_times),
            "endpoints": self.book.dump(),
        }, indent=2))
        tmp.chmod(0o600)
        tmp.replace(STATE_PATH)

    def write_status(self) -> None:
        STATUS_PATH.write_text(json.dumps({"host": HOST_NAME, "updated": iso(),
                                           "tunnels": self.summary(),
                                           "endpoints": self.book.stats()}, indent=2))

    def summary(self) -> list[dict]:
        return [t.summary() for t in self.tunnels]

    # --- регистрации
    def reg_budget_left(self) -> int:
        cutoff = now() - 3600
        while self.reg_times and self.reg_times[0] < cutoff:
            self.reg_times.popleft()
        return MAX_REG_PER_HOUR - len(self.reg_times)

    def new_account(self, t: Tunnel) -> bool:
        if self.reg_budget_left() <= 0:
            free_at = datetime.fromtimestamp(self.reg_times[0] + 3600).strftime("%H:%M") if self.reg_times else "?"
            log.warning("%s: лимит регистраций (%d/час) исчерпан, следующая попытка не раньше %s",
                        t.name, MAX_REG_PER_HOUR, free_at)
            return False
        if not t.account:  # новый туннель — сразу на незанятый эндпоинт
            busy = {o.endpoint for o in self.tunnels if o is not t and o.account}
            if not t.endpoint or t.endpoint in busy or self.book.is_bad(t.endpoint):
                t.endpoint = self.pick_endpoint(t)
        routes = self.reg_routes(exclude=t)
        if not routes:  # ждём, пока поднимется хоть один туннель — бюджет не тратим
            log.info("%s: регистрировать пока не через что (API напрямую выключен, живых туннелей нет), жду", t.name)
            return False
        try:
            acc = register_account(routes)
        except RegError as e:
            self.reg_times.append(now())  # неудачная попытка тоже тратит бюджет
            notify("register_failed", t.name, f"регистрация не удалась: {e}", self)
            return False
        self.reg_times.append(now())
        old = t.account
        t.account, t.last_reg = acc, now()
        t.apply()
        unregister_account(old, self.reg_routes(exclude=t))
        self.save()
        if acc.get("route", "direct") != "direct":
            log.info("%s: аккаунт зарегистрирован через %s", t.name, acc["route"])
        return True

    def reg_routes(self, exclude: "Tunnel | None" = None) -> list[str]:
        routes = ["direct"] if REG_DIRECT else []
        if REG_PROXY:
            routes.append("proxy")
        if REG_VIA_TUNNEL:
            routes += [o.name for o in self.tunnels if o is not exclude and o.account and o.up]
        return routes

    def pick_endpoint(self, t: Tunnel) -> str:
        """Эндпоинт для туннеля: не занятый соседями, не в бане, по возможности из другой /24."""
        if ENGINE == "masque":
            return masque_endpoint(t.account)
        others = [o.endpoint for o in self.tunnels if o is not t and o.account and o.endpoint]
        avoid = {_subnet(e) for e in others} | ({_subnet(t.endpoint)} if t.endpoint else set())  # и свою упавшую /24
        return self.book.pick(busy=set(others), avoid_subnets=avoid, after=t.endpoint)

    # --- основной цикл
    def bootstrap(self) -> None:
        check_host()
        for t in self.tunnels:
            if t.account and not is_engine_account(t.account):
                # сменили ENGINE между wg/awg и masque: ключ другого типа, нужен новый аккаунт
                log.warning("%s: аккаунт не подходит движку %s — будет зарегистрирован новый", t.name, ENGINE)
                t.account, t.endpoint = None, None
            if not t.account:
                t.ensure_blackhole()  # пока аккаунта нет — интерфейс-заглушка, чтобы xray не утёк мимо WARP
                t.last_action = now()
                if self.new_account(t):
                    notify("account_created", t.name, f"аккаунт создан, эндпоинт {t.endpoint}", self)
                continue
            if not t.endpoint:
                t.endpoint = self.pick_endpoint(t)
            t.apply()
            log.info("%s: поднят из state (эндпоинт %s)", t.name, t.endpoint)
        self.save()

    def tick(self, loop_no: int) -> None:
        for t in self.tunnels:
            if not t.account:  # не смогли зарегистрировать на старте
                if now() - t.last_action >= ACTION_COOLDOWN:
                    t.last_action = now()
                    if self.new_account(t):
                        notify("account_created", t.name, "аккаунт создан (повторная попытка)", self)
                continue
            if USERSPACE and not DRY_RUN and not iface_alive(t.name):
                log.warning("%s: процесс туннеля умер — поднимаю заново", t.name)
                t.apply()
            t.up = t.probe(loop_no)
            if t.up:
                t.last_ok = now()
                self.book.mark_good(t.endpoint)
                if t.degraded:
                    t.degraded = False
                    notify("recovered", t.name, f"туннель снова жив, {t.latency_ms} мс, {t.colo}", self)
                t.fails, t.endpoint_changes = 0, 0
            else:
                t.fails += 1
                if t.fails >= FAIL_THRESHOLD:
                    t.degraded = True

        failing = [t for t in self.tunnels if t.account and t.fails >= FAIL_THRESHOLD]
        live = [t for t in self.tunnels if t.account]
        if live and len(failing) == len(live):
            # Все сразу — проблема хоста/сети, а не аккаунтов. Не жжём регистрации.
            if now() - self.all_down_notified > 3600:
                self.all_down_notified = now()
                notify("all_down", None, "лежат все туннели сразу — похоже на сеть хоста, ротацию не делаю", self)
            return
        self.all_down_notified = 0.0

        for t in failing:
            if now() - t.last_action < ACTION_COOLDOWN:
                continue
            t.last_action = now()
            # Признаки, что виноват аккаунт, а не эндпоинт: смена эндпоинта не поможет.
            no_handshake = t.handshake_age() is None and now() - t.applied_at > DEAD_ACCOUNT_AFTER
            ep_ok_elsewhere = any(o is not t and o.up and o.endpoint == t.endpoint for o in self.tunnels)
            if no_handshake or ep_ok_elsewhere:
                why = "ни одного handshake с этим ключом" if no_handshake else f"эндпоинт {t.endpoint} работает у соседа"
                if self.new_account(t):
                    t.rotations += 1
                    t.fails, t.endpoint_changes = 0, 0
                    self.save()
                    notify("account_rotated", t.name, f"аккаунт битый ({why}), зарегистрирован новый", self)
                elif now() - t.blocked_notified > 3600:
                    t.blocked_notified = now()
                    notify("rotation_blocked", t.name, f"аккаунт битый ({why}), но лимит регистраций исчерпан", self)
                continue
            if t.endpoint_changes < ENDPOINT_TRIES and self.book.size() > 1:
                old = t.endpoint
                self.book.mark_bad(old)
                t.endpoint = self.pick_endpoint(t)
                t.endpoint_changes += 1
                t.set_endpoint()
                t.fails = 0
                self.save()
                notify("endpoint_changed", t.name, f"{old} → {t.endpoint}", self)
            elif now() - t.last_reg >= REG_COOLDOWN and self.new_account(t):
                t.rotations += 1
                t.fails, t.endpoint_changes = 0, 0
                self.save()
                notify("account_rotated", t.name, f"новый аккаунт, эндпоинт {t.endpoint}", self)
            elif now() - t.blocked_notified > 3600:
                t.blocked_notified = now()
                why = ("лимит регистраций исчерпан" if self.reg_budget_left() <= 0
                       else f"прошлая регистрация < {REG_COOLDOWN // 60} мин назад")
                notify("rotation_blocked", t.name, f"туннель лежит, ротация отложена: {why}", self)

    def log_summary(self) -> None:
        """Строка состояния: при первом цикле, при смене набора живых туннелей и раз в SUMMARY_INTERVAL."""
        up_set = tuple(t.up for t in self.tunnels)
        if up_set == self.last_up_set and now() - self.last_summary < SUMMARY_INTERVAL:
            return
        self.last_up_set, self.last_summary = up_set, now()
        parts = []
        for t in self.tunnels:
            if not t.account:
                parts.append(f"{t.name} нет аккаунта")
            elif t.up:
                parts.append(f"{t.name} ✓ {t.latency_ms}мс {t.colo}")
            else:
                parts.append(f"{t.name} ✗ ({t.fails} неудач)")
        log.info("[status] %d/%d живы | %s", sum(up_set), len(self.tunnels), " | ".join(parts))

    def loop(self) -> None:
        self.bootstrap()
        loop_no = 0
        while not self.stopping:
            loop_no += 1
            try:
                self.tick(loop_no)
                self.write_status()
                self.log_summary()
            except Exception:  # noqa: BLE001 — демон не должен падать из-за одной ошибки
                log.exception("ошибка в цикле")
            if MAX_LOOPS and loop_no >= MAX_LOOPS:
                break
            self._sleep(PROBE_INTERVAL)
        self.save()
        log.info("остановлен; интерфейсы оставлены работать")

    def _sleep(self, sec: float) -> None:
        end = now() + sec
        while not self.stopping and now() < end:
            time.sleep(min(1.0, max(0.0, end - now())))


# ---------------------------------------------------------------- проверки хоста
def check_host() -> None:
    if DRY_RUN:
        return
    if USERSPACE:
        if not Path("/dev/net/tun").exists():
            sys.exit(f"ENGINE={ENGINE}: нет /dev/net/tun в контейнере — проверь devices в docker-compose.yml")
    else:
        if not Path("/sys/module/wireguard").exists() and not ok(["ip", "link", "add", "wg-probe0", "type", "wireguard"]):
            sys.exit("нет модуля wireguard в ядре хоста: выполни на хосте `modprobe wireguard`")
        run(["ip", "link", "del", "wg-probe0"], check=False)
    try:
        rp = int(Path("/proc/sys/net/ipv4/conf/all/rp_filter").read_text())
        if rp == 1:
            log.warning("net.ipv4.conf.all.rp_filter=1 (strict): ответы из туннелей могут отбрасываться. "
                        "Поставь на хосте 2 (loose), см. README")
    except OSError:
        pass


# ---------------------------------------------------------------- подсказка для 3x-ui
def xray_snippets() -> str:
    """Готовые куски конфига для 3x-ui. Не зависят от ключей: ротация их не меняет."""
    lines = ["", "=" * 70, f"3x-ui: {TUNNELS} outbound(ов) — «+ Исходящие» → JSON → вставить строку → Создать", "=" * 70]
    for n in range(1, TUNNELS + 1):
        name = f"{IFACE_PREFIX}{n}"
        lines.append(json.dumps({"tag": name, "protocol": "freedom",
                                 "settings": {"domainStrategy": "UseIPv4v6"},
                                 "streamSettings": {"sockopt": {"interface": name}}}, ensure_ascii=False))
    lines += ["-" * 70, "Балансер (вкладка Balancers): тег warp-bal, selector " + IFACE_PREFIX
              + ", стратегия leastPing, fallback " + f"{IFACE_PREFIX}1",
              "Observatory (Advanced, верхний уровень):",
              json.dumps({"observatory": {"subjectSelector": [IFACE_PREFIX],
                                          "probeURL": "https://www.gstatic.com/generate_204",
                                          "probeInterval": "15s", "enableConcurrency": True}}),
              'Routing: "outboundTag": "warp"  →  "balancerTag": "warp-bal"',
              "=" * 70, ""]
    return "\n".join(lines)


# ---------------------------------------------------------------- CLI
def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "xray":
        print(xray_snippets())
        return
    if cmd == "status":
        print(STATUS_PATH.read_text() if STATUS_PATH.exists() else "status.json ещё нет")
        return
    pool = Pool()
    if cmd == "down":
        for t in pool.tunnels:
            t.teardown()
        log.info("интерфейсы и правила удалены (аккаунты в state.json сохранены)")
        return
    if cmd == "import":
        # import N PRIVATE_KEY V4 [V6] — положить в туннель N готовый рабочий аккаунт (например, с другого хоста)
        # import N CONFIG.json        — то же для masque: config.json от `usque register`
        if len(sys.argv) == 4 and sys.argv[3].endswith(".json"):
            c = json.loads(Path(sys.argv[3]).read_text())
            acc = {"id": c.get("id"), "token": c.get("access_token"), "private_key": c["private_key"],
                   "peer_public_key": c["endpoint_pub_key"], "v4": c["ipv4"], "v6": c.get("ipv6") or None,
                   "endpoint_v4": c.get("endpoint_v4", ""), "endpoint_v6": c.get("endpoint_v6", ""),
                   "type": "masque", "registered_at": iso(), "route": "import"}
        elif len(sys.argv) >= 5:
            v6 = sys.argv[5].split("/")[0] if len(sys.argv) > 5 else None
            acc = {"id": None, "token": None, "private_key": sys.argv[3], "peer_public_key": WARP_PEER_KEY,
                   "v4": sys.argv[4].split("/")[0], "v6": v6, "registered_at": iso(), "route": "import"}
        else:
            sys.exit("usage: import N PRIVATE_KEY V4 [V6]  |  import N USQUE_CONFIG.json")
        t = pool.tunnels[int(sys.argv[2]) - 1]
        t.account = acc
        t.last_reg = now()
        pool.save()
        log.info("%s: аккаунт импортирован; при следующем старте поднимется с ним", t.name)
        return
    if cmd != "run":
        sys.exit(f"неизвестная команда {cmd}; есть run | status | xray | down | import")

    def stop(*_):
        pool.stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(xray_snippets(), flush=True)
    eps = (f"auto ({len(AUTO_SUBNETS)} подсетей × {len(AUTO_PORTS)} портов)" if AUTO_ENDPOINTS
           else ", ".join(FIXED_ENDPOINTS))
    if ENGINE == "masque":
        eps = f"{masque_endpoint()} {'HTTP/2' if MASQUE_HTTP2 else 'HTTP/3'}, SNI {MASQUE_SNI or 'родной'}"
    regs = ",".join(["direct"] * REG_DIRECT + ["proxy"] * bool(REG_PROXY) + ["туннели"] * REG_VIA_TUNNEL) or "нет"
    log.info("старт: %d туннелей, движок %s, эндпоинты %s, регистрация: %s%s", TUNNELS, ENGINE, eps, regs,
             " [DRY_RUN]" if DRY_RUN else "")
    pool.loop()


if __name__ == "__main__":
    main()

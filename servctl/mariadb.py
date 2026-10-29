"""MariaDB server: install/secure, databases, users and per-database privileges.

All SQL goes to the client on stdin over the local unix socket as the OS root
user (unix_socket auth, the RHEL 9 default; /root/.my.cnf is honoured too), so
passwords never appear in the process list or in the plan preview.
"""
from __future__ import annotations

import functools
import os
import re
import secrets
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import firewall as fw
from .core import Step, which

SYSTEM_DBS = {"mysql", "information_schema", "performance_schema", "sys"}
PRIV_PRESETS: Dict[str, Tuple[str, str]] = {
    "all": ("All privileges on the database", "ALL PRIVILEGES"),
    "rw_ddl": ("Read/write + change tables (typical app)",
               "SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES, "
               "CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, CREATE VIEW, SHOW VIEW, "
               "CREATE ROUTINE, ALTER ROUTINE, EVENT, TRIGGER"),
    "rw": ("Read/write data only", "SELECT, INSERT, UPDATE, DELETE"),
    "ro": ("Read only", "SELECT, SHOW VIEW"),
}
CHARSETS = {"utf8mb4": "utf8mb4_unicode_ci", "utf8mb3": "utf8mb3_general_ci", "latin1": "latin1_swedish_ci"}

_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.%_:/-]{1,255}$")
_DB_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")


def client() -> str:
    return "mariadb" if which("mariadb") else "mysql"


@functools.lru_cache(maxsize=None)
def _ssl_args(binary: str) -> Tuple[str, ...]:
    """MariaDB 11.4+ clients demand TLS by default and fail with ERROR 2026 against a
    server without certificates - even on the local socket. Local socket traffic
    never leaves the host, so switch TLS off when the client knows the option."""
    if not shutil.which(binary):
        return ()
    try:
        out = subprocess.run([binary, "--help"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ()
    args: List[str] = []
    if re.search(r"^\s+--ssl\b", out, re.M):
        args.append("--skip-ssl")
    # Certificate verification (default on in 11.4+) re-enables TLS on its own.
    if re.search(r"^\s+--ssl-verify-server-cert\b", out, re.M):
        args.append("--skip-ssl-verify-server-cert")
    return tuple(args)


def client_argv(*extra: str) -> List[str]:
    c = client()
    return [c, "--protocol=socket", *_ssl_args(c), *extra]


def conf_dir() -> str:
    for d in ("/etc/my.cnf.d", "/etc/mysql/mariadb.conf.d"):
        if os.path.isdir(d):
            return d
    return "/etc/my.cnf.d"


# --------------------------------------------------------------------------- #
# Validation and quoting
# --------------------------------------------------------------------------- #

def check_user(user: str, host: str) -> None:
    if not _USER_RE.match(user or ""):
        raise ValueError("User name: letters, digits, '_', '.', '-' (max 80)")
    if not _HOST_RE.match(host or ""):
        raise ValueError("Host: localhost, %, an IP, or a pattern like 10.0.0.% / 10.0.0.0/255.255.255.0")


def check_dbs(dbs: List[str]) -> List[str]:
    if not dbs:
        raise ValueError("Enter at least one database name")
    for d in dbs:
        if not _DB_RE.match(d):
            raise ValueError(f"Database '{d}': use letters, digits and '_' (max 64)")
    return dbs


def check_password(pw: str) -> None:
    if len(pw) < 10:
        raise ValueError("Password must be at least 10 characters (or press Generate)")
    if any(c in pw for c in "\\\n\r\x00"):
        raise ValueError("Password may not contain backslashes or line breaks")


def q(s: str) -> str:
    """SQL string literal (inputs are validated first; quotes are doubled)."""
    return "'" + s.replace("'", "''") + "'"


def account(user: str, host: str) -> str:
    return f"{q(user)}@{q(host)}"


def generate_password(n: int = 20) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.+"
    return "".join(secrets.choice(alphabet) for _ in range(n))


def sql_step(title: str, sql: str, secret: Optional[str] = None, allow_fail: bool = False) -> Step:
    shown = sql.replace(q(secret), "'********'") if secret else sql
    argv = client_argv("--batch")
    return Step.cmd(title, *argv, stdin=sql, allow_fail=allow_fail,
                    display=f"{' '.join(argv)} <<SQL\n{shown.strip()}\nSQL")


# --------------------------------------------------------------------------- #
# Reading state
# --------------------------------------------------------------------------- #

def run_sql(sql: str, timeout: int = 15) -> Tuple[bool, List[List[str]], str]:
    if not shutil.which(client()):
        return False, [], "MariaDB client is not installed"
    try:
        r = subprocess.run(client_argv("-N", "-B"), input=sql, text=True,
                           capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, [], "query timed out"
    if r.returncode != 0:
        return False, [], (r.stderr or r.stdout).strip()
    return True, [line.split("\t") for line in r.stdout.splitlines() if line], ""


@dataclass
class Grant:
    user: str
    host: str
    target: str          # `db`.* or *.*
    privileges: str
    grant_option: bool

    @property
    def db(self) -> str:
        m = re.match(r"`?([^`.]+)`?\.", self.target)
        return m.group(1).replace("\\_", "_") if m else self.target


_GRANT_RE = re.compile(r"^GRANT (?P<privs>.+?) ON (?P<target>\S+) TO [`']?(?P<user>[^`'@]*)[`']?@[`']?"
                       r"(?P<host>[^`'\s]*)[`']?(?P<rest>.*)$")


def parse_grant(line: str) -> Optional[Grant]:
    m = _GRANT_RE.match(line.strip())
    if not m:
        return None
    rest = m.group("rest")
    return Grant(m.group("user"), m.group("host"), m.group("target"), m.group("privs"),
                 "WITH GRANT OPTION" in rest)


def status() -> Dict[str, str]:
    from .core import capture
    info = {"service": capture(["systemctl", "is-active", "mariadb"], 5)[1].strip() or "unknown",
            "installed": "yes" if which("mariadbd") or which("mysqld") or
            os.path.exists("/usr/libexec/mariadbd") else "no"}
    ok, rows, err = run_sql("SELECT VERSION(), @@bind_address, @@port, @@datadir, @@socket;")
    if ok and rows:
        info.update(zip(("version", "bind", "port", "datadir", "socket"), rows[0]))
    else:
        info["error"] = err
    return info


def databases() -> List[Tuple[str, str, int, int]]:
    ok, rows, _ = run_sql(
        "SELECT s.SCHEMA_NAME, s.DEFAULT_CHARACTER_SET_NAME, COUNT(t.TABLE_NAME), "
        "COALESCE(SUM(t.DATA_LENGTH + t.INDEX_LENGTH), 0) FROM information_schema.SCHEMATA s "
        "LEFT JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = s.SCHEMA_NAME "
        "GROUP BY s.SCHEMA_NAME, s.DEFAULT_CHARACTER_SET_NAME ORDER BY s.SCHEMA_NAME;")
    return [(r[0], r[1], int(r[2]), int(float(r[3]))) for r in rows if len(r) >= 4] if ok else []


def users() -> List[Tuple[str, str, str]]:
    ok, rows, _ = run_sql("SELECT User, Host, plugin FROM mysql.user ORDER BY User, Host;")
    return [(r[0], r[1], r[2] if len(r) > 2 else "") for r in rows] if ok else []


def grants(accounts: List[Tuple[str, str, str]]) -> List[Grant]:
    if not accounts:
        return []
    sql = "".join(f"SHOW GRANTS FOR {account(u, h)};\n" for u, h, _ in accounts if u)
    ok, rows, _ = run_sql(sql)
    out = []
    for r in rows if ok else []:
        g = parse_grant(r[0])
        if g:
            out.append(g)
    return out


# --------------------------------------------------------------------------- #
# Plans
# --------------------------------------------------------------------------- #

SECURE_SQL = """
-- equivalent of mariadb-secure-installation, without prompts
DELETE FROM mysql.global_priv WHERE User = '';
DELETE FROM mysql.global_priv WHERE User = 'root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db = 'test' OR Db = 'test\\\\_%';
FLUSH PRIVILEGES;
"""


def install_plan(pkg: str, listen_all: bool, open_firewall: bool, fw_source: str) -> List[Step]:
    pkg = pkg or "dnf"
    pkgs = ["mariadb-server", "mariadb"] if pkg in ("dnf", "yum") else ["mariadb-server", "mariadb-client"]
    bind = "0.0.0.0" if listen_all else "127.0.0.1"
    cnf = f"{conf_dir()}/90-servctl.cnf"
    steps = [
        Step.cmd("Install MariaDB server", pkg, "install", "-y", *pkgs),
        Step.write(f"Listen on {bind}", cnf,
                   "# Managed by servctl\n[mysqld]\n"
                   f"bind-address = {bind}\n"
                   "character-set-server = utf8mb4\n"
                   "collation-server = utf8mb4_unicode_ci\n"),
        Step.cmd("Enable and start MariaDB", "systemctl", "enable", "--now", "mariadb"),
        Step.cmd("Apply new settings", "systemctl", "restart", "mariadb"),
        sql_step("Secure the installation (anonymous users, remote root, test DB)", SECURE_SQL),
    ]
    if open_firewall:
        if not listen_all:
            raise ValueError("Opening the firewall only makes sense with 'Listen on all interfaces'")
        back = fw.backend()
        src = fw.validate_source(fw_source)
        if back == "firewalld":
            steps += fw.fw_open_plan([(3306, 3306)], ["tcp"], fw.Firewalld().default_zone(), src, True, 0)
        elif back == "nftables":
            try:
                steps += fw.nft_open_plan([(3306, 3306)], ["tcp"], src, fw.nft_ruleset(), True)
            except ValueError:
                pass   # nothing blocks it
    return steps


def create_db_plan(dbs: List[str], charset: str = "utf8mb4") -> List[Step]:
    check_dbs(dbs)
    coll = CHARSETS.get(charset)
    if not coll:
        raise ValueError("Unknown character set")
    sql = "".join(f"CREATE DATABASE IF NOT EXISTS `{d}` CHARACTER SET {charset} COLLATE {coll};\n" for d in dbs)
    return [sql_step(f"Create database(s): {', '.join(dbs)}", sql)]


def create_user_plan(user: str, host: str, password: str, reset_existing: bool) -> List[Step]:
    check_user(user, host)
    check_password(password)
    sql = f"CREATE USER IF NOT EXISTS {account(user, host)} IDENTIFIED BY {q(password)};\n"
    if reset_existing:
        sql += f"ALTER USER {account(user, host)} IDENTIFIED BY {q(password)};\n"
    return [sql_step(f"Create user {user}@{host}", sql, secret=password)]


def grant_plan(user: str, host: str, dbs: List[str], preset: str, create_missing: bool,
               with_grant_option: bool = False) -> List[Step]:
    check_user(user, host)
    check_dbs(dbs)
    if preset not in PRIV_PRESETS:
        raise ValueError("Pick a privilege level")
    if any(d in SYSTEM_DBS for d in dbs):
        raise ValueError(f"Refusing to grant on system database(s): {', '.join(d for d in dbs if d in SYSTEM_DBS)}")
    privs = PRIV_PRESETS[preset][1]
    sql = ""
    if create_missing:
        sql += "".join(f"CREATE DATABASE IF NOT EXISTS `{d}` CHARACTER SET utf8mb4 "
                       f"COLLATE utf8mb4_unicode_ci;\n" for d in dbs)
    opt = " WITH GRANT OPTION" if with_grant_option else ""
    sql += "".join(f"GRANT {privs} ON `{d}`.* TO {account(user, host)}{opt};\n" for d in dbs)
    sql += "FLUSH PRIVILEGES;\n"
    return [sql_step(f"Grant '{PRIV_PRESETS[preset][0]}' to {user}@{host} on {', '.join(dbs)}", sql)]


def revoke_plan(user: str, host: str, dbs: List[str]) -> List[Step]:
    check_user(user, host)
    check_dbs(dbs)
    sql = "".join(f"REVOKE ALL PRIVILEGES ON `{d}`.* FROM {account(user, host)};\n" for d in dbs)
    return [sql_step(f"Revoke {user}@{host} on {', '.join(dbs)}", sql + "FLUSH PRIVILEGES;\n")]


def drop_user_plan(user: str, host: str) -> List[Step]:
    check_user(user, host)
    if user == "root" or user.startswith("mariadb.") or user == "mysql":
        raise ValueError(f"Refusing to drop the system account {user}@{host}")
    return [sql_step(f"Drop user {user}@{host}", f"DROP USER IF EXISTS {account(user, host)};\n")]


def _dump_cmd() -> str:
    dump = "mariadb-dump" if which("mariadb-dump") else "mysqldump"
    return " ".join([dump, *_ssl_args(dump)])


def drop_db_plan(db: str, confirm: str) -> List[Step]:
    check_dbs([db])
    if db in SYSTEM_DBS:
        raise ValueError("Refusing to drop a system database")
    if confirm != db:
        raise ValueError(f"Type the database name '{db}' in the confirmation box to drop it")
    return [Step.cmd(f"Back up {db} first", "bash", "-euo", "pipefail", "-c",
                     f"mkdir -p /var/backups/servctl/mariadb && "
                     f"{_dump_cmd()} --single-transaction "
                     f"--routines --events {db} | gzip > /var/backups/servctl/mariadb/{db}-$(date +%Y%m%d-%H%M%S).sql.gz"),
            sql_step(f"Drop database {db}", f"DROP DATABASE `{db}`;\n")]

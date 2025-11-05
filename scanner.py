#!/usr/bin/env python3
"""
remote_inspect.py

Run from your local machine to SSH into a remote Ubuntu server and
collect nginx / proxy / pm2 / postgres / TLS details. Saves JSON report.

Usage:
  pip3 install paramiko
  python3 remote_inspect.py
"""
import json
import os
import shlex
import sys
import getpass
import re
import tempfile
from datetime import datetime

try:
    import paramiko
except Exception as e:
    print("Missing dependency: paramiko. Install with: pip3 install paramiko")
    raise

# -----------------------
# SSH wrapper (paramiko)
# -----------------------
class SSHClientWrapper:
    def __init__(self, host, port, user, pkey_path=None, password=None, timeout=20):
        self.host = host
        self.port = port
        self.user = user
        self.pkey_path = pkey_path
        self.password = password
        self.timeout = timeout
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self):
        kwargs = {"hostname": self.host, "port": self.port, "username": self.user, "timeout": self.timeout}
        if self.pkey_path:
            # load key (supports unencrypted keys)
            try:
                pkey = paramiko.RSAKey.from_private_key_file(os.path.expanduser(self.pkey_path))
            except paramiko.PasswordRequiredException:
                raise RuntimeError("Private key is encrypted. Provide an unencrypted key or implement passphrase support.")
            kwargs["pkey"] = pkey
        else:
            kwargs["password"] = self.password
        self.client.connect(**kwargs)

    def run(self, cmd, sudo=False, sudo_password=None, timeout=120):
        """
        cmd: str or list
        sudo: bool -> run with sudo -S -p ''
        sudo_password: str or None (sent to sudo stdin if provided)
        returns: (rc, stdout, stderr)
        """
        if isinstance(cmd, (list, tuple)):
            cmd_str = " ".join(shlex.quote(str(c)) for c in cmd)
        else:
            cmd_str = str(cmd)

        if sudo:
            # wrap with sudo -S and a shell so we can run complex commands
            cmd_str = f"sudo -S -p '' sh -c {shlex.quote(cmd_str)}"

        stdin, stdout, stderr = self.client.exec_command(cmd_str, timeout=timeout, get_pty=True)
        if sudo and sudo_password:
            try:
                stdin.write(sudo_password + "\n")
                stdin.flush()
            except Exception:
                pass

        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        rc = stdout.channel.recv_exit_status()
        return rc, out, err

    def get_file(self, remote_path, local_path):
        sftp = self.client.open_sftp()
        sftp.get(remote_path, local_path)
        sftp.close()

    def close(self):
        self.client.close()

# -----------------------
# Parse nginx text helpers
# -----------------------
listen_re = re.compile(r'listen\s+([^;{]+)', re.IGNORECASE)
server_name_re = re.compile(r'server_name\s+([^;]+);', re.IGNORECASE)
ssl_cert_re = re.compile(r'ssl_certificate\s+([^;]+);', re.IGNORECASE)
ssl_key_re = re.compile(r'ssl_certificate_key\s+([^;]+);', re.IGNORECASE)
proxy_pass_re = re.compile(r'proxy_pass\s+([^;]+);', re.IGNORECASE)

def parse_nginx_server_blocks(nginx_text):
    servers = []
    # crude split by 'server {'
    parts = re.split(r'(?m)^\s*server\s*\{', nginx_text)
    for part in parts[1:]:
        blk = "server {" + part
        # short-circuit: take until matching closing brace using simple counter
        depth = 0
        collected = []
        for ch in blk:
            collected.append(ch)
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
        txt = "".join(collected)
        servers.append({
            "listens": [m.strip() for m in listen_re.findall(txt)],
            "server_name": [s.strip() for s in server_name_re.findall(txt)],
            "ssl_certificate": [s.strip() for s in ssl_cert_re.findall(txt)],
            "ssl_key": [s.strip() for s in ssl_key_re.findall(txt)],
            "proxy_pass": [p.strip() for p in proxy_pass_re.findall(txt)],
            "raw": txt
        })
    return servers

# -----------------------
# High-level inspection
# -----------------------
def inspect_remote(ssh: SSHClientWrapper, sudo_password=None, try_install_missing=False):
    report = {
        "collected_at": datetime.utcnow().isoformat() + "Z",
        "host": ssh.host,
        "nginx": {},
        "server_blocks": [],
        "listeners": None,
        "pm2": {},
        "postgres": {},
        "certificates": [],
        "tls_probes": [],
        "notes": []
    }

    def run(cmd, sudo=False, timeout=120):
        rc, out, err = ssh.run(cmd, sudo=sudo, sudo_password=sudo_password, timeout=timeout)
        return rc, out, err

    # Check basic tools on remote
    for tool in ("nginx", "openssl", "ss", "pm2", "psql"):
        rc, out, err = run(["which", tool], sudo=False)
        report["notes"].append({ "tool": tool, "found": (rc == 0), "path": out.strip() or None, "err": err.strip() or None })

    # nginx -V (version) (often prints to stderr)
    rc, out_v, err_v = run(["nginx", "-V"], sudo=False)
    report["nginx"]["nginx_V_stdout"] = out_v.strip()
    report["nginx"]["nginx_V_stderr"] = err_v.strip()

    # nginx -T (full config)
    rc, out_t, err_t = run(["nginx", "-T"], sudo=False)
    if rc != 0:
        # maybe nginx not in PATH for that user or requires sudo
        rc2, out_t2, err_t2 = run(["nginx", "-T"], sudo=True)
        if rc2 == 0:
            out_t, err_t, rc = out_t2, err_t2, rc2
        else:
            report["notes"].append("nginx -T failed; collected nothing. Try running script with sudo or provide sudo password.")
    report["nginx"]["raw_config"] = out_t + ("\n\nERR:\n"+err_t if err_t else "")
    # parse server blocks
    report["server_blocks"] = parse_nginx_server_blocks(out_t if out_t else "")

    # system listeners
    rc, out_listen, err_listen = run(["ss", "-tunlp"], sudo=False)
    if rc != 0:
        rc, out_listen, err_listen = run(["ss", "-tunlp"], sudo=True)
    if rc != 0:
        rc, out_listen, err_listen = run(["netstat", "-tunlp"], sudo=True)
    report["listeners"] = out_listen.strip()

    # pm2 status / list (if installed)
    rc, which_pm2, _ = run(["which", "pm2"], sudo=False)
    if rc == 0 and which_pm2.strip():
        # pm2 may be installed for a particular user; run pm2 jlist for JSON (no sudo)
        rc, out_pm2, err = run([which_pm2.strip(), "jlist"], sudo=False)
        if rc != 0:
            # try as the connecting user with env
            rc, out_pm2, err = run("pm2 jlist", sudo=False)
        try:
            report["pm2"]["jlist"] = json.loads(out_pm2) if out_pm2 else None
        except Exception:
            report["pm2"]["jlist_raw"] = out_pm2
        # attempt to fetch ecosystem.config.js in common places
        for p in ("/var/www/frontend/ecosystem.config.js", "/var/www/backend/ecosystem.config.js", "~/ecosystem.config.js"):
            rc, outp, errp = run(f"test -f {shlex.quote(p)} && echo yes || echo no", sudo=False)
            if outp.strip() == "yes":
                rc, file_contents, _ = run(f"cat {shlex.quote(p)}", sudo=False)
                report["pm2"].setdefault("ecosystems", {})[p] = file_contents

    # postgres: check listening and psql version, DB list if sudo allowed
    rc, out_psql_which, _ = run(["which", "psql"], sudo=False)
    if rc == 0:
        rc, out_psql_v, _ = run(["psql", "--version"], sudo=False)
        report["postgres"]["psql_version"] = out_psql_v.strip()
    # check listening on 5432 via ss
    report["postgres"]["listeners_5432"] = ("5432" in out_listen)  # crude
    # attempt to list DBs via sudo -u postgres psql -c "\l"
    rc, out_dbs, err = run(['bash','-lc','sudo -n -u postgres psql -c "\\l" -P pager=off'], sudo=False)
    if rc != 0:
        # try with interactive sudo (if sudo password provided)
        if sudo_password:
            rc, out_dbs, err = run(['bash','-lc','sudo -u postgres psql -c "\\l" -P pager=off'], sudo=True, sudo_password=sudo_password)
    if rc == 0:
        report["postgres"]["db_list_raw"] = out_dbs.strip()
    else:
        report["postgres"]["db_list_raw"] = f"failed to list DBs (rc={rc}). Need sudo or postgres user access. err={err.strip()}"

    # Gather certificate files referenced in nginx config
    cert_paths = set()
    for sb in report["server_blocks"]:
        for p in sb.get("ssl_certificate", []):
            # remove variables and trailing params
            pclean = p.split()[0].strip()
            cert_paths.add(pclean)
    # Inspect certificate files with openssl on remote
    for cp in cert_paths:
        if not cp:
            continue
        # attempt to read file
        rc, out_file, err = run(f"test -f {shlex.quote(cp)} && echo YES || echo NO", sudo=False)
        accessible = False
        if out_file.strip() == "YES":
            accessible = True
            rc, cert_text, err = run(["openssl", "x509", "-in", cp, "-noout", "-text"], sudo=False)
        else:
            # maybe root-only -> try via sudo if sudo_password provided
            if sudo_password:
                rc, out_file2, err2 = run(f"test -f {shlex.quote(cp)} && echo YES || echo NO", sudo=True, sudo_password=sudo_password)
                if out_file2.strip() == "YES":
                    accessible = True
                    rc, cert_text, err = run(["openssl", "x509", "-in", cp, "-noout", "-text"], sudo=True, sudo_password=sudo_password)
                else:
                    cert_text = None
            else:
                cert_text = None
        report["certificates"].append({
            "path": cp,
            "accessible": accessible,
            "openssl_text": cert_text if cert_text else None
        })

    # TLS probe: for each server_name, attempt openssl s_client to host:443
    hosts_to_probe = set()
    for sb in report["server_blocks"]:
        for names in sb.get("server_name", []):
            for nm in names.split():
                nm = nm.strip()
                if nm and nm != "_":
                    hosts_to_probe.add(nm)
        for p in sb.get("proxy_pass", []):
            m = re.match(r'http(?:s)?://([^/:]+)(?::(\d+))?', p)
            if m:
                hosts_to_probe.add(m.group(1))

    for h in hosts_to_probe:
        # run a short s_client probe
        probe_cmd = f"echo | openssl s_client -connect {shlex.quote(h)}:443 -servername {shlex.quote(h)} -brief 2>/dev/null || echo 'NOPE'"
        rc, out_probe, err = run(probe_cmd, sudo=False)
        probe = {"host": h, "success": False, "raw": out_probe[:8000]}
        if out_probe and "NOPE" not in out_probe:
            # look for Protocol and Cipher lines
            proto = re.search(r'Protocol\s*:\s*(\S+)', out_probe)
            cipher = re.search(r'Cipher\s*:\s*(\S+)', out_probe)
            probe.update({"success": True, "protocol": proto.group(1) if proto else None, "cipher": cipher.group(1) if cipher else None})
        else:
            probe["error"] = err.strip() or out_probe.strip()
        report["tls_probes"].append(probe)

    return report

# -----------------------
# Interactive CLI
# -----------------------
def prompt_and_run():
    print("Remote NGINX + proxy inspector (SSH)\n")
    host = input("SSH host (IP or domain): ").strip()
    port = int(input("SSH port [22]: ").strip() or "22")
    user = input("SSH username: ").strip() or getpass.getuser()
    auth = input("Auth method? [key/password] (default:key): ").strip().lower() or "key"
    pkey = None
    password = None
    if auth == "key":
        pkey = input("Path to private key (default ~/.ssh/id_rsa): ").strip() or "~/.ssh/id_rsa"
        pkey = os.path.expanduser(pkey)
        if not os.path.exists(pkey):
            print("Warning: key file not found at", pkey)
    else:
        password = getpass.getpass("SSH password: ")

    sudo_password = getpass.getpass("sudo password (optional, leave blank if none): ")

    print("\nConnecting...")

    ssh = SSHClientWrapper(host=host, port=port, user=user, pkey_path=pkey if auth=="key" else None, password=password)
    try:
        ssh.connect()
    except Exception as e:
        print("SSH connect failed:", e)
        sys.exit(2)

    try:
        report = inspect_remote(ssh, sudo_password=sudo_password)
    except Exception as e:
        print("Inspection error:", e)
        ssh.close()
        sys.exit(3)

    ssh.close()

    out_path = os.path.abspath("nginx_remote_report.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to: {out_path}")
    # brief summary
    print("Summary:")
    print("  server blocks:", len(report.get("server_blocks", [])))
    print("  certificates found:", len(report.get("certificates", [])))
    print("  tls probes:", len(report.get("tls_probes", [])))
    print("\nDone.")

if __name__ == "__main__":
    prompt_and_run()

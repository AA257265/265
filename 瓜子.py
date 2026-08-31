# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
瓜子 APP - 多 API 自動切換 + 詳細診斷 + 影片解析修正版

用途：
1. 自動檢測多個 API Server：DNS / TCP / TLS / HTTP
2. 自動註冊/刷新裝置 token
3. 搜尋影片
4. 取得影片詳細資料與播放參數
5. 自動輪詢 API Server
6. 修正原程式 playerContent / token_id / stream URL 驗證問題
7. 對 m3u8 / mp4 / mpd 等播放 URL 做基本可達性檢查

安裝：
    python -m pip install requests pycryptodome

執行：
    python 瓜子APP_影片解析完整修正版.py
"""

import base64
import hashlib
import json
import os
import random
import re
import socket
import ssl
import sys
import time
import traceback
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    print("缺少 requests，請執行：python -m pip install requests")
    sys.exit(1)

try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("缺少 pycryptodome，請執行：python -m pip install pycryptodome")
    sys.exit(1)


class GuaziClient:
    def __init__(self):
        self.name = "瓜子"
        self.hosts = [
            "https://apinew.uozvr.com",
            "https://api.w32z7vtd.com",
            "https://api.6a7nnf7.com",
            "https://api.umygrx3.com",
            "https://api.rmedphk.com",
        ]
        self.host_index = 0
        self.host = self.hosts[0]

        self.AES_KEY = "OITxa5OqAYjhswxx"
        self.AES_IV = "rCMNwZASNBKZ8mXV"
        self.RSA_PUBLIC_KEY = (
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUM5+/y8sPsWkd1/RQS64X259EUwxFXFE5HlA65MqrxnPs0JqoSRojSDy5QhwvROlaD6TwRQHKMY2OAZ6SnQeUJsChTEFIR9qUkwrs3/MVUMxjsv6JS6Oe/juclyJGTgVmDhB55EafXsD0SQYVj/QXXsxR6ewR5E2kL52yAAD4yQIDAQAB"
        )
        # RSA 私鑰由原始版本提供；不在診斷輸出中顯示。
        self.RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGAe6hKrWLi1zQmjTT1\nozbE4QdFeJGNxubxld6GrFGximxfMsMB6BpJhpcTouAqywAFppiKetUBBbXwYsYU\n1wNr648XVmPmCMCy4rY8vdliFnbMUj086DU6Z+/oXBdWU3/b1G0DN3E9wULRSwcK\nZT3wj/cCI1vsCm3gj2R5SqkA9Y0CAwEAAQKBgAJH+4CxV0/zBVcLiBCHvSANm0l7\nHetybTh/j2p0Y1sTXro4ALwAaCTUeqdBjWiLSo9lNwDHFyq8zX90+gNxa7c5EqcW\nV9FmlVXr8VhfBzcZo1nXeNdXFT7tQ2yah/odtdcx+vRMSGJd1t/5k5bDd9wAvYdI\nDblMAg+wiKKZ5KcdAkEA1cCakEN4NexkF5tHPRrR6XOY/XHfkqXxEhMqmNbB9U34\nsaTJnLWIHC8IXys6Qmzz30TtzCjuOqKRRy+FMM4TdwJBAJQZFPjsGC+RqcG5UvVM\niMPhnwe/bXEehShK86yJK/g/UiKrO87h3aEu5gcJqBygTq3BBBoH2md3pr/W+hUM\nWBsCQQChfhTIrdDinKi6lRxrdBnn0Ohjg2cwuqK5zzU9p/N+S9x7Ck8wUI53DKm8\njUJE8WAG7WLj/oCOWEh+ic6NIwTdAkEAj0X8nhx6AXsgCYRql1klbqtVmL8+95KZ\nK7PnLWG/IfjQUy3pPGoSaZ7fdquG8bq8oyf5+dzjE/oTXcByS+6XRQJAP/5ciy1b\nL3NhUhsaOVy55MHXnPjdcTX0FaLi+ybXZIfIQ2P4rb19mVq1feMbCXhz+L1rG8oa\nt5lYKfpe8k83ZA==\n-----END RSA PRIVATE KEY-----"
        env_key = os.getenv("GUAZI_RSA_PRIVATE_KEY")
        if env_key:
            self.RSA_PRIVATE_KEY = env_key.replace("\\n", "\n")

        self.DEVICE_OLD_KEY = "aLFBMWpxBrIDAD1Si/KVvm41"
        self.deviceId = str(864150060000000 + random.randint(0, 9999))
        self.deviceKey = "".join(random.choices("0123456789ABCDEF", k=40))
        self.token = ""
        self.token_id = ""
        self.registered = False
        self.cache: Dict[str, Tuple[Any, float]] = {}
        self.cache_timeout = 60
        self.last_errors: List[str] = []

        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=0)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.header = {
            "User-Agent": "Lavf/57.83.100",
            "code": "GZ0369",
            "deviceId": self.deviceId,
            "lang": "zh_cn",
            "Cache-Control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded",
            "Version": "2604028",
            "PackageName": "com.ae06aebdbb.y286327f5a.ofe849883320260517",
            "Ver": "3.0.3.2",
            "api-ver": "3.0.3.2",
            "Referer": self.host,
        }

    # ---------------- 基礎 HTTP ----------------
    def _mask(self, value: Any, keep: int = 6) -> str:
        if not value:
            return ""
        s = str(value)
        if len(s) <= keep * 2:
            return "*" * len(s)
        return s[:keep] + "..." + s[-keep:]

    def _set_host(self, index: int):
        self.host_index = index % len(self.hosts)
        self.host = self.hosts[self.host_index]
        self.header["Referer"] = self.host

    def _request(self, method: str, url: str, **kwargs):
        kwargs.setdefault("timeout", (5, 15))
        kwargs.setdefault("allow_redirects", True)
        return self.session.request(method, url, **kwargs)

    # ---------------- 網路診斷 ----------------
    def _parse_host(self, host):
        p = urllib.parse.urlparse(host)
        scheme = p.scheme or "https"
        hostname = p.hostname
        port = p.port or (443 if scheme == "https" else 80)
        return scheme, hostname, port

    def check_dns(self, host):
        scheme, hostname, port = self._parse_host(host)
        result = {"host": host, "ok": False, "addresses": [], "error": ""}
        try:
            infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
            result["addresses"] = sorted({x[4][0] for x in infos})
            result["ok"] = bool(result["addresses"])
        except Exception as e:
            result["error"] = f"{type(e).__name__}: {e}"
        return result

    def check_tcp(self, host, timeout=5):
        _, hostname, port = self._parse_host(host)
        result = {"host": host, "ok": False, "elapsed_ms": 0, "error": ""}
        start = time.perf_counter()
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                result["ok"] = True
        except Exception as e:
            result["error"] = f"{type(e).__name__}: {e}"
        result["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 1)
        return result

    def check_tls(self, host, timeout=5):
        scheme, hostname, port = self._parse_host(host)
        result = {"host": host, "ok": False, "tls_version": "", "error": ""}
        if scheme.lower() != "https":
            result["ok"] = True
            result["tls_version"] = "HTTP"
            return result
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result["ok"] = True
                    result["tls_version"] = ssock.version() or ""
        except Exception as e:
            result["error"] = f"{type(e).__name__}: {e}"
        return result

    def check_http(self, host, timeout=8):
        result = {"host": host, "ok": False, "status": None, "elapsed_ms": 0, "error": ""}
        start = time.perf_counter()
        try:
            r = self._request("GET", host, headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"}, timeout=(5, timeout))
            result["status"] = r.status_code
            # 403/404 代表 HTTP 層可達，不等同於網路斷線。
            result["ok"] = True
        except Exception as e:
            result["error"] = f"{type(e).__name__}: {e}"
        result["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 1)
        return result

    def diagnose(self) -> List[Dict[str, Any]]:
        print("\n" + "=" * 82)
        print("        瓜子 API Server 自動檢測 / 詳細錯誤診斷")
        print("=" * 82)
        reports = []
        for i, host in enumerate(self.hosts, 1):
            print(f"\n[{i}/{len(self.hosts)}] {host}")
            r = {"host": host}
            r["dns"] = self.check_dns(host)
            print("  DNS :", "OK " + ", ".join(r["dns"]["addresses"]) if r["dns"]["ok"] else "FAIL " + r["dns"]["error"])
            if r["dns"]["ok"]:
                r["tcp"] = self.check_tcp(host)
                print(f"  TCP : {'OK' if r['tcp']['ok'] else 'FAIL'} {r['tcp']['elapsed_ms']} ms {r['tcp']['error']}")
                r["tls"] = self.check_tls(host)
                print(f"  TLS : {'OK' if r['tls']['ok'] else 'FAIL'} {r['tls'].get('tls_version','')} {r['tls']['error']}")
                r["http"] = self.check_http(host)
                print(f"  HTTP: {'OK' if r['http']['ok'] else 'FAIL'} status={r['http'].get('status')} {r['http']['error']}")
            else:
                r["tcp"] = r["tls"] = r["http"] = None
            reports.append(r)
        print("\n" + "-" * 82)
        print(f"{'Server':<34} {'DNS':<7} {'TCP':<7} {'TLS':<7} {'HTTP':<7}")
        print("-" * 82)
        for r in reports:
            def st(x): return "OK" if x and x.get("ok") else ("FAIL" if x else "--")
            print(f"{r['host'][:33]:<34} {st(r['dns']):<7} {st(r['tcp']):<7} {st(r['tls']):<7} {st(r['http']):<7}")
        alive = [r["host"] for r in reports if r.get("http", {}).get("ok")]
        print("-" * 82)
        print(f"可用 HTTP Server：{len(alive)}/{len(self.hosts)}")
        for h in alive:
            print("  OK", h)
        print("=" * 82)
        return reports

    # ---------------- 加密 ----------------
    def aes_encrypt(self, text: str) -> str:
        cipher = AES.new(self.AES_KEY.encode(), AES.MODE_CBC, self.AES_IV.encode())
        return cipher.encrypt(pad(text.encode(), AES.block_size)).hex().upper()

    def aes_decrypt(self, text: str, key: str, iv: str) -> str:
        raw = bytes.fromhex(text)
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
        return unpad(cipher.decrypt(raw), AES.block_size).decode()

    def rsa_encrypt(self, text: str) -> str:
        pub = RSA.import_key("-----BEGIN PUBLIC KEY-----\n" + self.RSA_PUBLIC_KEY + "\n-----END PUBLIC KEY-----")
        return base64.b64encode(PKCS1_v1_5.new(pub).encrypt(text.encode())).decode()

    def rsa_decrypt(self, text: str) -> str:
        key = RSA.import_key(self.RSA_PRIVATE_KEY)
        raw = base64.b64decode(text)
        out = PKCS1_v1_5.new(key).decrypt(raw, None)
        if not out:
            raise ValueError("RSA 解密失敗")
        return out.decode()

    # ---------------- 認證 ----------------
    def _auth_request(self, path, params):
        return self._send_encrypted_request(params, path, is_auth=True)

    def _apply_auth(self, data):
        if not data or not data.get("token"):
            raise RuntimeError(f"認證回應沒有 token：{data}")
        self.token = data["token"]
        self.token_id = data.get("app_user_id") or data.get("token_id") or self.token_id
        self.registered = True

    def sign_up(self):
        print("註冊新設備...")
        data = self._auth_request("/App/Authentication/Device/signUp", {
            "new_key": self.deviceKey,
            "old_key": self.DEVICE_OLD_KEY,
            "phone_type": 1,
            "code": "",
        })
        self._apply_auth(data)

    def sign_in(self):
        print("設備登入...")
        data = self._auth_request("/App/Authentication/Device/signIn", {
            "new_key": self.deviceKey,
            "old_key": self.DEVICE_OLD_KEY,
        })
        self._apply_auth(data)

    def refresh_token(self):
        print("刷新 token...")
        data = self._auth_request("/App/Authentication/Authenticator/refresh", {})
        self._apply_auth(data)

    def ensure_token(self):
        if self.token and self.token_id:
            return True
        if self.registered:
            self.sign_in()
        else:
            self.sign_up()
        self.refresh_token()
        return bool(self.token and self.token_id)

    # ---------------- API 核心 ----------------
    def _send_encrypted_request(self, data, path, is_auth=False):
        if not is_auth:
            # 避免遞迴：認證本身不能再呼叫 ensure_token。
            if not self.token or not self.token_id:
                raise RuntimeError("token/token_id 尚未準備完成")

        json_params = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        request_key = self.aes_encrypt(json_params)
        keys = self.rsa_encrypt(json.dumps({"iv": self.AES_IV, "key": self.AES_KEY}, separators=(",", ":")))
        t = str(int(time.time()))
        sign_str = (
            f"token_id={self.token_id},token={self.token},phone_type=1,"
            f"request_key={request_key},app_id=1,time={t},keys={keys}"
            f"*&zvdvdvddbfikkkumtmdwqppp?|4Y!s!2br"
        )
        signature = hashlib.md5(sign_str.encode()).hexdigest().upper()

        body = {
            "token": self.token,
            # 原程式這裡固定寫成空字串；這是重要修正。
            "token_id": self.token_id,
            "phone_type": "1",
            "time": t,
            "phone_model": "xiaomi-25031",
            "keys": keys,
            "request_key": request_key,
            "signature": signature,
            "app_id": "1",
            "ad_version": "1",
        }
        url = self.host.rstrip("/") + path
        r = self._request("POST", url, headers=self.header, data=body, timeout=(5, 15))
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")
        try:
            obj = r.json()
        except Exception:
            raise RuntimeError(f"回應不是 JSON：{r.text[:500]}")
        if obj.get("code") not in (None, 200):
            raise RuntimeError(f"API code={obj.get('code')} response={str(obj)[:500]}")
        section = obj.get("data") or {}
        encrypted_response = section.get("response_key")
        encrypted_keys = section.get("keys")
        if not encrypted_response or not encrypted_keys:
            raise RuntimeError(f"API 缺少 response_key/keys：{str(obj)[:500]}")
        key_info = json.loads(self.rsa_decrypt(encrypted_keys))
        plain = self.aes_decrypt(encrypted_response, key_info["key"], key_info["iv"])
        return json.loads(plain)

    def request_api(self, data, path, retries=True):
        errors = []
        start_index = self.host_index
        count = len(self.hosts) if retries else 1
        for n in range(count):
            idx = (start_index + n) % len(self.hosts)
            self._set_host(idx)
            try:
                if not self.token or not self.token_id:
                    self.ensure_token()
                result = self._send_encrypted_request(data, path)
                print(f"[OK] {path} <- {self.host}")
                self.last_errors = errors
                return result
            except Exception as e:
                msg = f"{self.host}{path} -> {type(e).__name__}: {e}"
                errors.append(msg)
                print("[FAIL]", msg)
                continue
        self.last_errors = errors
        return None

    # ---------------- 影片資料 ----------------
    def search(self, keyword: str, page=1):
        return self.request_api({"keywords": keyword, "order_val": "1", "page": str(page)}, "/App/Index/findMoreVod")

    def detail(self, vod_id: str):
        qdata = self.request_api({
            "token_id": self.token_id,
            "vod_id": vod_id,
            "mobile_time": str(int(time.time())),
            "token": self.token,
        }, "/App/IndexPlay/playInfo")
        jdata = self.request_api({"vurl_cloud_id": "2", "vod_d_id": vod_id}, "/App/Resource/Vurl/show")
        return qdata, jdata

    def extract_play_params(self, jdata, vod_name=""):
        results = []
        if not jdata or not isinstance(jdata.get("list"), list):
            return results
        for index, item in enumerate(jdata["list"]):
            plays = item.get("play") or {}
            params = []
            names = []
            for key, value in plays.items():
                if isinstance(value, dict) and value.get("param"):
                    names.append(str(key))
                    params.append(str(value["param"]))
            if params:
                results.append({
                    "name": str(index + 1) if len(jdata["list"]) != 1 else vod_name,
                    "param": params[-1],
                    "resolutions": names,
                })
        return results

    def resolve_player(self, param: str, resolutions: List[str]):
        params = {}
        for pair in param.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = urllib.parse.unquote_plus(v)
        numeric = [x for x in resolutions if str(x).isdigit()]
        if numeric:
            params["resolution"] = max(numeric, key=int)
        else:
            params["resolution"] = resolutions[-1] if resolutions else ""
        return self.request_api(params, "/App/Resource/VurlDetail/showOne")

    # ---------------- Stream 驗證 ----------------
    def validate_stream(self, url: str, referer: Optional[str] = None):
        if not url or not isinstance(url, str):
            return {"ok": False, "reason": "URL 為空"}
        p = urllib.parse.urlparse(url)
        if p.scheme not in ("http", "https"):
            return {"ok": False, "reason": f"不支援的 scheme: {p.scheme}"}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151 Safari/537.36",
            "Accept": "*/*",
        }
        if referer:
            headers["Referer"] = referer
        try:
            r = self._request("GET", url, headers=headers, stream=True, timeout=(5, 12))
            ctype = (r.headers.get("Content-Type") or "").lower()
            prefix = b""
            try:
                prefix = next(r.iter_content(512), b"")
            finally:
                r.close()
            looks_hls = ".m3u8" in url.lower() or "mpegurl" in ctype or b"#EXTM3U" in prefix
            looks_mpd = ".mpd" in url.lower() or "dash+xml" in ctype or b"<MPD" in prefix
            looks_video = url.lower().split("?", 1)[0].endswith((".mp4", ".mkv", ".flv", ".ts", ".webm")) or ctype.startswith("video/")
            return {
                "ok": r.status_code < 400,
                "status": r.status_code,
                "content_type": ctype,
                "hls": looks_hls,
                "mpd": looks_mpd,
                "video": looks_video,
                "reason": "OK" if r.status_code < 400 else f"HTTP {r.status_code}",
            }
        except Exception as e:
            return {"ok": False, "reason": f"{type(e).__name__}: {e}"}

    def save_result(self, title, result):
        safe = re.sub(r"[\\/:*?\"<>|]+", "_", title or "影片")[:80]
        path = f"{safe}_解析結果.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        return path


def print_search_results(data):
    items = (data or {}).get("list") or []
    print("\n搜尋結果：")
    print("-" * 90)
    for i, x in enumerate(items, 1):
        print(f"[{i:02d}] {x.get('vod_name','')} | ID={x.get('vod_id','')} | {x.get('vod_remarks','')}")
    print("-" * 90)
    return items


def main():
    print("=" * 82)
    print("      瓜子 APP｜多 API + 影片 URL 自動解析診斷版")
    print("=" * 82)
    client = GuaziClient()

    # 第一步：只做網路診斷；如果全部失敗，就先停止，避免一直重試。
    reports = client.diagnose()
    if not any(r.get("http", {}).get("ok") for r in reports):
        print("\n❌ 所有 API Server 都無法連線，影片解析不會成功。")
        print("請先檢查 DNS / Proxy / 防火牆 / 網路環境或 API Server 是否已失效。")
        return 2

    print("\n認證與 API 測試中...")
    try:
        client.ensure_token()
        print("認證成功")
        print("  host     =", client.host)
        print("  deviceId =", client.deviceId)
        print("  token    =", client._mask(client.token))
        print("  token_id =", client._mask(client.token_id))
    except Exception as e:
        print("❌ 認證失敗：", type(e).__name__, e)
        print("詳細錯誤：")
        for x in client.last_errors:
            print(" ", x)
        return 3

    while True:
        print("\n" + "-" * 82)
        print("1. 搜尋影片")
        print("2. 重新檢測 API")
        print("3. 顯示目前認證狀態")
        print("0. 離開")
        choice = input("請選擇：").strip()
        if choice == "0":
            break
        if choice == "2":
            client.diagnose()
            continue
        if choice == "3":
            print("Host    :", client.host)
            print("deviceId:", client.deviceId)
            print("token   :", client._mask(client.token))
            print("token_id:", client._mask(client.token_id))
            continue
        if choice != "1":
            print("無效選項")
            continue

        keyword = input("輸入影片名稱：").strip()
        if not keyword:
            continue
        data = client.search(keyword)
        items = print_search_results(data)
        if not items:
            print("❌ 找不到搜尋結果")
            continue
        try:
            idx = int(input("選擇編號：").strip()) - 1
            item = items[idx]
        except Exception:
            print("選擇無效")
            continue

        vod_id = str(item.get("vod_id", "")).split("/")[0]
        title = item.get("vod_name", keyword)
        print(f"\n取得《{title}》播放資訊...")
        qdata, jdata = client.detail(vod_id)
        if not qdata:
            print("❌ playInfo 取得失敗")
            continue
        vod = qdata.get("vodInfo") or {}
        print("影片：", vod.get("vod_name", title))
        print("年份：", vod.get("vod_year", ""))
        print("地區：", vod.get("vod_area", ""))

        play_params = client.extract_play_params(jdata, title)
        if not play_params:
            print("❌ API 有回應，但沒有找到 play.param")
            print("這表示問題已經從『網路』進一步縮小到『播放參數/來源資料』。")
            continue

        final = []
        for p in play_params:
            print(f"\n解析播放來源：{p['name']}")
            print("可用清晰度：", ", ".join(p["resolutions"]) or "未知")
            resolved = client.resolve_player(p["param"], p["resolutions"])
            if not resolved:
                print("  ❌ showOne 失敗")
                continue
            url = resolved.get("url") if isinstance(resolved, dict) else None
            if not url:
                print("  ❌ showOne 沒有 URL")
                print("  回應：", str(resolved)[:500])
                continue
            check = client.validate_stream(url, referer=client.host)
            print("  URL:", url)
            print("  狀態:", check)
            final.append({"name": p["name"], "param": p["param"], "resolutions": p["resolutions"], "url": url, "check": check})

        if final:
            out = {"title": title, "vod_id": vod_id, "sources": final, "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
            path = client.save_result(title, out)
            print("\n✅ 影片來源解析完成")
            print("結果已寫入：", os.path.abspath(path))
        else:
            print("\n❌ 找到影片資料，但沒有成功取得可播放 URL。")
            print("這時請把上面完整的 [FAIL] 與 showOne 回應貼給我，我可以再針對該 API 格式修改。")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n使用者中止")
    except Exception as e:
        print("\n程式發生未處理錯誤：")
        print(type(e).__name__, e)
        traceback.print_exc()
        input("\n按 Enter 離開...")

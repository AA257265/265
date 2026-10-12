# -*- coding: utf-8 -*-
"""
蝴蝶影院 · 动态自愈版
参考 片库.py 结构改写
导航站: x99dh.cc / x99dh.one  → 解析「三级片资源」真实域名
默认: https://ptt01.com
"""
import re
import json
import base64
import urllib.parse
import urllib.request
import ssl

try:
    import requests
except ImportError:
    requests = None

try:
    from base.spider import Spider as BaseSpider
except ImportError:
    class BaseSpider:
        def getCache(self, key):
            return None

        def setCache(self, key, value):
            return "fail"

        def delCache(self, key):
            return "fail"


HOST = "https://ptt01.com"
NAV_URLS = ["https://x99dh.cc", "https://x99dh.one"]
SITE_NAME = "三级片资源"
TG = "https://t.me/tvshare23"
UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko)"
)

CHANNELS = [
    ("/p/1", "🎬 电影"),
    ("/p/3", "📺 电视剧"),
    ("/p/4", "🌸 动漫"),
    ("/p/2", "🎤 综艺"),
    ("/p/66", "⚡ 短剧"),
    ("/p/53", "⚽ 体育"),
]


class Spider(BaseSpider):
    def getName(self):
        return "蝴蝶影院"

    def init(self, extend=""):
        global HOST
        if extend:
            try:
                conf = (
                    json.loads(extend)
                    if isinstance(extend, str) and extend.strip().startswith("{")
                    else (extend if isinstance(extend, dict) else {})
                )
                if conf.get("host"):
                    HOST = str(conf["host"]).rstrip("/")
            except Exception:
                pass
        cached = None
        try:
            cached = self.getCache("ptt01_dynamic_site_url")
        except Exception:
            pass
        if cached and str(cached).startswith("http"):
            HOST = str(cached).strip().rstrip("/")
        return self

    def _headers(self, extra=None):
        h = {
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Referer": HOST + "/",
        }
        if extra:
            h.update(extra)
        return h

    def _get(self, url, extra=None, timeout=12):
        if not url:
            return ""
        if url.startswith("//"):
            url = "https:" + url
        elif url.startswith("/"):
            url = HOST + url
        try:
            if requests is not None:
                r = requests.get(
                    url, headers=self._headers(extra), timeout=timeout, verify=False
                )
                return r.text or ""
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers=self._headers(extra))
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.read().decode("utf-8", "ignore")
        except Exception as e:
            print("get err", url, e)
            return ""

    def _abs(self, u):
        if not u:
            return ""
        u = str(u).strip().replace("\\/", "/")
        if u.startswith("//"):
            return "https:" + u
        if u.startswith("http"):
            return u
        if u.startswith("/"):
            return HOST + u
        return HOST + "/" + u

    def _clean(self, t):
        t = re.sub(r"<[^>]+>", " ", str(t or ""))
        t = (
            t.replace("&nbsp;", " ")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
        )
        return re.sub(r"\s+", " ", t).strip()

    def _remarks(self, meta=""):
        meta = re.sub(r"[\r\n\t]+", " ", str(meta or "")).strip()
        return ("蝴蝶影视 | " + meta) if meta else "蝴蝶影视"

    # ---------- 动态域名 ----------
    def _refresh_host(self):
        global HOST
        for nav in NAV_URLS:
            text = self._get(nav, timeout=6)
            if not text:
                continue
            for b in re.findall(r'["\']([A-Za-z0-9+/=]{100,})["\']', text):
                try:
                    decoded = base64.b64decode(b).decode("utf-8", "ignore")
                    unquoted = urllib.parse.unquote(decoded)
                    if "[" not in unquoted:
                        continue
                    if SITE_NAME not in unquoted and "稀缺资源" not in unquoted:
                        continue
                    site_list = json.loads(unquoted)
                    for item in site_list:
                        name = str(item.get("name") or "").strip()
                        if name not in (SITE_NAME, "稀缺资源"):
                            continue
                        cands = []
                        if item.get("url"):
                            cands.append(item["url"])
                        for u_obj in item.get("urls") or []:
                            u = (u_obj or {}).get("url") or ""
                            if u and u not in cands:
                                cands.append(u)
                        for c_url in cands:
                            p = urllib.parse.urlparse(c_url)
                            if not p.scheme or not p.netloc:
                                continue
                            base = "%s://%s" % (p.scheme, p.netloc)
                            chk = self._get(base + "/p/1", timeout=5)
                            if chk and len(chk) > 500:
                                HOST = base
                                try:
                                    self.setCache("ptt01_dynamic_site_url", base)
                                except Exception:
                                    pass
                                return True
                except Exception:
                    continue
        return False

    def _fetch(self, path, timeout=10):
        html = self._get(path, timeout=timeout)
        if not html or len(html) < 200:
            if self._refresh_host():
                html = self._get(path, timeout=timeout)
        return html or ""

    # ---------- 列表解析 ----------
    def _parse_list(self, html):
        videos, seen = [], set()
        if not html:
            return videos
        blocks = re.findall(
            r'(<div[^>]+class=["\'][^"\']*item[^"\']*["\'][\s\S]*?</div>\s*</div>\s*</div>)',
            html,
            re.I,
        )
        if not blocks:
            blocks = re.findall(r'(<a[^>]+href=["\']/\d+["\'][\s\S]*?</a>)', html, re.I)

        for block in blocks:
            m = re.search(r'href=["\'](/(\d+))["\']', block)
            if not m:
                continue
            path, vid = m.group(1), m.group(2)
            if path in seen:
                continue
            seen.add(path)

            name = ""
            tm = re.search(r'title=["\']([^"\']+)["\']', block)
            if tm:
                name = tm.group(1).strip()
            if not name:
                tm = re.search(r">([^<]{1,40})</a>", block)
                if tm:
                    clean = tm.group(1).strip()
                    if clean and not clean.startswith("fa-"):
                        name = clean
            if not name:
                name = "视频 " + vid

            pic = ""
            pm = re.search(
                r'(?:src|data-original|data-src)=["\']([^"\']+)["\']', block, re.I
            )
            if pm:
                cand = pm.group(1).strip()
                low = cand.lower()
                if not any(x in low for x in ("logo", "avatar", "icon", ".svg")):
                    pic = self._abs(cand)

            remarks = "HD"
            rm = re.search(
                r'class=["\'][^"\']*(?:badge|label|text-muted|remarks)[^"\']*["\'][^>]*>([^<]+)<',
                block,
                re.I,
            )
            if rm:
                remarks = self._clean(rm.group(1))

            videos.append(
                {
                    "vod_id": path,
                    "vod_name": self._clean(name)[:80],
                    "vod_pic": pic,
                    "vod_remarks": self._remarks(remarks),
                    "style": {"type": "rect", "ratio": 0.75},
                }
            )
        return videos

    # ---------- 壳入口 ----------
    def homeContent(self, filter=False):
        classes = [{"type_id": tid, "type_name": name} for tid, name in CHANNELS]
        result = {"class": classes, "list": [], "filters": {}}
        if filter:
            areas = [
                {"n": "全部", "v": ""},
                {"n": "大陆", "v": "2"},
                {"n": "香港", "v": "5"},
                {"n": "台湾", "v": "4"},
                {"n": "韩国", "v": "17"},
                {"n": "日本", "v": "18"},
                {"n": "欧美", "v": "6"},
                {"n": "泰国", "v": "10"},
            ]
            movie_types = [
                {"n": "全部", "v": ""},
                {"n": "伦理", "v": "/c/33"},
                {"n": "动作", "v": "/c/5"},
                {"n": "喜剧", "v": "/c/6"},
                {"n": "爱情", "v": "/c/7"},
                {"n": "科幻", "v": "/c/8"},
                {"n": "恐怖", "v": "/c/9"},
                {"n": "犯罪", "v": "/c/10"},
                {"n": "剧情", "v": "/c/13"},
                {"n": "悬疑", "v": "/c/15"},
            ]
            years = [{"n": "全部", "v": ""}] + [
                {"n": str(y), "v": str(y)} for y in range(2026, 2015, -1)
            ]
            f_movie = [
                {"key": "class_id", "name": "类型", "value": movie_types},
                {"key": "area_id", "name": "地区", "value": areas},
                {"key": "year", "name": "年份", "value": years},
            ]
            f_common = [
                {"key": "area_id", "name": "地区", "value": areas},
                {"key": "year", "name": "年份", "value": years},
            ]
            result["filters"] = {
                "/p/1": f_movie,
                "/p/3": f_common,
                "/p/4": f_common,
                "/p/2": f_common,
                "/p/66": f_common,
                "/p/53": f_common,
            }
        return result

    def homeVideoContent(self):
        html = self._fetch("/p/1")
        return {"list": self._parse_list(html)[:30]}

    def categoryContent(self, tid, pg, filter=False, extend=None):
        pg = int(pg or 1)
        extend = extend if isinstance(extend, dict) else {}
        if isinstance(extend, str) and extend.strip().startswith("{"):
            try:
                extend = json.loads(extend)
            except Exception:
                extend = {}
        path = str(tid or "/p/1").strip()
        class_id = extend.get("class_id") or ""
        if class_id:
            path += class_id
        qs = []
        if extend.get("area_id"):
            qs.append("area_id=%s" % extend["area_id"])
        if extend.get("year"):
            qs.append("year=%s" % extend["year"])
        if pg > 1:
            qs.append("page=%d" % pg)
        if qs:
            path += ("&" if "?" in path else "?") + "&".join(qs)
        html = self._fetch(path)
        videos = self._parse_list(html)
        return {
            "list": videos,
            "page": pg,
            "pagecount": pg + 1 if len(videos) >= 12 else max(pg, 1),
            "limit": 30,
            "total": 99999,
        }

    def searchContent(self, key, quick=False, pg=1):
        return self.searchContentPage(key, quick, pg)

    def searchContentPage(self, key, quick=False, pg=1):
        pg = int(pg or 1)
        key = str(key or "").strip()
        if not key:
            return {"list": [], "page": 1, "pagecount": 1, "limit": 20, "total": 0}
        path = "/search?q=%s" % urllib.parse.quote(key)
        if pg > 1:
            path += "&page=%d" % pg
        html = self._fetch(path)
        videos = self._parse_list(html)
        return {
            "list": videos,
            "page": pg,
            "pagecount": pg + 1 if len(videos) >= 12 else pg,
            "limit": 30,
            "total": len(videos),
        }

    def detailContent(self, ids):
        raw = str((ids or [""])[0]).strip()
        path = raw if raw.startswith("/") else ("/" + raw)
        html = self._fetch(path)
        name = "正片"
        m = re.search(r"<title>(.*?)</title>", html or "", re.I)
        if m:
            name = self._clean(m.group(1).split("-")[0])
        pic = ""
        m = re.search(
            r'property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']',
            html or "",
            re.I,
        )
        if m:
            pic = self._abs(m.group(1).strip())
        content = "PTT01 官方直连专线"
        m = re.search(
            r'class=["\'][^"\']*(?:detail|intro|summary|content)[^"\']*["\'][^>]*>([\s\S]*?)</div>',
            html or "",
            re.I,
        )
        if m:
            d = self._clean(m.group(1))
            if d:
                content = d[:250]

        play_items = []
        streams = re.findall(r'https?://[^"\'\s<>]+\.m3u8[^"\'\s<>]*', html or "")
        if streams:
            play_items.append("正片$%s" % streams[0].replace("\\/", "/"))
        else:
            seen = set()
            for m in re.finditer(
                r'<a[^>]+href=["\'](/v/\d+[^"\']*)["\'][^>]*>([\s\S]*?)</a>',
                html or "",
                re.I,
            ):
                href, text = m.group(1), self._clean(m.group(2))
                if not text or any(x in text for x in ("快捷键", "XVIDEOS", "广告")):
                    continue
                if href in seen:
                    continue
                seen.add(href)
                play_items.append("%s$%s" % (text, href))

        full = (
            "【🔥 官方交流群: %s】\n【当前发布域名: %s】\n━━━━━━━━━━━━━━━━\n%s"
            % (TG, HOST, content)
        )
        return {
            "list": [
                {
                    "vod_id": path,
                    "vod_name": name,
                    "vod_pic": pic,
                    "vod_actor": "🦋 TG群: @tvshare23",
                    "vod_director": "🦋 蝴蝶影视",
                    "vod_remarks": self._remarks("HD原画"),
                    "vod_content": full,
                    "vod_play_from": "PTT01专线",
                    "vod_play_url": "#".join(play_items) if play_items else "",
                    "style": {"type": "rect", "ratio": 0.75},
                }
            ]
        }

    def playerContent(self, flag, id, vipFlags=None):
        head = {"User-Agent": UA, "Referer": HOST + "/", "Origin": HOST}
        play = str(id or "").strip()
        if "$" in play:
            play = play.split("$")[-1].strip()
        if play.startswith("http") and re.search(r"\.(m3u8|mp4)(\?|$)", play, re.I):
            return {
                "parse": 0,
                "jx": 0,
                "url": play,
                "header": head,
                "format": "application/x-mpegURL"
                if ".m3u8" in play.lower()
                else "video/mp4",
            }
        if play.startswith("/v/") or (play.startswith("/") and not play.startswith("http")):
            html = self._fetch(play)
            m = re.search(r'https?://[^"\'\s<>]+\.m3u8[^"\'\s<>]*', html or "")
            if m:
                play = m.group(0).replace("\\/", "/")
                return {
                    "parse": 0,
                    "jx": 0,
                    "url": play,
                    "header": head,
                    "format": "application/x-mpegURL",
                }
        return {"parse": 0, "jx": 0, "url": self._abs(play), "header": head}

    def isVideoFormat(self, url):
        return bool(url and re.search(r"\.(mp4|m3u8|flv)(\?|$)", str(url), re.I))

    def manualVideoCheck(self):
        return False

    def localProxy(self, param):
        return None


if __name__ == "__main__":
    sp = Spider()
    sp.init()
    print("home", [c["type_name"] for c in sp.homeContent(True)["class"]])
    hv = sp.homeVideoContent()
    print("homeVod", len(hv.get("list") or []))
    r = sp.categoryContent("/p/1", 1, False, {})
    print("cat", len(r.get("list") or []), (r["list"][0]["vod_name"] if r.get("list") else None))
    if r.get("list"):
        d = sp.detailContent([r["list"][0]["vod_id"]])
        main = d["list"][0]
        print("detail", main.get("vod_name"), main.get("vod_play_from"))
        pu = (main.get("vod_play_url") or "").split("#")[0]
        if "$" in pu:
            p = sp.playerContent("PTT01专线", pu.split("$", 1)[1], [])
            print("play", p.get("parse"), str(p.get("url"))[:90])

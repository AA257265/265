import base64
import binascii
import ipaddress
import json
import os
import re
import socket
import struct
from typing import Any, Dict, List, Optional, Set, Tuple, Union
try:
    from collections.abc import Mapping, Sequence
except Exception:  # Python 3.6 / YIWO Chaquopy 回退
    from collections import Mapping, Sequence  # type: ignore
from urllib.parse import parse_qsl, quote, unquote, urlsplit
import requests
try:
    from Crypto.Cipher import AES as _PY_AES
except Exception:
    _PY_AES = None
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _HAS_CRYPTOGRAPHY = True
except Exception:
    Cipher = None
    algorithms = None
    modes = None
    _HAS_CRYPTOGRAPHY = False


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if _PY_AES is not None:
        return _PY_AES.new(key, _PY_AES.MODE_CBC, iv).decrypt(data)
    if _HAS_CRYPTOGRAPHY:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return decryptor.update(data) + decryptor.finalize()
    raise HongguoPluginError("红果响应解密失败")


def _hg_popcount(x: int) -> int:
    return bin(x & 0xFFFFFFFF).count("1")


def _hg_s8(v: int) -> int:
    v &= 0xFF
    return v - 256 if v >= 128 else v


def _hg_strncmp0(a: Union[bytes, bytearray], b: bytes, n: int) -> bool:
    for k in range(n):
        ca = a[k] if k < len(a) else 0
        cb = b[k] if k < len(b) else 0
        if ca != cb:
            return False
        if ca == 0:
            return True
    return True


def _hg_unwrap_v1(spade: Union[bytes, str], flag: int = 0) -> Optional[str]:
    try:
        if isinstance(spade, str):
            spade = bytes.fromhex(spade)
        L = len(spade)
        if L < 3:
            return None
        bVar5 = spade[0] ^ spade[1] ^ spade[2]
        iVar9 = bVar5 - 0x30
        if iVar9 < 1:
            return None
        uVar1 = (L - bVar5) + 0x2F
        if uVar1 < 1 or 1 + uVar1 > L:
            return None
        dest = bytearray(spade[1:1 + uVar1])
        s1 = bytearray(iVar9)
        b16 = spade[L - iVar9 - 2]
        b14 = spade[L - iVar9 - 1]
        for i in range(iVar9):
            s1[i] = b14 ^ b16 ^ spade[i + (L - iVar9)]
        if _hg_strncmp0(s1, b"app_v2", iVar9) or _hg_strncmp0(s1, b"web_v2", iVar9):
            return None
        b14, b16 = 0x55, 0xFA
        for i in range(uVar1):
            b6 = dest[i]
            u18 = _hg_popcount(i)
            b3, b7 = b6, b14
            if i & 1:
                b3, b7, b16 = b16, b6, b14
            cVar4 = (u18 + 0x15) if flag else _hg_s8(-0x15 - u18)
            dest[i] = (cVar4 + (b16 ^ b6)) & 0xFF
            b14, b16 = b7, b3
        b0 = dest[0]
        if 0x30 <= b0 <= 0x39:
            u11 = b0 - 0x30
        elif 0x61 <= b0 <= 0x7A:
            u11 = b0 - 0x57
        else:
            return None
        iv9 = uVar1 - (u11 & 0xFF)
        if iv9 < 2:
            return None
        return bytes(dest[1:iv9]).decode("latin1", "replace")
    except Exception:
        return None


def _hg_spade_to_key(spade_a_b64: str) -> Optional[str]:
    try:
        raw = base64.b64decode(str(spade_a_b64 or "") + "=" * (-len(str(spade_a_b64 or "")) % 4), validate=False)
        if len(raw) < 16:
            return None
        key = _hg_unwrap_v1(raw, 0)
        if not key or len(key) != 32:
            return None
        try:
            bytes.fromhex(key)
        except Exception:
            return None
        return key.lower()
    except Exception:
        return None


def _hg_box_iter(d: bytes, s: int, e: int):
    o = s
    n = len(d)
    if e > n:
        e = n
    while o + 8 <= e:
        sz = struct.unpack(">I", d[o:o + 4])[0]
        t = d[o + 4:o + 8]
        hs = 8
        if sz == 1:
            if o + 16 > e:
                break
            sz = struct.unpack(">Q", d[o + 8:o + 16])[0]
            hs = 16
        elif sz == 0:
            sz = e - o
        if sz < 8 or o + sz > e + 16:
            break
        yield t, o, sz, hs
        o += sz


def _hg_find(d: bytes, path: List[bytes], s: int = 0, e: Optional[int] = None):
    if e is None:
        e = len(d)
    for t, o, sz, hs in _hg_box_iter(d, s, e):
        if t == path[0]:
            if len(path) == 1:
                return (o + hs, o + sz)
            return _hg_find(d, path[1:], o + hs, o + sz)
    return None


def _hg_u32(d: bytes, o: int) -> int:
    return struct.unpack(">I", d[o:o + 4])[0]


def _hg_track_samples(d: bytes, handler: bytes):
    mv = _hg_find(d, [b"moov"])
    if not mv:
        return [], []
    traks = [(o + hs, o + sz) for t, o, sz, hs in _hg_box_iter(d, mv[0], mv[1]) if t == b"trak"]

    def _hdlr(tr):
        h = _hg_find(d, [b"mdia", b"hdlr"], tr[0], tr[1])
        return d[h[0] + 8:h[0] + 12] if h else None
    want = [t for t in traks if _hdlr(t) == handler]
    if not want:
        return [], []
    stbl = _hg_find(d, [b"mdia", b"minf", b"stbl"], want[0][0], want[0][1])
    if not stbl:
        return [], []
    stsz = _hg_find(d, [b"stsz"], stbl[0], stbl[1])
    stco = _hg_find(d, [b"stco"], stbl[0], stbl[1])
    co64 = _hg_find(d, [b"co64"], stbl[0], stbl[1])
    stsc = _hg_find(d, [b"stsc"], stbl[0], stbl[1])
    if not stsz or (not stco and not co64) or not stsc:
        return [], []
    ss = _hg_u32(d, stsz[0] + 4)
    cnt = _hg_u32(d, stsz[0] + 8)
    if cnt <= 0 or cnt > 100000:
        return [], []
    sizes = [ss] * cnt if ss else [_hg_u32(d, stsz[0] + 12 + 4 * i) for i in range(cnt)]
    if stco:
        n = _hg_u32(d, stco[0] + 4)
        ch = [_hg_u32(d, stco[0] + 8 + 4 * i) for i in range(n)]
    else:
        n = _hg_u32(d, co64[0] + 4)
        ch = [struct.unpack(">Q", d[co64[0] + 8 + 8 * i:co64[0] + 16 + 8 * i])[0] for i in range(n)]
    ne = _hg_u32(d, stsc[0] + 4)
    runs = [(_hg_u32(d, stsc[0] + 8 + 12 * i), _hg_u32(d, stsc[0] + 12 + 12 * i), _hg_u32(d, stsc[0] + 16 + 12 * i)) for i in range(ne)]
    spc = [0] * len(ch)
    for i, (fc, sp, _sd) in enumerate(runs):
        last = runs[i + 1][0] - 1 if i + 1 < len(runs) else len(ch)
        for c in range(fc, last + 1):
            if 1 <= c <= len(ch):
                spc[c - 1] = sp
    offs: List[int] = []
    si = 0
    for c in range(len(ch)):
        off = ch[c]
        for _ in range(spc[c]):
            if si >= cnt:
                break
            offs.append(off)
            try:
                off += sizes[si]
            except Exception:
                break
            si += 1
    if len(offs) > len(sizes):
        offs = offs[:len(sizes)]
    return sizes, offs


def _hg_trak_senc_iv8(d: bytes, lo: int, hi: int) -> Optional[str]:
    for m in re.finditer(b"senc", d):
        o = m.start()
        if lo <= o < hi:
            p = o + 8 + 4
            if p + 8 <= len(d):
                return d[p:p + 8].hex()
    return None


def _hg_aes_ctr(key: bytes, iv_int: int, data: bytes) -> bytes:
    if _PY_AES is not None:
        try:
            from Crypto.Util.Counter import new as _ctr_new
            ctr = _ctr_new(128, initial_value=iv_int)
            return _PY_AES.new(key, _PY_AES.MODE_CTR, counter=ctr).decrypt(bytes(data))
        except Exception:
            pass
    # manual CTR via ECB (no extra dep, TV-safe)
    try:
        ecb = _PY_AES.new(key, _PY_AES.MODE_ECB) if _PY_AES is not None else None
    except Exception:
        ecb = None
    if ecb is not None:
        out = bytearray(len(data))
        blocks = (len(data) + 15) // 16
        for b in range(blocks):
            ks = ecb.encrypt((iv_int + b).to_bytes(16, "big"))
            s = b * 16
            chunk = data[s:s + 16]
            for j in range(len(chunk)):
                out[s + j] = chunk[j] ^ ks[j]
        return bytes(out)
    if _HAS_CRYPTOGRAPHY:
        from cryptography.hazmat.primitives.ciphers import Cipher as _C, algorithms as _A, modes as _M
        encryptor = _C(_A.AES(key), _M.CTR(iv_int.to_bytes(16, "big"))).encryptor()
        return encryptor.update(bytes(data)) + encryptor.finalize()
    raise HongguoPluginError("红果解密缺少AES环境")


def _hg_nal_ok(pt: bytes, sz: int) -> bool:
    p = 0
    try:
        while p + 4 <= sz:
            ln = struct.unpack(">I", pt[p:p + 4])[0]
            if ln == 0 or p + 4 + ln > sz:
                return False
            p += 4 + ln
        return p == sz
    except Exception:
        return False

def _hg_decrypt_range(buf: bytearray, key_hex: str, base_iv64: str, sizes: List[int], offs: List[int], lo: int, hi: int) -> int:
    """CENC 交集解密。buf 對應檔案座標區間 [lo, hi),offs 為檔案座標樣本偏移。
    樣本跨區間邊界時解出交集部分:CTR 從樣本內 block 對齊偏移起算,
    任何樣本只要與本次回應區間有重疊都會被正確解密,杜絕 Invalid NAL length。"""
    try:
        K = bytes.fromhex(key_hex)
    except Exception:
        return 0
    try:
        biv = int(base_iv64, 16)
    except Exception:
        return 0
    buflen = len(buf)
    done = 0
    # ---------------------------------------------------------------- CENC CTR 快速路徑
    # LDPlayer(x86 native bridge)上純 Python 循環構建 keystream 會慢 20 倍以上,
    # 實測 1MB 段解密要 20 秒+,播放器等不到就斷線(Exo Invalid NAL / IJK 循環)。
    # 改用 pycryptodome 的 CTR 模式:每樣本只 1 次 new + 1 次 decrypt,
    # keystream 生成全在 C 層,1MB 段 <1 秒完成。
    try:
        from Crypto.Util import Counter as _HGCounter
    except Exception:
        _HGCounter = None
    if _PY_AES is not None and _HGCounter is not None:
        _done_fast = 0
        for idx, (co, sz) in enumerate(zip(offs, sizes)):
            if sz <= 0 or co < 0:
                continue
            s = co if co > lo else lo
            e = co + sz
            if e > hi:
                e = hi
            if s >= e:
                continue
            bs = s - lo
            be = e - lo
            if bs >= buflen:
                continue
            if be > buflen:
                be = buflen
                e = lo + be
                if s >= e:
                    continue
            try:
                skip = s - co
                blocks_skip = skip >> 4
                skip_rem = skip & 15
                ctr = _HGCounter.new(128, initial_value=((biv + idx) << 64) + blocks_skip)
                cipher = _PY_AES.new(K, _PY_AES.MODE_CTR, counter=ctr)
                data = bytes(buf[bs:be])
                pt = cipher.decrypt(b"\x00" * skip_rem + data)[skip_rem:]
                buf[bs:be] = pt
                _done_fast += 1
            except Exception:
                continue
        return _done_fast
    # fallback:無 Crypto.Util.Counter 時不解(返回 0,調用端原樣回傳)
    return 0


class _hg_moov_cache_holder:
    cache: Dict[str, bytes] = {}
    tables: Dict[str, dict] = {}
    totals: Dict[str, int] = {}


def _hg_patch_moov_enc(buf: bytearray, lo: int, moov_end: int) -> None:
    """硬解/软解全兼容：encv->hvc1 / enca->mp4a + 加密盒同长改free。
    只改moov区间，不碰mdat；同长度替换，box尺寸/偏移/total不受影响。
    把 sinf/senc/saiz/saio/sbgp/sgpd 改成 free，EXO/IJK就不再按加密轨走，
    直接播我们已解密的明文样本；MPV不受影响。限定moov避免误伤mdat。
    """
    try:
        if moov_end <= 0 or lo < 0 or lo >= moov_end:
            return
        end = moov_end - lo
        if end > len(buf):
            end = len(buf)
        if end <= 8:
            return
        try:
            region = bytes(buf[:end])
        except Exception:
            return
        if b"encv" not in region and b"enca" not in region and b"sinf" not in region and b"senc" not in region:
            return
        try:
            region = region.replace(b"encv", b"hvc1").replace(b"enca", b"mp4a")
            # 加密信令盒全部同长改free：尺寸不变，播放器直接当明文轨
            region = region.replace(b"sinf", b"free").replace(b"senc", b"free").replace(b"saiz", b"free").replace(b"saio", b"free").replace(b"sbgp", b"free").replace(b"sgpd", b"free")
            buf[:end] = region
        except Exception:
            pass
    except Exception:
        pass


def _hg_fetch_follow(sess, url, headers, timeout, stream=True):
    """手动跟302（最多5跳）：qznovelvod首跳必302到idouyinvod。
    每跳都带Range，真total从落地页拿；Py3.6兼容，不用新语法。
    返回 (response, final_url)，调用方负责close。
    """
    cur = url
    last = None
    try:
        for _ in range(5):
            try:
                r = sess.get(cur, headers=headers, timeout=timeout, stream=stream, allow_redirects=False)
            except Exception:
                return last, cur
            try:
                code = int(r.status_code or 0)
            except Exception:
                code = 0
            if code in (301, 302, 303, 307, 308):
                try:
                    loc = r.headers.get("Location") or r.headers.get("location") or ""
                except Exception:
                    loc = ""
                try:
                    r.close()
                except Exception:
                    pass
                if not loc:
                    return None, cur
                # 相对Location拼全
                try:
                    if loc.startswith("/"):
                        from urllib.parse import urlsplit as _sp
                        p = _sp(cur)
                        loc = p.scheme + "://" + p.netloc + loc
                except Exception:
                    pass
                cur = loc
                last = None
                continue
            return r, cur
    except Exception:
        pass
    return last, cur


# 行为与数据基线：
# /mnt/test/buye-T/vod/routes/短剧/【短剧】红果短剧.js
# SHA-256 e728c1e8f506e6a88f9e01b6f6fe846d2de5c63711e40e47b3c88743684a4759
MV_PLUGIN = {
    "id": "hongguo",
    "name": "红果短剧",
    "version": "3.0.0",
    "profile": "python-basic-v1",
    "capabilities": {
        "content": True,
        "network": True,
    },
    "concurrency": {
        "content_max_inflight": 1,
        "resolver_max_inflight": 1,
    },
    "timeouts": {
        "startup_ms": 10000,
        "health_ms": 2000,
        "content_ms": 120000,
        "resolver_ms": 1800000,
        "idle_ms": 300000,
    },
    "content_sources": [
        {
            "id": "main",
            "name": "红果短剧",
            "searchable": True,
            "quick_search": True,
            "filterable": True,
            "changeable": False,
        }
    ],
    "config_schema": {
        "type": "object",
        "properties": {},
    },
    "compatibility": {
        "upstream": "hongguo-official-web-v1",
    },
}

# ---------------------------------------------------------------- extra imports
import hashlib
import html as _html_mod
import random
import time as _time_mod

# ================================================================ 新上游:紅果官方直連
# 舊上游 djapi.999888456.xyz(唐三 API)已全面回「请更新到唐三最新版」佔位,點播全斷。
# 改為自包含:官網 hongguoduanju.com SSR(免簽名)做分類/榜單/詳情,
# 官方 App API(字節系全套簽名)做播放資訊;播放解密管線(spade_a -> CENC key
# -> hgcenc 本地代理)與原版完全一致,localProxy 不需改動。
_HG_SITE = "https://hongguoduanju.com"

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36"
)
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_ITEMS = 200
_MAX_FILTER_GROUPS = 64
_MAX_FILTER_OPTIONS = 200
_MAX_PLAY_LINES = 32
_MAX_EPISODES_PER_LINE = 2000
_MAX_MEDIA_OPTIONS = 16
_CATEGORY_RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
_ITEM_PREFIX = "hgv2i_"
_EPISODE_PREFIX = "hgv2e_"
_SERIES_TARGET_PREFIX = "series_id:"
_RAW_TARGET_PREFIX = "raw_id:"
_SAFE_QUERY_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_HEX = re.compile(r"^[0-9A-Fa-f]+$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_ALLOWED_MEDIA_HEADERS = {
    "user-agent": "User-Agent",
    "referer": "Referer",
    "origin": "Origin",
}

# 官網分類/榜單 id 對照
_HG_CATEGORY_CONFIG = (
    ("short", "短剧"),
    ("human", "真人剧"),
    ("comic", "漫剧"),
    ("ai", "AI剧"),
    ("rank_hot", "红果热播榜"),
    ("rank_human", "真人剧热播榜"),
    ("rank_comic", "漫剧热播榜"),
    ("rank_ai", "AI剧热播榜"),
)
_HG_CATEGORY_NAMES = dict(_HG_CATEGORY_CONFIG)
_HG_APP_TABS = {"human": (11, "短剧"), "comic": (19, "热门"), "ai": (11, "AI剧")}
_HG_RANK_ROUTES = {
    "rank_hot": "hot-drama",
    "rank_human": "hot-real-drama",
    "rank_comic": "hot-comic-drama",
    "rank_ai": "hot-ai-drama",
}
_HG_APP_FALLBACK_RANK = {"human": "rank_human", "comic": "rank_comic", "ai": "rank_ai"}
_HG_PAGE_SIZE = 24
_HG_WEB_CACHE_TTL = 150.0
_HG_VIDEO_CACHE_TTL = 14400.0  # 4 小時(上游 url_expire 約 5 小時,取 4h 保守值)
_HG_SEARCH_CACHE_TTL = 300.0
_HG_APP_SEARCH_TAB = 11
# localProxy 單段回應上限(1MB):open-ended Range 一律鉗成此長度,
# 首包快、IJK/Exo 分段續拉(實測 IJK 可正常起播與順播)。
_HG_PROXY_SEG_SIZE = 1048576

# 官網分類篩選;值以 cate_ 開頭時同步帶 cate= 參數提高命中
_HG_FILTER_GROUPS = (
    ("background", "背景", (
        ("现代", "cate_757"), ("都市", "cate_1"), ("古代", "cate_758"), ("乡村", "cate_11"),
        ("年代", "cate_79"), ("架空", "cate_452"), ("职场", "cate_127"), ("民国", "cate_390"),
        ("校园", "cate_4"), ("宫廷", "cate_1153"), ("荒岛", "cate_1162"),
    )),
    ("topic", "主题", (
        ("现言", "cate_1021"), ("女性成长", "cate_1048"), ("脑洞", "cate_262"),
        ("奇幻", "cate_1020"), ("玄幻", "cate_1019"), ("古言", "cate_439"),
        ("战神", "cate_1038"), ("宫斗", "cate_246"), ("仙侠", "cate_1013"),
        ("权谋", "cate_1047"), ("种田", "cate_1180"), ("悬疑", "cate_165"),
        ("喜剧", "cate_303"), ("青春", "cate_297"), ("志怪", "cate_1027"),
        ("法律", "cate_1136"), ("刑侦", "cate_1148"), ("抗战", "cate_504"),
        ("武侠", "cate_1172"), ("动作", "cate_302"), ("科幻", "cate_1092"),
    )),
    ("setting", "设定", (
        ("打脸虐渣", "cate_1051"), ("大女主", "cate_760"), ("马甲", "cate_266"),
        ("重生", "cate_36"), ("穿越", "cate_37"), ("系统", "cate_19"),
        ("先婚后爱", "cate_265"), ("破镜重圆", "cate_475"), ("神豪", "cate_20"),
        ("豪门", "cate_936"), ("赘婿逆袭", "cate_1044"), ("甜宠", "cate_96"),
        ("娱乐圈", "cate_43"), ("神医", "cate_26"), ("追妻火葬场", "cate_616"),
        ("萌宝", "cate_1291"), ("反派主角", "cate_1042"), ("双向救赎", "cate_1200"),
    )),
    ("gender", "受众", (("男频", "1"), ("女频", "0"))),
    ("time", "上新", (("7天内", "1"), ("14天内", "2"), ("30天内", "3"), ("90天内", "4"))),
    ("sort_type", "排序", (("最新", "2"), ("最热", "1"))),
)


def _hg_clean_url(value: Any) -> str:
    text = str(value or "")
    return (text.replace("\\/", "/")
            .replace("\\u0026", "&")
            .replace("&", "&")
            .replace("&", "&"))


def _hg_quality_number(value: Any) -> int:
    text = str(value or "")
    m = re.search(r"(2160|1440|1080|720|576|540|480|360)", text)
    if m:
        return int(m.group(1))
    table = {"1920": 1080, "1280": 720, "1024": 576, "854": 480, "640": 360}
    if text in table:
        return table[text]
    return int(text) if re.fullmatch(r"\d{3,4}", text) else 0


def _hg_quality_label(value: Any) -> str:
    n = _hg_quality_number(value)
    if n:
        return "%dP" % n
    labels = {"low": "流畅", "smooth": "流畅", "medium": "标清", "normal": "高清",
              "high": "超清", "original": "原画", "uhd": "原画", "super_high": "原画"}
    key = str(value or "").lower()
    return labels.get(key, str(value or "自动"))


def _hg_decrypt_spade_url(value: Any, seed_b64: Any) -> str:
    """main_url(加密) + key_seed -> 明文 CDN URL(AES-128-CBC, sha512 推鑰)"""
    if _PY_AES is None:
        raise HongguoPluginError("红果URL解密缺少AES环境")
    encoded = str(value or "")
    if not encoded:
        return ""
    raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4))
    if len(raw) < 5 or raw[0] != 0xA8 or raw[2] != 0x01 or raw[3] != 0x00:
        raise HongguoPluginError("红果URL密文格式无效")
    cipher_len = ((len(raw) - 4) // 16) * 16
    if not cipher_len:
        raise HongguoPluginError("红果URL密文无完整块")
    ks = str(seed_b64 or "").replace("-", "+").replace("_", "/")
    seed = base64.b64decode(ks + "=" * (-len(ks) % 4)) if ks else b""
    constants = bytes.fromhex(
        "4dd4c2e6b83162090e52b3c7a6733ba41cb2462b829ab58a196b39db57177524"
        "f49baf7f08e8d68d26a72e37c1a95a2f1f05a51892aef2949732b62a38aadd58"
    )
    h1 = hashlib.sha512(seed).digest()
    h2 = hashlib.sha512(h1 + constants).digest()
    plain = bytearray(_aes_cbc_decrypt(h2[:16], h2[16:32], raw[4:4 + cipher_len]))
    if plain:
        padding = plain[-1]
        if 1 <= padding <= 16 and padding <= len(plain):
            plain = plain[:len(plain) - padding]
    while plain and plain[-1] == 0:
        plain = plain[:-1]
    return bytes(plain).decode("utf-8", "replace")


# ---------------------------------------------------------------- 官網 SSR 工具
_HG_FN_ARGS_RE = re.compile(
    r'data-fn-name="(?:r|mergeLoaderData)"[^>]*data-fn-args=(?:"([^"]*)"|\'([^\']*)\')'
)


def _hg_brace_json_at(text: str, start_index: int):
    """從 start_index 起括號配平取一個完整 JSON 物件"""
    first = text.index("{", start_index)
    depth = 0
    quote = False
    esc = False
    for i in range(first, len(text)):
        ch = text[i]
        if quote:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                quote = False
            continue
        if ch == '"':
            quote = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0:
                return json.loads(text[first:i + 1])
    raise HongguoPluginError("红果页面数据不完整")


def _hg_walk_find(obj, key: str, depth: int = 0):
    """遞迴尋找含非空 key 值(list/dict)的節點;遇到含 key 的字串再解析一層"""
    if depth > 6:
        return None
    if isinstance(obj, dict):
        v = obj.get(key)
        if (isinstance(v, list) and v) or (isinstance(v, dict) and v):
            return obj
        for vv in obj.values():
            hit = _hg_walk_find(vv, key, depth + 1)
            if hit is not None:
                return hit
    elif isinstance(obj, list):
        for vv in obj:
            hit = _hg_walk_find(vv, key, depth + 1)
            if hit is not None:
                return hit
    elif isinstance(obj, str) and key in obj and len(obj) < _MAX_RESPONSE_BYTES:
        try:
            return _hg_walk_find(json.loads(obj), key, depth + 1)
        except Exception:
            return None
    return None


def _hg_parse_fallback(value: Any) -> str:
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return str(parsed.get("fallback_api") or value)
        except Exception:
            pass
        return value
    if isinstance(value, list):
        return str(value[0]) if value else ""
    if isinstance(value, dict):
        return str(value.get("fallback_api") or "")
    return str(value or "")


# ================================================================ 字節系簽名(移植自 drpys 红果果[短].js,GPL-3.0)
# 演算法實測黑盒:常數與位運算順序 1:1,勿改。
_HG_SM3_IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
]


def _hg_sm3_t(j):
    return 0x79CC4519 if j < 16 else 0x7A879D8A


def _hg_sm3_p0(x):
    return x ^ _hg_rol32(x, 9) ^ _hg_rol32(x, 17)


def _hg_sm3_p1(x):
    return x ^ _hg_rol32(x, 15) ^ _hg_rol32(x, 23)


def _hg_rol32(x, n):
    n &= 31
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _hg_sm3(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    msg = bytearray(data)
    bitlen = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack(">Q", bitlen)
    v = list(_HG_SM3_IV)
    for off in range(0, len(msg), 64):
        b = msg[off:off + 64]
        w = [struct.unpack_from(">I", b, i * 4)[0] for i in range(16)]
        for j in range(16, 68):
            x = w[j - 16] ^ w[j - 9] ^ _hg_rol32(w[j - 3], 15)
            x = _hg_sm3_p1(x)
            w.append((x ^ _hg_rol32(w[j - 13], 7) ^ w[j - 6]) & 0xFFFFFFFF)
        w1 = [w[j] ^ w[j + 4] for j in range(64)]
        a, bb, c, d, e, f, g, h = v
        for j in range(64):
            t = _hg_sm3_t(j)
            if j < 16:
                a12 = a ^ bb ^ c
                ro = _hg_rol32(a, 12)
            else:
                a12 = (a & bb) | (a & c) | (bb & c)
                ro = _hg_rol32(a, 12)
            ss1 = _hg_rol32((ro + e + _hg_rol32(t, j & 31)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ ro
            tt1 = (a12 + d + ss2 + w1[j]) & 0xFFFFFFFF
            if j < 16:
                maj = e ^ f ^ g
            else:
                maj = (e & f) | ((~e & 0xFFFFFFFF) & g)
            tt2 = (maj + h + ss1 + w[j]) & 0xFFFFFFFF
            h = g
            g = _hg_rol32(f, 19)
            f = e
            e = _hg_sm3_p0(tt2)
            d = c
            c = _hg_rol32(bb, 9)
            bb = a
            a = tt1
        for i in range(8):
            v[i] = (v[i] ^ [a, bb, c, d, e, f, g, h][i]) & 0xFFFFFFFF
    return struct.pack(">8I", *v)


# ---------------------------------------------------------------- 基礎位運算
def _hg_u32m(v):
    return v & 0xFFFFFFFF


def _hg_rol32(v, n):
    n &= 31
    x = _hg_u32m(v)
    return _hg_u32m((x << n) | (x >> (32 - n)))


def _hg_ror32(v, n):
    n &= 31
    x = _hg_u32m(v)
    return _hg_u32m((x >> n) | (x << (32 - n)))


def _hg_ror64(v, n):
    n &= 63
    return ((v >> n) | (v << (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _hg_le32(v):
    return struct.pack("<I", _hg_u32m(v))


def _hg_be32(v):
    return struct.pack(">I", _hg_u32m(v))


def _hg_zigzag(v):
    n = int(v)
    return (-n * 2 - 1) if n < 0 else (n * 2)


def _hg_varint(v):
    n = int(v)
    out = bytearray()
    while n > 127:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _hg_proto_field(tag, value, typ="string"):
    if value is None or value == "":
        return b""
    if typ in ("bytes", "string", "message"):
        if typ == "bytes":
            body = bytes(value)
        elif typ == "message":
            body = bytes(value)
        else:
            body = str(value).encode()
        return _hg_varint((tag << 3) | 2) + _hg_varint(len(body)) + body
    if typ == "float":
        body = struct.pack("<f", float(value))
        return _hg_varint((tag << 3) | 5) + body
    # sint / _hg_varint
    v = _hg_zigzag(value) if typ == "sint" else int(value)
    return _hg_varint(tag << 3) + _hg_varint(v)


def _hg_proto(fields):
    return b"".join(_hg_proto_field(t, v, ty) for t, v, ty in fields)


def get_iv(iv, data):
    value = _hg_u32m(iv)
    for i, b in enumerate(data):
        if (i & 1) == 0:
            value = _hg_u32m((value >> 4) ^ value ^ ((value << 6) & 0xFFFFFFFF) ^ b)
        else:
            inner = _hg_u32m((value >> 7) ^ value ^ ((b | ((value << 12) & 0xFFFFFFFF)) & 0xFFFFFFFF))
            value = (~inner) & 0xFFFFFFFF
    return value


def sum_md5(data):
    check = 0x20220420
    for i in range(12):
        if (i & 1) == 0:
            temp = _hg_u32m((check >> 3) ^ check)
            check = _hg_u32m((data[i] ^ ((check << 7) & 0xFFFFFFFF)) ^ temp)
        else:
            temp = _hg_u32m((check >> 5) ^ check)
            check = _hg_u32m(data[i] | ((check << 11) & 0xFFFFFFFF))
            check = (~check) & 0xFFFFFFFF
            check = _hg_u32m(check ^ temp)
    return _hg_u32m((check | 4) ^ 0x1000000)


# ---------------------------------------------------------------- F13/medusa 雜湊
_HG_BRANCH2_SV = [
    0xa7aefe20, 0x7149f1d6, 0x47e4ca07, 0xe9b58f67, 0x93b924de, 0xc614d0f5,
    0x38afe0ef, 0xb2bbad73, 0xe24444c3, 0x9d3aec9b, 0xdf7b37e4, 0xd8b16d40,
    0xf8ac31b8, 0x76b9a90b, 0x31d833ee, 0x953fce64, 0x353595a4, 0x4609c13b,
    0x36925008, 0x8c6d0925, 0x5df5c177, 0x1cfbf52b, 0x8a4fa7f0, 0x114ca35e,
    0x8193f984, 0x7a7a8733, 0x316ab4d5, 0x3c20cfc9, 0xa6d84453, 0x3a18500c,
    0x798ec47a, 0x97a76b28, 0x66c4ff96, 0x51716443, 0xdd2fc3b, 0xb5696da7,
    0xbbeb3ac5, 0x5c53d204, 0xd32608ce, 0x7279b9ec, 0xf4188ecf, 0xf7d793db,
    0x332cc491, 0xab76ae15, 0x9bebe727, 0x18a01384, 0x5be9f8a7, 0x5f90a754,
    0x39b663c0, 0x36673c83, 0x7c92f514, 0x9d7d94d7, 0xe2e8d9aa, 0x5f7e9ea9,
    0x7abd4551, 0x569e05da, 0x40a25632, 0x3df5a9a5, 0xbab37d80, 0x454286dc,
    0x3f5d4e78, 0x3d7b75d, 0xb1fe4af7, 0xa5ab26a3,
]
_HG_BRANCH2_ORDERS = bytes.fromhex(
    "0f0704000908030a060b050d0e010c020f05080c0009020103070e060b0a0d04060500070c000a04080f010b0d09020e060b02050403080101070a000d0c090e0d070e0f0b0208030c0509010004060a0d0902060f0b0a040807000c0503010e0c090f07060f030e020d0405010b0a000c050a090e0802040407030f01060b000b0f0408020a0700090d06010e03050c0b060a0508020c03070f0e090d0001040906080f050800040a0b030d01020c0e090d0c0604070a03030f00080105020e01000d0f090a0b0e0402080703060c0501080a0c0f0905060b000304020e070d04080f000c0f0e0d0a01060207090503040205080d0b0a0606000e0f070c09030a08040f000b01060d0c0709030e05020a070b050f00020e0108030d0c0609040d070f08050f06040b0a0e0c090002030d0c020704010b0e0e08060f09050003"
)


def _hg_md5_step(kind, a, b, c, d, m, shift, constant):
    if kind == 0:
        f = (b & c) | ((~b & 0xFFFFFFFF) & d)
    elif kind == 1:
        f = (b & d) | (c & (~d & 0xFFFFFFFF))
    elif kind == 2:
        f = b ^ c ^ d
    else:
        f = c ^ (b | (~d & 0xFFFFFFFF))
    return _hg_u32m(b + _hg_rol32(_hg_u32m(a + f + m + constant), shift))


def _hg_md5_sum_v3(message, count_v2, orders, count_v1):
    sv = [_hg_ror32(v, count_v1) for v in _HG_BRANCH2_SV]
    start = [_hg_ror32(0x79e0f2fb, count_v2), _hg_ror32(0xc8b52570, count_v2),
             _hg_ror32(0xebc2f8cd, count_v2), _hg_ror32(0x7c104d93, count_v2)]
    end_count = (count_v2 + 6) & 255
    end = [_hg_ror32(0x19be4866, end_count), _hg_ror32(0xe85986b4, end_count),
           _hg_ror32(0xe19b326e, end_count), _hg_ror32(0x71d1d7d4, end_count)]
    m = [struct.unpack_from("<I", message, i * 4)[0] for i in range(16)]
    a, b, c, d = start

    def run(kind, shifts, offset):
        nonlocal a, b, c, d
        for i in range(16):
            phase = i & 3
            mv = m[orders[offset + i]]
            cv = sv[offset + i]
            if phase == 0:
                nxt = _hg_md5_step(kind, a, b, c, d, mv, shifts[i], cv)
                a = nxt
            elif phase == 1:
                nxt = _hg_md5_step(kind, d, a, b, c, mv, shifts[i], cv)
                d = nxt
            elif phase == 2:
                nxt = _hg_md5_step(kind, c, d, a, b, mv, shifts[i], cv)
                c = nxt
            else:
                nxt = _hg_md5_step(kind, b, c, d, a, mv, shifts[i], cv)
                b = nxt

    run(0, [7, 12, 17, 22] * 4, 0)
    run(1, [5, 9, 14, 20] * 4, 16)
    run(2, [4, 11, 16, 23] * 4, 32)
    run(3, [6, 10, 15, 21] * 4, 48)
    ret = struct.pack(
        "<4I",
        _hg_u32m((start[0] + a) ^ end[0]),
        _hg_u32m((start[1] + b) ^ end[1]),
        _hg_u32m((start[2] + c) ^ end[2]),
        _hg_u32m((start[3] + d) ^ end[3]),
    )
    return ret + _hg_le32(sum_md5(ret))


def _hg_branch2_f13(iv, query_sm3, body_md5, ts_bytes, khronos):
    v = (iv & 13) * 86
    iv_v0 = ((v >> 15) & 255) + ((v >> 8) & 255)
    n1 = [0x8980f29b, 0xeb549c7f, 0xb08726db, 0xd40cb5e6, 0xe8f559e4][iv_v0]
    count_v1 = (n1 + khronos + 1) & 255
    count_v2 = _hg_u32m(n1 + khronos)
    shift = (count_v2 + 5) & 7
    seed = [0x84, 0x96, 0x77, 0x9d, 0xd4, 0x15, 0x0b, 0xf8]
    pad = bytes((((x | ((x << 8) & 0xFFFF)) >> shift) & 255) for x in seed)
    inp = bytes(query_sm3) + bytes(body_md5) + bytes(ts_bytes) + pad + bytes.fromhex("a0010000")
    return _hg_md5_sum_v3(inp, count_v2, _HG_BRANCH2_ORDERS[iv_v0 << 6:(iv_v0 + 1) << 6], count_v1)


def _hg_bxor(a, b):
    n = min(len(a), len(b))
    return bytes(a[i] ^ b[i] for i in range(n))


def hash_f13(query_sm3, body_md5, ts_bytes, khronos):
    iv = get_iv(get_iv(get_iv(0x20230928, query_sm3), body_md5), ts_bytes)
    low = iv & 15
    iv_v0 = (low * 171) >> 9
    branch = low - iv_v0 * 3
    if branch == 2:
        return _hg_branch2_f13(iv, query_sm3, body_md5, ts_bytes, khronos)
    if branch != 0:
        joined = bytes(query_sm3) + bytes(body_md5)
        return bytes(query_sm3[:16]) + bytes(body_md5) + _hg_le32(sum_md5(joined))
    iv_v1_list = [0xc4a78580, 0xb3c0fd39, 0xc58c5686, 0xc9aa3ba7, 0xf5a7adf2, 0x963c2ed1]
    iv_v1 = iv_v1_list[iv_v0]
    count_v1 = (iv_v1 + khronos + 1) & 255
    count_v2 = _hg_u32m(iv_v1 + khronos)
    tt02 = [
        0xebb64faf, 0x7aadcc2, 0xcf3187bf, 0xe01138ff, 0x6d0bfcff, 0x5a30a3be,
        0xb41ad638, 0x34180eb8, 0xf233eb6f, 0xb1a584cc, 0xccc30dc7, 0x47d1db51,
        0xd55653de, 0x70a84fa1, 0x57473c12, 0xf76f0288, 0x2c077f0a, 0xda0dcad0,
        0xfbb86f6c, 0xfdc4cf00, 0x688a020d, 0xe676c6a6, 0x8cd6338b, 0x1a3c8d0e,
        0xcce8b06b, 0x6ad0ed0b, 0xa0522717, 0xdc71ac83, 0x2285db71, 0xd5b4dda6,
        0x736f8650, 0x6560306c, 0x617ce2a6, 0xe423417e, 0xa40e143, 0x544e4032,
        0x88dffb2a, 0x716c1ae0, 0x4c467a88, 0x5b23bb3, 0xe1d0b866, 0xbaa3dcb8,
        0xae3374d3, 0xc3381a50, 0x1702f75b, 0xfe6da368, 0xf0b4cf48, 0x4e0ffbb8,
        0x72aad10d, 0x26c53a3d, 0xf2bce0f6, 0xb4557581, 0x4a257fdd, 0x8c3182a2,
        0xab0b3b86, 0x3d5dfb14, 0x4f103634, 0xd37b52d7, 0x444eff16, 0xeb0a33d1,
        0x6ca86f6e, 0x284ba7, 0x8387cfa, 0x5fb37586,
    ]
    tt = [_hg_ror32(v, count_v1) for v in tt02]
    n0 = (count_v2 + 2) & 7
    seed = [0xfa, 0x45, 0x61, 0xd7]
    pad = bytes((((x | ((x << 8) & 0xFFFF)) >> n0) & 255) for x in seed)
    data = bytes(query_sm3) + bytes(body_md5) + bytes(ts_bytes) + pad + bytes.fromhex("00000000000001a0")
    di = [struct.unpack_from(">I", data, i)[0] for i in range(0, len(data), 4)]
    di0 = di[0]
    for i in range(112):
        di1 = di[i + 1]
        di14 = di[i + 14]
        r1 = _hg_rol32(di1, 14) ^ _hg_rol32(di1, 25) ^ (di1 >> 3)
        r2 = _hg_rol32(di14, 13) ^ _hg_rol32(di14, 15) ^ (di14 >> 10)
        di.append(_hg_u32m(di0 + di[i + 9] + r1 + r2))
        di0 = di1
    init0 = [0x7aba4fc8, 0x67166507, 0x6403fa00, 0x340f512f,
             984304912, 3005047866, 2874125293, 2152413264]
    init = [_hg_ror32(v, count_v2 & 31) for v in init0]
    chosen = [
        [101, 5, 7, 6, 3, 2, 1, 0, 5, 4, 3], [96, 0, 6, 7, 5, 3, 2, 1, 5, 4, 4],
        [96, 7, 6, 2, 1, 4, 0, 5, 4, 3, 5], [99, 3, 6, 2, 4, 5, 1, 0, 0, 7, 6],
        [96, 0, 5, 6, 7, 3, 1, 2, 5, 4, 4], [100, 2, 0, 3, 5, 4, 6, 7, 2, 1, 5],
    ][iv_v0]
    d = list(init)
    for i in range(chosen[0]):
        base = _hg_u32m(iv_v1 + i)
        n0v = di[base & 127]
        n1 = (((d[chosen[3]] ^ d[chosen[4]]) & d[chosen[1]]) ^ d[chosen[3]])
        n2 = _hg_rol32(d[chosen[1]], 26) ^ _hg_rol32(d[chosen[1]], 21) ^ _hg_rol32(d[chosen[1]], 7)
        n4 = _hg_u32m(n0v + n1 + n2 + tt[base & 63] + d[chosen[5]])
        n5 = _hg_rol32(d[chosen[2]], 30) ^ _hg_rol32(d[chosen[2]], 19) ^ _hg_rol32(d[chosen[2]], 10)
        n6 = (d[chosen[2]] & d[chosen[6]]) | ((d[chosen[2]] | d[chosen[6]]) & d[chosen[7]])
        n7 = _hg_u32m(n5 + n6)
        old = d[chosen[9]]
        d = [d[-1]] + d[:-1]
        d[chosen[10]] = _hg_u32m(n7 + n4)
        d[chosen[8]] = _hg_u32m(old + n4)
    ret = struct.pack(">8I", *[_hg_u32m(d[i] + init[i]) for i in range(8)])
    folded = _hg_bxor(ret[:16], ret[16:])
    ret = folded + ret[16:]
    return ret[:16] + _hg_le32(sum_md5(ret[:16]))


# ---------------------------------------------------------------- x-gorgon
def _hg_reverse_bits(value):
    result = 0
    for i in range(8):
        result = ((result << 1) | ((value >> i) & 1)) & 0xFFFF
    return result & 0xFF


def _hg_rc4_gorgon(data, key):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255
        s[i] = s[j]
    i = 0
    j = 0
    out = bytearray(len(data))
    for k, value in enumerate(data):
        i += 1
        x = s[i]
        j += x
        y = s[j & 255]
        s[i] = y
        out[k] = value ^ s[(y + y) & 255]
    return bytes(out)


def x_gorgon(query, body, timestamp, rnd):
    sdk = struct.pack("<I", 67503104)
    qmd5 = hashlib.md5(query.encode("utf-8") if isinstance(query, str) else query).digest()
    bmd5 = hashlib.md5(body).digest() if body else b"\x00" * 4
    inp = qmd5[:4] + bmd5[:4] + b"\x00" * 4 + sdk + _hg_be32(timestamp)
    key = [0x4A, 0x40, 0x16, (rnd >> 8) & 255, 0x47, 0x6C, 0x01, rnd & 255]
    out = bytearray(_hg_rc4_gorgon(list(inp), key))
    n = len(out)
    for i in range(n):
        value = out[i]
        value = ((value >> 4) | (value << 4)) & 255
        nxt = out[i + 1] if i + 1 < n else out[0]
        out[i] = (~_hg_reverse_bits((nxt ^ value) & 255) ^ 20) & 255
    return (bytes.fromhex("8404") + bytes([rnd & 255, (rnd >> 8) & 255, 0x40, 0x01]) + bytes(out)).hex()


# ---------------------------------------------------------------- protobuf 裝置
def device_proto(device_id, version):
    return _hg_proto([
        (1, 1, "sint"), (2, 2, "sint"), (3, "8662", "string"), (4, device_id, "string"),
        (5, "Ai6svO3PyrwDOUSmO6ZcResxu", "string"), (6, "!noperm!", "string"),
        (7, -888888, "sint"), (8, -888888, "sint"), (9, 3, "sint"), (10, -888888, "sint"),
        (11, "!notset!", "string"), (12, "Asia/Shanghai,8", "string"), (13, "zh_CN", "string"),
        (14, 4, "sint"), (16, 255.24993896484375, "float"), (17, 35.58599090576172, "float"),
        (18, 3.467449188232422, "float"), (19, 3.467449188232422, "float"),
        (20, 255.1754913330078, "float"), (21, 42.17544174194336, "float"),
        (22, "16", "string"), (23, 41, "sint"), (24, 36, "sint"),
        (25, 1728388016635, "sint"), (26, 1728388016635, "sint"), (27, 1728388016635, "sint"),
        (28, 1728388016637, "sint"), (29, -1, "sint"), (30, "25053RT47C", "string"),
        (31, "Redmi", "string"), (32, "25053RT47C", "string"), (33, "25053RT47C", "string"),
        (34, "Xiaomi", "string"), (35, "Redmi", "string"), (36, "Redmi", "string"),
        (38, 31, "sint"),
    ])


# ---------------------------------------------------------------- _HgAesV3 變體
_HG_SBOX = base64.b64decode(
    "+n0Ia5xZs0sEXznQOEqRmQBnpiCf9U2Ccybu3xhmgzOAAxn72f6uqqmwUsYL83klTni0NqxdGieeiNu9PGPsSRXBMB/cuFbUbM3KCUPINaPvHvSW0vwOcnuUhNHqRVpiAj/TEoE0K91+5ijypUYTATsh9mE3KSoN7Yyvv51cuyR2D3XkU4nhmI2xmmVwT1RMWKtub4sjxAcRDLrPoKSO2AU9FLLadMPX577Wf95IFj6FkKFVt3dCIsmGUC4X+WQxLJvxbRxEaOPpqJOXyzJX6+Vxaq3AzMfF/WAdoi1Hp+JRaV56zgpBtpWP97mH4DoGEIq1+FvV8LyS/3wvwugbQOwb2r26mJEMsiuDQTRn+wrYdrVGBVlhI3WQhyrjUBVMrLF5667llUcEaPCGPVGLD8qO5LlO8hKCvA7V9+8oJc9bXelqVQLhM76T5/WtnT45JKji+hdX0HoNCDDWuKON/QeaxB5uImSX0h2wv0VmP2zd2yeApxHcpsVS+MC2yFwAc2B7oBkTqsk1SEvTpM2fmfMQREBUfin0Bh+iq6EvPPavhWI2IX9e3yAas7Tm/3KEj2UmlFp36kN4x0rMLBRrxuh0U/zUHM4xcAMYjJY4MonxOl/X+alpt2M3WMI8w3HLnpIBigtNiJu7T21v4P6lSd5WFgntnMEt7oF92XzRLkJbTcGmXepE/UVOG6E/0YnhfS+q26utWcuxzpooyeD2cDlK1/8w9d28VzsRjbLuALbmGlp8+d7EzS6Au7lMpZ+ECMZvQmzwJ+eLOpxR+2chdUExp8ogQyq3v9l68rX4jCwjg0+PYKAEEzcU4wHFY2ZcdIHfWL1okD3SszT0GZMyKdZJrg1L2AeerB4tC0C4crp2EHGo5FYdSP7lwkeR2ocmnR+Ia8CYviUJlzOjhRZef9xuVOn3qcjow3fQgivsAmKKkg4+sA8F8/GWeDiGNhg8JM8KtFPMYWWkx5TVFX5t73kiNRJqjlIGVXtGZFCV4gzt0xcDopuZ6xz8r9Rzafpf9ywev8jh8592gHFIqpStZPuJxmDDMrNN0uBE3V+oscdoIzTJbRJ/t+sVvqnReJOgDJKk10fjisJwqyZBmnmn2BSFj8BvVtCMEkkuPOKdzw7eA11GPs04Qw8zWtkaZWwiO/wwpojqn6K0jY5RnNZA7vn4hPSul+nKCkVnVwQvg1xVxcSCtqORmB9KrJaBbssbCQivGJVJfVTt+hYxOtq4ZvWl8f4QAQZ0zGPffCgl9s6yT4vlvIdpu4YhBwA25wtQWZsc6GJYGWHyvSdeuh3mmUI9DSq13Fsp8C1MU3tqc04/df9LoTUXVXI5INOw/e8C7Hd+5CvbkMEFnnrUUmskEw=="
)


def _hg_xor_bytes(a, b):
    out = bytearray(a)
    for i in range(len(out)):
        out[i] ^= b[i % len(b)]
    return bytes(out)


def _hg_matrix(b):
    return [list(b[i * 4:i * 4 + 4]) for i in range(4)]


def _hg_flat(rows):
    out = bytearray()
    for r in rows:
        out += bytes(r)
    return bytes(out)


def _hg_aes_mix(rows):
    for i in range(4):
        t = rows[0][i] ^ rows[1][i] ^ rows[2][i] ^ rows[3][i]
        u = rows[0][i]
        xt = lambda x: (((x << 1) ^ (0x1B if (x & 0x80) else 0)) & 0xFF)
        rows[0][i] ^= t ^ xt(rows[0][i] ^ rows[1][i])
        rows[1][i] ^= t ^ xt(rows[1][i] ^ rows[2][i])
        rows[2][i] ^= t ^ xt(rows[2][i] ^ rows[3][i])
        rows[3][i] ^= t ^ xt(rows[3][i] ^ u)


class _HgAesV3:
    def __init__(self, key, khronos):
        self.word_size = khronos & 3
        box_off = self.word_size * 256
        self.box = _HG_SBOX[box_off:box_off + 256]
        self.con = [[1, 0, 2, 3], [1, 3, 0, 2], [0, 1, 3, 2], [1, 0, 2, 3]][self.word_size]
        self.con2 = [[1, 0, 2, 3], [2, 0, 3, 1], [0, 1, 3, 2], [1, 0, 2, 3]][self.word_size]
        self.order = [
            [0, 9, 14, 11, 4, 13, 2, 7, 8, 1, 6, 15, 12, 5, 10, 3],
            [0, 9, 14, 15, 4, 13, 2, 7, 8, 1, 6, 3, 12, 5, 10, 11],
            [0, 9, 14, 7, 4, 13, 2, 11, 8, 1, 6, 3, 12, 5, 10, 15],
            [0, 9, 14, 11, 4, 13, 2, 7, 8, 1, 6, 15, 12, 5, 10, 3],
        ][self.word_size]
        init = [0xCA025DDC, 0x823DC546, 0xC9420583, 0xC298225F][self.word_size]
        initial = struct.pack("<4I", *([init] * 4))
        mk = _hg_xor_bytes(initial, key)
        expanded = bytearray(mk + b"\x00" * 32)
        rounds = 8
        for i in range(4, 12):
            at = 4 * (i - 1)
            a, b, c, d = expanded[at], expanded[at + 1], expanded[at + 2], expanded[at + 3]
            if (i & 3) == 0:
                t = (_hg_u32m(init >> (rounds & 24)) ^ self.box[b]) & 255
                b = self.box[c]
                c = self.box[d]
                d = self.box[a]
                a = t
            rounds += 2
            expanded[at + 4] = a ^ expanded[at - 12]
            expanded[at + 5] = b ^ expanded[at - 11]
            expanded[at + 6] = c ^ expanded[at - 10]
            expanded[at + 7] = d ^ expanded[at - 9]
        self.keys = [list(bytes(expanded[i * 4:i * 4 + 4])) for i in range(12)]

    def _add(self, rows, key):
        for i in range(4):
            for j in range(4):
                rows[i][j] ^= key[i][j]

    def _add_con(self, rows, keys):
        for i in range(4):
            for j in range(4):
                rows[i][j] ^= keys[i][self.con2[j]]

    def _sub(self, rows):
        for i in range(4):
            for j in range(4):
                rows[i][j] = self.box[rows[i][j]]
        old = [list(r) for r in rows]
        for i in range(4):
            rows[i] = list(old[self.con2[i]])

    def _shift(self, rows):
        b = _hg_flat(rows)
        for i in range(16):
            rows[i // 4][i % 4] = b[self.order[i]]

    def _shift_con(self, rows):
        old = [list(r) for r in rows]
        for i in range(4):
            rows[i] = [old[i][x] for x in self.con2]

    def block(self, value):
        rows = _hg_matrix(value)
        self._add_con(rows, self.keys[0:4])
        for i in (1, 2):
            self._sub(rows)
            self._shift(rows)
            if i == 1:
                self._shift_con(rows)
                _hg_aes_mix(rows)
            self._add_con(rows, self.keys[i * 4:i * 4 + 4])
        self._add(rows, self.keys[4:8])
        return _hg_flat(rows)

    def encrypt(self, data, iv):
        source = bytes(data)
        plaintext = bytearray(32)
        for i in range(31):
            at = i * 8
            n0 = (source[at] >> 4) & 2
            n1 = n0 | (source[at + 1] & 64)
            n2 = n1 | ((source[at + 2] >> 2) & 1)
            n3 = n2 | ((source[at + 3] << 3) & 128)
            n4 = n3 | ((source[at + 4] >> 1) & 4)
            n5 = n4 | ((source[at + 5] << 3) & 16)
            n6 = n5 | ((source[at + 6] << 5) & 32)
            plaintext[i] = (n6 | ((source[at + 7] >> 4) & 8)) & 255
        plaintext[31] = 1
        blocks = []
        previous = bytes(iv)
        for i in range(0, len(plaintext), 16):
            value = self.block(_hg_xor_bytes(bytes(plaintext[i:i + 16]), previous))
            blocks.append(value)
            previous = value
        key = b"".join(blocks)
        out = bytearray(source)
        for i in range(31):
            at = i * 8
            k = key[i]
            out[at] = (out[at] & 0xDF) | ((k << 4) & 32)
            out[at + 1] = (out[at + 1] & 0xBF) | (k & 64)
            out[at + 2] = (out[at + 2] & 0xFB) | ((k << 2) & 4)
            out[at + 3] = (out[at + 3] & 0xEF) | ((k >> 3) & 16)
            out[at + 4] = (out[at + 4] & 0xF7) | ((k + k) & 8)
            out[at + 5] = (out[at + 5] & 0xFD) | ((k >> 3) & 2)
            out[at + 6] = (out[at + 6] & 0xFE) | ((k >> 5) & 1)
            out[at + 7] = (out[at + 7] & 0x7F) | ((k << 4) & 128)
        return key[-1:] + bytes(out)


# ---------------------------------------------------------------- _hg_xmxor / _hg_key_hash / medusa / _hg_helios
def _hg_xmxor(data, key):
    data = bytes(data)
    encoded = bytearray(len(data))
    for i in range(len(data)):
        at = (i * 4) & 28
        d0, d1 = key[at], key[at + 1]
        d2 = ((((data[i] << 4) | (data[i] >> 4)) & 255) + d0)
        d2 = (~d2) & 0xFFFFFFFF
        d2 ^= d1
        d2 = d2 & 255
        d2 = (((d2 << 3) | (d2 >> 5)) & 255)
        d2 = (d2 + d1) & 255
        d2 = (d2 ^ d0) & 255
        encoded[len(data) - i - 1] = (~d2) & 255
    last = encoded[-1] ^ encoded[-2]
    first = encoded[0]
    encoded[0] = (~last + first) & 255
    encoded[1] = ((encoded[0] ^ encoded[-1] ^ 254) + encoded[1]) & 255
    encoded[2] = (encoded[2] + ((last - first) ^ (((encoded[1] << 3) | (encoded[1] >> 5)) & 255) ^ 2)) & 255
    for i in range(len(encoded) - 4):
        temp = ((((encoded[i + 2] << 3) | (encoded[i + 2] >> 5)) & 255) ^ encoded[i + 1] ^ (i + 3))
        encoded[i + 3] = (~temp + encoded[i + 3]) & 255
    encoded[-1] ^= encoded[-2]
    total = 0
    for i in range(len(encoded) - 1):
        total += encoded[i + 1]
    encoded[0] = ((encoded[0] ^ encoded[1]) + total) & 255
    return bytes(encoded)


def key_hash(sign_key, rnd):
    inp = bytes(sign_key) + _hg_le32(rnd) + bytes(sign_key)
    h = _hg_sm3(inp)
    d1 = (rnd >> 16) & 255
    d2 = (((d1 << 11) | (rnd >> 24)) & 0xFFFFFFFF) ^ (d1 >> 5) ^ d1
    d2 = (~d2) & 0xFFFFFFFF
    return h, _hg_le32(d2)


_HG_MEDUSA_KEY = bytes.fromhex(
    "8ebdfa3806ecc5cee79423e6029ed82540bc2218bb7eae" "f71cb691f7aa8aa2f5"
)


def build_medusa(url, body, khronos, device):
    body_md5 = hashlib.md5(body).digest() if body else b"\x00" * 16
    query = url.split("?", 1)[1]
    query_sm3 = _hg_sm3(query)
    ts = _hg_le32(khronos)
    query_body_ts = hash_f13(query_sm3, body_md5, ts, khronos)
    nested = _hg_proto([(1, 111, "sint"), (2, 10, "sint"), (3, 694367, "sint"), (5, 586952199, "sint")])
    message_rand = random.randint(0, 0xFFFFFFFF)
    env_launch = random.randint(0, 20) + 100
    env_pid = random.randint(0, 1999) + 10001
    env = _hg_proto([
        (1, env_launch, "sint"), (2, 146331399, "sint"), (3, 146331396, "sint"),
        (5, 7, "sint"), (6, "v04.06.04.03-bugfix", "string"), (7, env_pid, "sint"),
        (12, device_proto(device["device_id"], device["version_name"]), "message"),
        (13, _hg_proto([(1, int(_time_mod.time()), "sint"), (2, -2, "sint"), (4, 200, "sint")]), "message"),
        (14, device["version_name"], "string"),
    ])
    query_hash = _hg_sm3(query.encode("utf-8") + body_md5 + b"none")
    message = _hg_proto([
        (1, bytes.fromhex("f7e85ffad7d7dc3bd62ac87057cf6118"), "bytes"),
        (2, 3, "sint"), (3, message_rand, "sint"), (4, "8662", "string"),
        (5, device["device_id"], "string"), (6, "1588093228", "string"),
        (7, device["version_name"], "string"), (8, "v04.06.04-ml-android", "string"),
        (9, 67503104, "sint"), (10, bytes.fromhex("4001000000000000"), "bytes"),
        (12, khronos, "sint"), (13, query_body_ts, "bytes"),
        (14, query_sm3[:6], "bytes"), (15, nested, "message"),
        (16, "AXYQOS6n2m60x1fVZHIrH3iol", "string"), (17, khronos, "sint"),
        (19, query_hash, "bytes"), (20, "none", "string"), (21, 312, "sint"),
        (23, env, "message"),
        (24, "{\"cmr\":16777216,\"cmr2\":16777216,\"un_h\":1879194040,\"vpn\":0,\"kd\":0,\"fkd\":3672518972,\"pd\":-1872573247,\"dyn\":\"\",\"do\":0,\"tk\":true}", "string"),
    ])
    rnd = random.randint(0, 0xFFFFFFFF)
    h, seed = key_hash(_HG_MEDUSA_KEY, rnd)
    transformed = _hg_xmxor(message, h)
    transformed = (bytes.fromhex("4001000000000000") + transformed)[::-1]
    transformed = bytes(b ^ seed[(~i) & 3] for i, b in enumerate(transformed))
    check = (((query_sm3[0] & 63) << 14) | 0x18000001 | ((query_body_ts[0] & 63) << 8)) & 0xFFFFFFFF
    xm_rand = random.randint(0, 0xFFFFFFFF)
    packed = (bytes([0x35]) + _hg_le32(xm_rand) + _hg_le32(check) + transformed
              + bytes([(rnd >> 16) & 255, (rnd >> 24) & 255]))
    encrypted = _HgAesV3(bytes.fromhex("f1593376766ea98d34f31b057a9d5be4"), khronos).encrypt(
        packed, bytes.fromhex("1fe109a4125283f418de9e051a969e12"))
    version = bytes.fromhex("03000000f7e85ffad7d7dc3bd62ac87057cf6118")
    prefix = bytearray(20)
    for i in range(0, 20, 4):
        prefix[i:i + 4] = struct.pack("<I", _hg_u32m(struct.unpack_from("<I", version, i)[0] ^ khronos))
    return base64.b64encode(bytes(prefix) + bytes([rnd & 255, (rnd >> 8) & 255, 0, 1]) + encrypted).decode("ascii")


def _hg_helios(khronos):
    rnd = random.randint(0, 0xFFFFFFFF)
    data = _hg_le32(rnd) + b"8662"
    digest = hashlib.md5(data).hexdigest().encode("ascii")
    words = [int.from_bytes(digest[i * 8:i * 8 + 8], "little") for i in range(4)]
    table = [words[0]]
    b0 = words[0]
    b8 = words[1]
    rest = words[2:]
    for i in range(34):
        x8 = (_hg_ror64(b8, 8) + b0) & 0xFFFFFFFFFFFFFFFF
        x8 = x8 ^ i
        rest.append(x8)
        x8 = x8 ^ _hg_ror64(b0, 61)
        table.append(x8)
        b0 = x8
        b8 = rest.pop(0)
    text = ("%d-1588093228-8662" % khronos).encode("ascii")
    pad_len = ((len(text) + 1 + 15) // 16) * 16
    fill = 16 - (len(text) % 16)
    pad = bytearray([fill]) * pad_len
    pad[0:len(text)] = text
    output = []
    for at in range(0, len(pad), 16):
        a = int.from_bytes(pad[at:at + 8], "little")
        b = int.from_bytes(pad[at + 8:at + 16], "little")
        for i in range(34):
            b = (table[i] ^ ((a + _hg_ror64(b, 8)) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
            a = (b ^ _hg_ror64(a, 61)) & 0xFFFFFFFFFFFFFFFF
        output.append(struct.pack("<QQ", a, b))
    return base64.b64encode(_hg_le32(rnd) + b"".join(output)).decode("ascii")


def branch_of(url, body, khronos):
    body_md5 = hashlib.md5(body).digest() if body else b"\x00" * 16
    q = _hg_sm3(url.split("?", 1)[1])
    iv = get_iv(get_iv(get_iv(0x20230928, q), body_md5), _hg_le32(khronos))
    low = iv & 15
    return low - ((low * 171) >> 9) * 3


# ---------------------------------------------------------------- query 編碼
def _hg_js_query_encode(values):
    """1:1 移植 JS pythonUrlEncode(鍵序=插入序,保留 *-._~ 與字母數字)"""
    def enc(s):
        out = []
        for b in str(s).encode("utf-8"):
            c = chr(b)
            if ("0" <= c <= "9") or ("a" <= c <= "z") or ("A" <= c <= "Z") or c in "*-._~":
                out.append(c)
            else:
                out.append("%%%02X" % b)
        return "".join(out)
    return "&".join(enc(k) + "=" + enc(v) for k, v in values)


# ---------------------------------------------------------------- 簽名請求
_HG_VIDEO_API = "https://api5-normal-sinfonlineb.fqnovel.com/novel/player/multi_video_model/v1/"
_HG_SEARCH_API = "https://api5-normal-sinfonlinea.fqnovel.com/reading/bookapi/search/tab/v"
_HG_VIDEO_UA = ("com.phoenix.read/73932 (Linux; U; Android 16; zh_CN; 25053RT47C; "
            "Build/BP2A.250605.031.A3; Cronet/TTNetVersion:04657795 2026-01-23 QuicVersion:c67e9834 2025-09-08)")
_HG_APP_UA = "com.phoenix.read/73932 (Linux; U; Android 16; zh_CN; 25053RT47C; Build/BP2A.250605.031.A3)"

# 2026-10-13:上游已拒絕 7.1.x(71332)版本參數,需 7.3.9.32(73932);
# 固定 device_id/iid 長期使用會被風控拉黑 → 改為「隨機裝置身分,
# 持久化於 py 同目錄 hg_device.json,3~5 天隨機輪換一次」:
# 同一進程/重啟都沿用同一身分(除非到期),到期自動換新。


def _hg_device_identity():
    try:
        base = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base, "hg_device.json")
    except Exception:
        path = ""
    now = int(_time_mod.time())
    if path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            did = str(data.get("device_id") or "")
            iid = str(data.get("iid") or "")
            exp = int(data.get("expire") or 0)
            if did and iid and len(did) == 19 and len(iid) == 19 and now < exp:
                return did, iid
        except Exception:
            pass
    did = str(random.randint(1900000000000000, 1999999999999999))
    iid = str(random.randint(1900000000000000, 1999999999999999))
    exp = now + random.randint(3, 5) * 86400  # 3~5 天後輪換
    if path:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"device_id": did, "iid": iid, "expire": exp}, f)
        except Exception:
            pass
    return did, iid


_HG_DEVICE_ID, _HG_IID = _hg_device_identity()

_HG_DEVICE_ORDER = [
    ("iid", _HG_IID), ("device_id", _HG_DEVICE_ID), ("ac", "wifi"),
    ("channel", "update_64"), ("aid", "8662"), ("app_name", "novelread"),
    ("version_code", "73932"), ("version_name", "7.3.9.32"), ("device_platform", "android"),
    ("os", "android"), ("ssmix", "a"), ("device_type", "25053RT47C"),
    ("device_brand", "Redmi"), ("language", "zh"), ("os_api", "36"), ("os_version", "16"),
    ("manifest_version_code", "73932"), ("resolution", "1280*2772"), ("dpi", "520"),
    ("update_version_code", "73932"), ("host_abi", "arm64-v8a"),
    ("dragon_device_type", "phone"), ("pv_player", "73932"), ("compliance_status", "0"),
    ("need_personal_recommend", "1"), ("player_so_load", "1"), ("is_android_pad_screen", "0"),
]

# 2026-10-13 實測:上游對單一裝置的 video_model 配額極低(新裝置約 1 次成功,
# 之後即回 110001);換新裝置立即恢復,但同 IP 短時間連續請求(5 秒內)回 101000
# 頻率限制,連續猛打會升級到 TLS 層斷連。策略(三件套):
#   1)節流:兩次 video_model 請求強制間隔(滑動窗);
#   2)輪換:playerContent 失敗重試時自動換新裝置;
#   3)預取:詳情頁後台線程按節流間隔慢慢取好後續集數,點播時快取秒回;
# 並在連續全敗後 60 秒退避,避免猛打讓 IP 惡化。
_HG_FAIL_COOLDOWN = 60.0
_HG_VM_MIN_GAP = 22.0          # 兩次 video_model 最小間隔(實測 5s 仍 101000,取 22s 留裕量)
_HG_PREFETCH_COUNT = 8          # 詳情頁後台預取的集數
_hg_last_hard_fail = [0.0]  # 用 list 包裝以便模組內賦值
_hg_last_vm_ts = [0.0]


def _hg_rotate_device_identity():
    """輪換裝置身分(刪除持久檔 → 重新生成)"""
    global _HG_DEVICE_ID, _HG_IID
    try:
        base = os.path.dirname(os.path.abspath(__file__))
        p = os.path.join(base, "hg_device.json")
        if os.path.exists(p):
            os.remove(p)
    except Exception:
        pass
    _HG_DEVICE_ID, _HG_IID = _hg_device_identity()
    for i, (k, v) in enumerate(_HG_DEVICE_ORDER):
        if k == "device_id":
            _HG_DEVICE_ORDER[i] = ("device_id", _HG_DEVICE_ID)
        elif k == "iid":
            _HG_DEVICE_ORDER[i] = ("iid", _HG_IID)


def _hg_vm_throttle():
    """節流:距離上次 video_model 請求不足最小間隔 → 補足等待(上限 15s 防 FongMi 超時)"""
    delta = _HG_VM_MIN_GAP - (_time_mod.time() - _hg_last_vm_ts[0])
    if delta > 0:
        _time_mod.sleep(min(delta, 15.0))


def _hg_prefetch_episodes(plug, vids):
    """後台預取:按節流間隔逐集取 video_info 存入快取(daemon 線程用)"""
    for vid in vids:
        try:
            if vid in plug._video_cache:
                continue
            _hg_vm_throttle()
            plug._video_info(vid)
        except Exception:
            try:
                _hg_rotate_device_identity()
            except Exception:
                pass
        _time_mod.sleep(1.0)
_HG_APP_OVERRIDES = {
    "version_code": "73932", "version_name": "7.3.9.32",
    "manifest_version_code": "73932", "update_version_code": "73932", "pv_player": "73932",
}


def _hg_device_map():
    return dict(_HG_DEVICE_ORDER)


def _hg_app_device_map():
    m = dict(_HG_DEVICE_ORDER)
    m.update(_HG_APP_OVERRIDES)
    return m


def _hg_signed_video_request(payload, session=None):
    """POST video_model 用;回傳 (url, headers, body_bytes)"""
    khronos = int(_time_mod.time())
    body = payload.encode("utf-8") if isinstance(payload, str) else payload
    ticket_base = int(_time_mod.time() * 1000)
    d = _hg_device_map()
    request_ticket = ticket_base
    query = ""
    url = ""
    for offset in range(32):
        request_ticket = ticket_base + offset
        values = list(d.items()) + [("ts", str(khronos)), ("_rticket", str(request_ticket))]
        query = _hg_js_query_encode(values)
        url = _HG_VIDEO_API + "?" + query
        if branch_of(url, body, khronos) != 1:
            break
    rnd = random.randint(0, 65535)
    md5hex = hashlib.md5(body).hexdigest().upper()
    headers = {
        "User-Agent": _HG_VIDEO_UA,
        "Accept": "application/json; charset=utf-8,application/x-protobuf",
        "Content-Type": "application/json; charset=UTF-8",
        "x-xs-from-web": "0",
        "x-ss-req-ticket": str(request_ticket),
        "x-tt-request-tag": "t=0;n=0",
        "sdk-version": "2",
        "passport-sdk-version": "50561",
        "x-vc-bdturing-sdk-version": "3.7.2.cn",
        "x-ss-stub": md5hex,
        "x-gorgon": x_gorgon(query, body, khronos, rnd),
        "x-khronos": str(khronos),
        "x-ladon": base64.b64encode(_hg_be32(khronos)).decode("ascii"),
        "x-argus": base64.b64encode(_hg_le32(khronos)).decode("ascii"),
        "x-helios": _hg_helios(khronos),
        "x-medusa": build_medusa(url, body, khronos, d),
        "x-tt-dt": "",
    }
    return url, headers, body


def _hg_signed_app_get_params(values, base_device=None):
    khronos = int(_time_mod.time())
    ticket = int(_time_mod.time() * 1000)
    d = dict(base_device if base_device is not None else _hg_app_device_map())
    ordered = [(k, v) for k, v in d.items()]
    for kv in values:
        ordered.append(kv)
    ordered += [("ts", str(khronos)), ("_rticket", str(ticket))]
    query = _hg_js_query_encode(ordered)
    url = _HG_SEARCH_API + "?" + query
    rnd = random.randint(0, 65535)
    headers = {
        "User-Agent": _HG_APP_UA,
        "Accept": "application/json; charset=utf-8,application/x-protobuf",
        "x-ss-req-ticket": str(ticket),
        "x-tt-request-tag": "t=0;n=0",
        "sdk-version": "2",
        "passport-sdk-version": "50561",
        "x-xs-from-web": "0",
        "x-khronos": str(khronos),
        "x-ladon": base64.b64encode(_hg_be32(khronos)).decode("ascii"),
        "x-argus": base64.b64encode(_hg_le32(khronos)).decode("ascii"),
        "x-gorgon": x_gorgon(query, None, khronos, rnd),
        "x-helios": _hg_helios(khronos),
        "x-medusa": build_medusa(url, None, khronos, d),
        "x-tt-dt": "",
    }
    return url, headers

class HongguoPluginError(RuntimeError):
    """Fail-closed error without upstream IDs, URLs, or response data."""


class _HongguoRetryableRequestError(RuntimeError):
    """Internal marker for one safe retry of an idempotent category GET."""


def _sequence(value: Any) -> List[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def _text(value: Any, fallback: str = "", *, limit: int = 4096) -> str:
    if value is None or value == "":
        value = fallback
    if isinstance(value, (Mapping, Sequence)) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        return ""
    result = str(value or "").strip()
    if any(character in result for character in ("\0", "\r", "\n")):
        result = " ".join(result.split())
    return result[:limit]


def _positive_page(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 1
    return parsed if parsed > 0 else 1


def _strict_string(value: Any, *, max_bytes: int, field: str) -> str:
    if value is None or isinstance(value, (Mapping, list, tuple, set, bytes, bytearray)):
        raise HongguoPluginError(f"红果{field}无效")
    text = str(value).strip()
    if (
        not text
        or any(character in text for character in ("\0", "\r", "\n"))
        or len(text.encode("utf-8")) > max_bytes
    ):
        raise HongguoPluginError(f"红果{field}无效")
    return text


def _encode_opaque(prefix: str, value: Any, *, max_bytes: int) -> str:
    text = _strict_string(value, max_bytes=max_bytes, field="返回引用")
    raw = text.encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{prefix}{encoded}"


def _decode_opaque(prefix: str, value: Any, *, max_bytes: int) -> str:
    text = _strict_string(
        value,
        max_bytes=max_bytes * 2,
        field="引用",
    )
    if not text.startswith(prefix):
        return text
    payload = text[len(prefix) :]
    if not payload or not _B64URL.fullmatch(payload):
        raise HongguoPluginError("红果引用无效")
    padding = "=" * (-len(payload) % 4)
    try:
        raw = base64.b64decode(payload + padding, altchars=b"-_", validate=True)
        decoded = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise HongguoPluginError("红果引用无效") from exc
    if (
        len(raw) > max_bytes
        or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != payload
        or not decoded
        or any(character in decoded for character in ("\0", "\r", "\n"))
    ):
        raise HongguoPluginError("红果引用无效")
    return decoded


def _encode_item_id(value: Any) -> str:
    return _encode_opaque(_ITEM_PREFIX, value, max_bytes=700)


def _decode_item_id(value: Any) -> str:
    return _decode_opaque(_ITEM_PREFIX, value, max_bytes=700)


def _canonical_item_target(value: Any) -> str:
    raw = _strict_string(value, max_bytes=16 * 1024, field="内容引用")
    if raw.startswith("rank_folder:"):
        if len(raw.encode("utf-8")) > 256:
            raise HongguoPluginError("红果内容引用无效")
        return raw
    if len(raw) % 4 != 1 and len(raw) <= 16 * 1024:
        try:
            decoded = base64.b64decode(
                raw + "=" * (-len(raw) % 4),
                validate=True,
            )
            value = json.loads(decoded.decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            value = None
        if isinstance(value, Mapping) and value.get("series_id") not in (None, ""):
            series_id = _strict_string(
                value.get("series_id"),
                max_bytes=512,
                field="剧集身份",
            )
            return f"{_SERIES_TARGET_PREFIX}{series_id}"
    if len(raw.encode("utf-8")) <= 640:
        return f"{_RAW_TARGET_PREFIX}{raw}"
    raise HongguoPluginError("红果内容引用无效")


def _api_item_target(value: str) -> str:
    if value.startswith(_SERIES_TARGET_PREFIX):
        return _strict_string(
            value[len(_SERIES_TARGET_PREFIX) :],
            max_bytes=512,
            field="剧集身份",
        )
    if value.startswith(_RAW_TARGET_PREFIX):
        return _strict_string(
            value[len(_RAW_TARGET_PREFIX) :],
            max_bytes=640,
            field="内容身份",
        )
    return value


def _item_input(value: Any) -> Tuple[str, str, bool]:
    text = _strict_string(value, max_bytes=4096, field="内容引用")
    if text.startswith(_ITEM_PREFIX):
        canonical = _decode_item_id(text)
        return canonical, _api_item_target(canonical), True
    return text, text, False


def _encode_episode_ref(value: Any) -> str:
    return _encode_opaque(_EPISODE_PREFIX, value, max_bytes=2048)


def _decode_episode_ref(value: Any) -> str:
    text = _strict_string(value, max_bytes=4096, field="播放引用")
    if not text.startswith(_EPISODE_PREFIX):
        raise HongguoPluginError("红果播放引用无效")
    return _decode_opaque(_EPISODE_PREFIX, text, max_bytes=2048)

def _categories(value: Any) -> List[Dict[str, str]]:
    result: List[Dict[str, str]] = []
    seen: Set[str] = set()
    for item in _sequence(value)[:_MAX_ITEMS]:
        if not isinstance(item, Mapping):
            continue
        identifier = _text(item.get("type_id") or item.get("id"), limit=256)
        name = _text(item.get("type_name") or item.get("name"), limit=100)
        if (
            not identifier
            or not name
            or identifier in seen
            or identifier.lower().startswith(("http://", "https://"))
        ):
            continue
        seen.add(identifier)
        result.append({"id": identifier, "name": name})
    return result


def _filters(value: Any) -> Dict[str, List[Dict[str, Any]]]:
    if not isinstance(value, Mapping):
        return {}
    result: Dict[str, List[Dict[str, Any]]] = {}
    total_groups = 0
    for raw_category, raw_groups in value.items():
        category_id = _text(raw_category, limit=256)
        if (
            not category_id
            or category_id.lower().startswith(("http://", "https://"))
            or any(character in category_id for character in ("\0", "\r", "\n"))
        ):
            continue
        groups: List[Dict[str, Any]] = []
        for raw_group in _sequence(raw_groups):
            if total_groups >= _MAX_FILTER_GROUPS:
                break
            if not isinstance(raw_group, Mapping):
                continue
            key = _text(raw_group.get("key") or raw_group.get("id"), limit=100)
            name = _text(raw_group.get("name") or raw_group.get("title") or key, limit=100)
            raw_options = (
                raw_group.get("options")
                or raw_group.get("value")
                or raw_group.get("values")
            )
            options: List[Dict[str, str]] = []
            for raw_option in _sequence(raw_options)[:_MAX_FILTER_OPTIONS]:
                if not isinstance(raw_option, Mapping):
                    continue
                option_name = _text(
                    raw_option.get("name")
                    or raw_option.get("n")
                    or raw_option.get("label"),
                    limit=100,
                )
                option_value = _text(
                    raw_option.get("value")
                    if raw_option.get("value") is not None
                    else raw_option.get("v")
                    if raw_option.get("v") is not None
                    else raw_option.get("id"),
                    limit=256,
                )
                if option_name:
                    options.append({"n": option_name, "v": option_value})
            if not key or not name or not options:
                continue
            group: Dict[str, Any] = {"key": key, "name": name, "value": options}
            selected = _text(raw_group.get("selected"), limit=256)
            if selected:
                group["selected"] = selected
            groups.append(group)
            total_groups += 1
        if groups:
            result[category_id] = groups
    return result


def _content_item(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping):
        return None
    try:
        raw_id = _strict_string(
            value.get("vod_id") or value.get("id"),
            max_bytes=16 * 1024,
            field="内容引用",
        )
        canonical_id = _canonical_item_target(raw_id)
    except HongguoPluginError:
        return None
    name = _text(value.get("vod_name") or value.get("name"), limit=300)
    if not raw_id or not name:
        return None
    item: Dict[str, Any] = {
        "id": _encode_item_id(canonical_id),
        "title": name,
        "poster": _text(value.get("vod_pic") or value.get("poster"), limit=2048) or None,
        "remarks": _text(value.get("vod_remarks") or value.get("remarks"), limit=300),
        "navigation": (
            "category"
            if _text(value.get("vod_tag"), limit=32) == "folder"
            or raw_id.startswith("rank_folder:")
            else "detail"
        ),
        "play_sources": [],
    }
    year = _text(value.get("vod_year") or value.get("year"), limit=32)
    if year:
        item["year"] = year
    return item


def _content_items(value: Any) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for raw in _sequence(value)[:_MAX_ITEMS]:
        item = _content_item(raw)
        if item is not None:
            result.append(item)
    return result


def _document(
    kind: str,
    *,
    items: Optional[List[Dict[str, Any]]] = None,
    categories: Optional[List[Dict[str, str]]] = None,
    filters: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    page: int = 1,
    page_count: int = 1,
    limit: int = 18,
    total: Optional[int] = None,
    title: Optional[str] = None,
) -> Dict[str, Any]:
    content_items = items or []
    return {
        "schema_version": "mv.python-content.v1",
        "kind": kind,
        "title": title,
        "categories": categories or [],
        "filters": filters or {},
        "items": content_items,
        "pagination": {
            "page": max(1, page),
            "page_count": max(1, page_count),
            "limit": max(1, limit),
            "total": max(0, len(content_items) if total is None else total),
        },
        "metadata": {
            "upstream_contract": "hongguo-js-v2",
        },
    }



def _query_value(value: Any) -> Optional[str]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)) and not isinstance(value, complex):
        text = str(value).strip()
        if text.casefold() in {"nan", "inf", "+inf", "-inf", "infinity"}:
            return None
        if text and len(text.encode("utf-8")) <= 256 and not any(
            character in text for character in ("\0", "\r", "\n")
        ):
            return text
    return None


def _category_params(
    category_id: str,
    page: int,
    extend: Optional[Dict[str, Any]],
) -> Dict[str, str]:
    result = {"tid": category_id, "pg": str(page)}
    if not isinstance(extend, Mapping):
        return result
    for raw_key, raw_value in list(extend.items())[:32]:
        key = str(raw_key or "")
        if key in {"cateId", "tid", "pg"} or not _SAFE_QUERY_KEY.fullmatch(key):
            continue
        value = _query_value(raw_value)
        if value is not None:
            result[key] = value
    return result


def _play_sources(value: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw_value = value.get("vod_play_url")
    if raw_value is None or raw_value == "":
        return []
    raw_urls = _strict_string(
        raw_value,
        max_bytes=512 * 1024,
        field="播放选集",
    )
    if not raw_urls:
        return []
    lines = raw_urls.split("$$$")
    if len(lines) > _MAX_PLAY_LINES:
        raise HongguoPluginError("红果播放线路过多")
    raw_flags = _text(value.get("vod_play_from"), "播放", limit=4096).split("$$$")
    if len(raw_flags) != len(lines):
        raise HongguoPluginError("红果播放线路无效")
    sources: List[Dict[str, Any]] = []
    for line_index, line in enumerate(lines):
        episodes: List[Dict[str, str]] = []
        entries = [entry for entry in line.split("#") if entry]
        if len(entries) > _MAX_EPISODES_PER_LINE:
            raise HongguoPluginError("红果选集过多")
        for episode_index, entry in enumerate(entries):
            name, separator, raw_ref = entry.partition("$")
            if not separator:
                raw_ref = name
                name = f"第{episode_index + 1}集"
            name = _text(name, f"第{episode_index + 1}集", limit=100)
            raw_ref = _strict_string(
                raw_ref,
                max_bytes=2048,
                field="选集引用",
            )
            episodes.append(
                {
                    "id": f"episode-{line_index + 1}-{episode_index + 1}",
                    "name": name,
                    "ref": _encode_episode_ref(raw_ref),
                }
            )
        if episodes:
            line_name = _text(raw_flags[line_index], f"线路{line_index + 1}", limit=100)
            sources.append(
                {
                    "id": f"line-{line_index + 1}",
                    "name": line_name,
                    "episodes": episodes,
                }
            )
    return sources


def _detail_item(canonical_id: str, value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping):
        return None
    title = _text(value.get("vod_name"), limit=300)
    if not title:
        return None
    extra = {
        key: text
        for key, text in {
            "remarks": _text(value.get("vod_remarks"), limit=300),
            "type_name": _text(value.get("type_name"), limit=100),
            "content": _text(value.get("vod_content"), limit=8192),
        }.items()
        if text
    }
    return {
        "id": _encode_item_id(canonical_id),
        "title": title,
        "poster": _text(value.get("vod_pic"), limit=2048) or None,
        "remarks": extra.get("remarks", ""),
        "navigation": "detail",
        "extra": extra,
        "play_sources": _play_sources(value),
    }


def _media_headers(value: Any) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    result: Dict[str, str] = {}
    total = 0
    for raw_name, raw_value in value.items():
        normalized = str(raw_name or "").strip().casefold()
        name = _ALLOWED_MEDIA_HEADERS.get(normalized)
        header_value = str(raw_value or "").strip()
        if not name or not header_value:
            continue
        if any(character in name + header_value for character in ("\0", "\r", "\n")):
            raise HongguoPluginError("红果播放 Header 无效")
        header_bytes = len(header_value.encode("utf-8"))
        total += len(name.encode("utf-8")) + header_bytes
        if header_bytes > 4096 or total > 8192:
            raise HongguoPluginError("红果播放 Header 过大")
        result[name] = header_value
    return result


def _media_kind(url: str) -> Tuple[str, str, bool]:
    parsed = urlsplit(url)
    path = parsed.path.casefold()
    try:
        query = {
            key.casefold(): value.casefold()
            for key, value in parse_qsl(
                parsed.query,
                keep_blank_values=True,
                max_num_fields=128,
            )
        }
    except ValueError:
        query = {}
    mime = query.get("mime_type", "").replace("-", "_")
    if ".m3u8" in path or mime in {
        "hls",
        "m3u8",
        "application/vnd.apple.mpegurl",
        "application/x_mpegurl",
    }:
        return "remote_hls", "application/vnd.apple.mpegurl", False
    if ".mp4" in path or mime in {"mp4", "video/mp4", "video_mp4"}:
        return "remote_file", "video/mp4", True
    if ".mkv" in path or mime in {"video/x_matroska", "video_mkv"}:
        return "remote_file", "video/x-matroska", True
    if path.endswith(".ts") or mime in {"video/mp2t", "video_mpegts"}:
        return "remote_file", "video/mp2t", True
    return "remote_file", "application/octet-stream", True


def _media_url(value: Any) -> str:
    url = _strict_string(value, max_bytes=8192, field="播放地址")
    try:
        parsed = urlsplit(url)
        port = parsed.port or 443
    except ValueError:
        raise HongguoPluginError("红果播放地址无效") from None
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port != 443
    ):
        raise HongguoPluginError("红果播放地址无效")
    return url



def _media_options(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) % 2:
        raise HongguoPluginError("红果播放候选格式无效")
    if len(value) // 2 > _MAX_MEDIA_OPTIONS:
        raise HongguoPluginError("红果播放候选过多")
    result: List[Dict[str, Any]] = []
    for index in range(0, len(value), 2):
        name = _strict_string(
            value[index],
            max_bytes=400,
            field="播放候选名称",
        )
        url = _media_url(value[index + 1])
        if len(name) > 100:
            raise HongguoPluginError("红果播放候选名称无效")
        kind, content_type, supports_range = _media_kind(url)
        result.append(
            {
                "name": name,
                "kind": kind,
                "url": url,
                "headers": {},
                "header_policy": "protected",
                "content_type": content_type,
                "expires_at": None,
                "supports_range": supports_range,
                "size": 0,
            }
        )
    return result


# ================================================================ HongguoPlugin(官方直連版)
class HongguoPlugin:
    def __init__(self, context: Dict[str, Any]) -> None:
        self._plugin_id = _text(
            (context.get("plugin") or {}).get("id")
            if isinstance(context.get("plugin"), Mapping)
            else "",
            "hongguo",
            limit=64,
        )
        self._session = None  # type: Optional[requests.Session]
        self._web_cache = {}  # type: Dict[str, Tuple[float, Dict[str, Any]]]
        self._video_cache = {}  # type: Dict[str, Tuple[float, Dict[str, Any]]]
        self._video_inflight = {}  # type: Dict[str, bool]  # 併發去重:正在請求中的 vid
        self._search_cache = {}  # type: Dict[Tuple, Tuple[float, Dict[str, Any]]]

    def _http_client(self) -> requests.Session:
        if self._session is None:
            session = requests.Session()
            session.headers.update(
                {
                    "User-Agent": _USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                }
            )
            session.trust_env = False
            session.verify = True
            session.max_redirects = 5
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=2, pool_maxsize=2, max_retries=0
            )
            session.mount("https://", adapter)
            session.mount("http://", adapter)
            self._session = session
        return self._session

    # ------------------------------------------------------------ 官網 SSR ----
    def _web_get(self, path: str, want_key: str, tries: int = 4):
        """抓官網頁面並取出含 want_key 的資料節點;多形態解析 + 重試"""
        cache_key = path + "#" + want_key
        cached = self._web_cache.get(cache_key)
        now = _time_mod.time()
        if cached and now - cached[0] < _HG_WEB_CACHE_TTL:
            return cached[1]
        for attempt in range(tries):
            try:
                session = self._http_client()
                response = session.get(
                    _HG_SITE + path,
                    timeout=(5, 20),
                    allow_redirects=True,
                    headers={"Cache-Control": "no-cache"},
                )
                if response.status_code == 200:
                    page = response.text
                    # 形態A: data-fn-args(r / mergeLoaderData)
                    for m in _HG_FN_ARGS_RE.finditer(page):
                        try:
                            raw = _html_mod.unescape(
                                m.group(1) if m.group(1) is not None else m.group(2)
                            )
                            hit = _hg_walk_find(json.loads(raw), want_key)
                            if hit is not None:
                                self._web_cache[cache_key] = (now, hit)
                                return hit
                        except Exception:
                            continue
                    # 形態B: _ROUTER_DATA = {...} 直塞
                    idx = page.find("_ROUTER_DATA = ")
                    if idx >= 0:
                        try:
                            data = _hg_brace_json_at(page, idx)
                            hit = _hg_walk_find(data, want_key)
                            if hit is not None:
                                self._web_cache[cache_key] = (now, hit)
                                return hit
                        except Exception:
                            pass
            except Exception:
                pass
            _time_mod.sleep(0.3)
        return None

    # ------------------------------------------------------------ 卡片轉換 ----
    def _card_to_vod(self, item: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(item, Mapping):
            return None
        src = item.get("video_data") if isinstance(item.get("video_data"), Mapping) else (
            item.get("video_data")[0] if isinstance(item.get("video_data"), list) and item.get("video_data") else item
        )
        if not isinstance(src, Mapping):
            src = item
        sid = (
            src.get("series_id") or src.get("seriesId") or src.get("id")
            or item.get("seriesId") or item.get("series_id") or item.get("id")
        )
        name = (
            src.get("series_name") or src.get("series_title") or src.get("title")
            or src.get("name") or item.get("title") or item.get("name")
        )
        sid = str(sid or "").strip()
        name = str(name or "").strip()
        if not sid or not name:
            return None
        cover = src.get("series_cover") or src.get("cover") or src.get("cover_url") or ""
        count = src.get("episode_cnt") or src.get("episodeCount") or 0
        try:
            count = int(count)
        except Exception:
            count = 0
        remarks = str(src.get("episode_right_text") or "").strip()
        if not remarks and count:
            remarks = "全%d集" % count
        elif not remarks:
            remarks = str(item.get("episode_right_text") or "").strip()
        return {
            "vod_id": sid,
            "vod_name": name,
            "vod_pic": _hg_clean_url(cover),
            "vod_remarks": remarks,
        }

    def _items_from_rows(self, rows: Any) -> List[Dict[str, Any]]:
        raw = []
        for entry in _sequence(rows)[:_MAX_ITEMS]:
            vod = self._card_to_vod(entry)
            if vod is not None:
                raw.append(vod)
        return _content_items(raw)

    # ------------------------------------------------------------ 榜單/分類 ----
    def _rank_content(self, route: str, page: int) -> Dict[str, Any]:
        if route not in _HG_RANK_ROUTES.values():
            raise HongguoPluginError("红果榜单无效")
        path = "/rank/" + route + ("?page=%d" % page if page > 1 else "")
        hit = self._web_get(path, "rankList")
        if not hit:
            raise _HongguoRetryableRequestError
        rank_list = _sequence(hit.get("rankList"))[:_MAX_ITEMS]
        items = self._items_from_rows(rank_list)
        pagination = hit.get("pagination") if isinstance(hit.get("pagination"), Mapping) else {}
        try:
            total_pages = int(pagination.get("totalPages") or 1)
        except Exception:
            total_pages = 1
        return _document(
            "list",
            items=items,
            page=page,
            page_count=max(1, total_pages),
            limit=_HG_PAGE_SIZE,
            total=9999,
        )

    def _site_category(self, page: int, extend: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        params = {"tab": "1"}
        if isinstance(extend, Mapping):
            for raw_key, raw_value in list(extend.items())[:32]:
                key = str(raw_key or "")
                value = _query_value(raw_value)
                if key in {"cateId", "tid", "pg"} or not _SAFE_QUERY_KEY.fullmatch(key):
                    continue
                if value is None:
                    continue
                params[key] = value
                if str(value).startswith("cate_"):
                    params.setdefault("cate", value)
        pairs = ["%s=%s" % (k, quote(v, safe="")) for k, v in params.items()]
        if page > 1:
            pairs.append("page=%d" % page)
        path = "/category?" + "&".join(pairs)
        hit = self._web_get(path, "recommendList")
        if not hit:
            raise _HongguoRetryableRequestError
        rows = _sequence(hit.get("recommendList"))[:_MAX_ITEMS]
        return _document(
            "list",
            items=self._items_from_rows(rows),
            page=page,
            page_count=9999,
            limit=_HG_PAGE_SIZE,
            total=9999,
        )

    # ------------------------------------------------------------ App 搜尋 ----
    def _app_search_cells(self, cell: Any) -> List[Any]:
        result = []
        if isinstance(cell, Mapping):
            result.append(cell)
        lynx = cell.get("lynx_data") if isinstance(cell, Mapping) else None
        if isinstance(lynx, str) and lynx:
            try:
                payload = json.loads(lynx)
                if isinstance(payload, Mapping):
                    for item in _sequence(payload.get("cell_data"))[:40]:
                        if isinstance(item, Mapping):
                            result.append(item)
            except Exception:
                pass
        return result

    def _app_search_page(self, keyword: str, tab_type: int, page: int, limit: int) -> Dict[str, Any]:
        now = _time_mod.time()
        cache_key = (tab_type, keyword, limit, page)
        cached = self._search_cache.get(cache_key)
        if cached and now - cached[0] < _HG_SEARCH_CACHE_TTL:
            return cached[1]
        cursor = {}  # type: Dict[str, str]
        value = None  # type: Optional[Dict[str, Any]]
        for current in range(1, page + 1):
            step_key = (tab_type, keyword, limit, current)
            step_cached = self._search_cache.get(step_key)
            if step_cached and now - step_cached[0] < _HG_SEARCH_CACHE_TTL:
                value = step_cached[1]
                if current < page and isinstance(value, Mapping):
                    cursor = dict(value.get("cursor") or {})
                continue
            values = [
                ("query", keyword),
                ("count", str(limit)),
                ("offset", str(max(0, (current - 1) * limit))),
                ("tab_type", str(tab_type)),
                ("bookshelf_search_plan", "4"),
                ("use_correct", "true"),
                ("user_is_login", "0"),
            ]
            if cursor.get("search_id"):
                values.append(("search_id", cursor["search_id"]))
            if cursor.get("passback"):
                values.append(("passback", cursor["passback"]))
            url, headers = _hg_signed_app_get_params(values)
            data = {}  # type: Dict[str, Any]
            try:
                response = self._http_client().get(url, headers=headers, timeout=(5, 15))
                if response.status_code == 200:
                    try:
                        data = response.json() or {}
                    except Exception:
                        data = {}
            except Exception:
                data = {}
            tabs = data.get("search_tabs")
            if not isinstance(tabs, list):
                tabs = (data.get("data") or {}).get("search_tabs")
            tab = None
            if isinstance(tabs, list):
                for candidate in tabs:
                    try:
                        if int(candidate.get("tab_type") or 0) == int(tab_type):
                            tab = candidate
                            break
                    except Exception:
                        continue
            cells = _sequence(tab.get("data")) if isinstance(tab, Mapping) else []
            rows = []
            seen = set()
            for cell in cells[:80]:
                for item in self._app_search_cells(cell):
                    video = None
                    vd = item.get("video_data")
                    if isinstance(vd, list) and vd:
                        video = vd[0] if isinstance(vd[0], Mapping) else None
                    elif isinstance(vd, Mapping):
                        video = vd
                    if not isinstance(video, Mapping):
                        continue
                    highlight = item.get("search_high_light")
                    title = ""
                    if isinstance(highlight, Mapping):
                        title = str((highlight.get("title") or {}).get("text") or "")
                    title = title or str(video.get("title") or item.get("cell_name") or "").strip()
                    vid_id = str(
                        video.get("series_id") or item.get("book_id")
                        or item.get("search_result_id") or ""
                    ).strip()
                    if not vid_id or not title or vid_id in seen:
                        continue
                    seen.add(vid_id)
                    count = video.get("episode_cnt") or 0
                    try:
                        count = int(count)
                    except Exception:
                        count = 0
                    rows.append({
                        "vod_id": vid_id,
                        "vod_name": title,
                        "vod_pic": _hg_clean_url(video.get("cover") or video.get("cover_url")),
                        "vod_remarks": ("全%d集" % count) if count else str(
                            video.get("rec_text") or video.get("sub_title") or ""
                        ).strip(),
                    })
            has_more = bool(tab.get("has_more")) if isinstance(tab, Mapping) else False
            value = {
                "list": rows,
                "has_more": has_more,
                "cursor": {
                    "search_id": str(tab.get("search_id") or "") if isinstance(tab, Mapping) else "",
                    "passback": str(tab.get("passback") or "") if isinstance(tab, Mapping) else "",
                },
            }
            # 空結果不長快取(上游間歇回空,下次重簽重試)
            if rows:
                self._search_cache[step_key] = (now, value)
            if current < page:
                cursor = dict(value.get("cursor") or {})
        if value is None:
            raise HongguoPluginError("红果App搜索失败")
        return value

    def _app_category(self, tid: str, page: int) -> Dict[str, Any]:
        tab_type, keyword = _HG_APP_TABS[tid]
        try:
            result = self._app_search_page(keyword, tab_type, page, _HG_PAGE_SIZE)
            rows = _sequence(result.get("list"))[:_MAX_ITEMS]
            items = _content_items(rows)
            if items:
                has_more = bool(result.get("has_more"))
                return _document(
                    "list",
                    items=items,
                    page=page,
                    page_count=(page + 1) if has_more else page,
                    limit=_HG_PAGE_SIZE,
                    total=9999,
                )
        except Exception:
            pass
        fallback_tid = _HG_APP_FALLBACK_RANK[tid]
        return self._rank_content(_HG_RANK_ROUTES[fallback_tid], page)

    # ------------------------------------------------------------ T3 介面 ----
    def homeContent(self, filter: bool = False) -> Dict[str, Any]:
        del filter
        categories = [{"id": cid, "name": name} for cid, name in _HG_CATEGORY_CONFIG]
        filters: Dict[str, List[Dict[str, Any]]] = {}
        for cid in ("short", "human", "comic", "ai"):
            groups: List[Dict[str, Any]] = []
            for key, name, options in _HG_FILTER_GROUPS:
                values = [{"n": "全部", "v": ""}]
                for option_name, option_value in options[: _MAX_FILTER_OPTIONS]:
                    values.append({"n": option_name, "v": option_value})
                groups.append({"key": key, "name": name, "value": values})
            filters[cid] = groups
        return _document(
            "home",
            items=[],
            categories=categories,
            filters=filters,
            limit=18,
        )

    def categoryContent(
        self,
        tid: str,
        pg: int = 1,
        filter: bool = False,
        extend: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        del filter
        page = _positive_page(pg)
        raw_tid = str(tid or "short").strip() or "short"
        if isinstance(extend, Mapping):
            selected = _text(extend.get("cateId"), limit=700)
            if selected and selected in _HG_CATEGORY_NAMES:
                raw_tid = selected
        if raw_tid in _HG_RANK_ROUTES:
            return self._rank_content(_HG_RANK_ROUTES[raw_tid], page)
        if raw_tid in _HG_APP_TABS:
            return self._app_category(raw_tid, page)
        return self._site_category(page, extend)

    def searchContent(
        self,
        key: str,
        quick: bool = False,
        pg: int = 1,
    ) -> Dict[str, Any]:
        del quick
        keyword = _text(key, limit=300)
        page = _positive_page(pg)
        if not keyword:
            return _document(
                "search", items=[], page=page, page_count=page, limit=18, total=0
            )
        # 1) 官方 App 搜尋(簽名)
        try:
            result = self._app_search_page(keyword, _HG_APP_SEARCH_TAB, page, 20)
            rows = _sequence(result.get("list"))[:_MAX_ITEMS]
            items = _content_items(rows)
            if items:
                has_more = bool(result.get("has_more"))
                return _document(
                    "search",
                    items=items,
                    page=page,
                    page_count=(page + 1) if has_more else page,
                    limit=20,
                    total=9999,
                )
        except Exception:
            pass
        # 2) 官網搜尋 SSR fallback
        try:
            path = "/search/%s?page=%d" % (quote(keyword, safe=""), page)
            hit = self._web_get(path, "searchList")
            if hit:
                rows = _sequence(hit.get("searchList"))[:_MAX_ITEMS]
                items = self._items_from_rows(rows)
                if items:
                    return _document(
                        "search", items=items, page=page,
                        page_count=page + 1, limit=20, total=9999,
                    )
        except Exception:
            pass
        return _document("search", items=[], page=page, page_count=page, limit=20, total=0)

    def _series_to_vod(self, series: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(series, Mapping):
            return None
        name = str(series.get("series_name") or series.get("series_title") or "").strip()
        if not name:
            return None
        vids = []
        for v in _sequence(series.get("vid_list"))[:_MAX_EPISODES_PER_LINE]:
            text = str(v or "").strip()
            if text:
                vids.append(text)
        if not vids:
            return None
        count = series.get("episode_cnt")
        if not count and isinstance(series.get("series_episode_info"), Mapping):
            count = series.get("series_episode_info").get("episode_cnt")
        try:
            count = int(count or 0)
        except Exception:
            count = 0
        remarks = str(series.get("episode_right_text") or "").strip()
        if not remarks and count:
            remarks = "全%d集" % count
        tags = series.get("tags")
        if not isinstance(tags, list):
            tags = []
            for entry in _sequence(series.get("category_list"))[:10]:
                if isinstance(entry, Mapping):
                    tags.append(entry.get("name") or "")
                else:
                    tags.append(entry)
        type_name = "/".join(str(t) for t in tags if t)[:100]
        play_url = "#".join(
            "第%d集$%s" % (index + 1, vid) for index, vid in enumerate(vids)
        )
        return {
            "vod_id": "",
            "vod_name": name,
            "vod_pic": _hg_clean_url(series.get("series_cover")),
            "vod_remarks": remarks,
            "vod_content": str(series.get("series_intro") or ""),
            "type_name": type_name,
            "vod_play_from": "红果",
            "vod_play_url": play_url,
        }

    def detailContent(self, ids: List[str]) -> Dict[str, Any]:
        result: List[Dict[str, Any]] = []
        for encoded_id in _sequence(ids)[:20]:
            canonical_id, raw_id, was_encoded = _item_input(encoded_id)
            if not raw_id:
                continue
            if not was_encoded:
                canonical_id = _canonical_item_target(raw_id)
            path = "/detail?series_id=" + quote(str(raw_id), safe="")
            hit = self._web_get(path, "seriesDetail")
            series = hit.get("seriesDetail") if isinstance(hit, Mapping) else None
            if not isinstance(series, Mapping) or not series:
                continue
            vod = self._series_to_vod(series)
            if vod is None:
                continue
            detail = _detail_item(canonical_id, vod)
            if detail is not None:
                result.append(detail)
                # 後台預取:詳情頁打開後,按節流間隔慢慢取好前 N 集,
                # 用戶點第 2/3 集...時快取秒回(上游滑動窗風控下必備)。
                try:
                    import threading as _hg_threading
                    raw_vids = []
                    for entry in (vod.get("vod_play_url") or "").split("$$$")[0].split("#")[:_HG_PREFETCH_COUNT]:
                        try:
                            _ref = entry.split("$", 1)[1]
                            # _series_to_vod 的 play_url 存 raw vid;Spider 層才是 hgv2e_ 編碼 ref
                            if _ref.startswith(_EPISODE_PREFIX):
                                _ref = _decode_episode_ref(_ref)
                            raw_vids.append(_ref)
                        except Exception:
                            continue
                    if raw_vids:
                        t = _hg_threading.Thread(
                            target=_hg_prefetch_episodes, args=(self, raw_vids),
                            daemon=True,
                        )
                        t.start()
                except Exception:
                    pass  # 預取屬優化,失敗不影響主流程
        return _document(
            "detail",
            items=result,
            page=1,
            page_count=1,
            limit=max(1, len(result)),
            total=len(result),
            title=result[0]["title"] if result else None,
        )

    # ------------------------------------------------------------ 播放 ----
    def _video_info(self, vid: str) -> Dict[str, Any]:
        vid = str(vid or "").strip()
        if not vid:
            raise HongguoPluginError("红果播放引用无效")
        now = _time_mod.time()
        cached = self._video_cache.get(vid)
        if cached and now - cached[0] < _HG_VIDEO_CACHE_TTL:
            return cached[1]
        # 併發去重:若後台預取線程正在取同一集,等它完成(最多 28s),
        # 避免主/背景線程重複請求浪費上游裝置配額(實測重複請求會多等 30s+)
        _waited = 0.0
        while self._video_inflight.get(vid) and _waited < 28.0:
            _time_mod.sleep(0.3)
            _waited += 0.3
            cached = self._video_cache.get(vid)
            if cached and _time_mod.time() - cached[0] < _HG_VIDEO_CACHE_TTL:
                return cached[1]
        self._video_inflight[vid] = True
        try:
            return self._video_info_locked(vid)
        finally:
            try:
                self._video_inflight[vid] = False
            except Exception:
                pass

    def _video_info_locked(self, vid: str) -> Dict[str, Any]:
        now = _time_mod.time()
        cached = self._video_cache.get(vid)
        if cached and now - cached[0] < _HG_VIDEO_CACHE_TTL:
            return cached[1]
        payload = json.dumps(
            {
                "biz_param": {
                    "detail_page_version": 0, "device_level": 3,
                    "disable_digg_stat": False, "need_all_video_definition": True,
                    "need_mp4_align": False, "use_os_player": False,
                    "use_server_dns": False, "video_platform": 1024,
                },
                "mixed_video_id_map": {"1004": [vid]},
            },
            separators=(",", ":"),
        )
        data = None  # type: Optional[Dict[str, Any]]
        # 退避:剛剛才全軍覆沒(3 連敗)→ 60 秒內直接快速失敗,避免猛打惡化 IP 風控
        if _time_mod.time() - _hg_last_hard_fail[0] < _HG_FAIL_COOLDOWN:
            raise _HongguoRetryableRequestError
        for attempt in range(3):
            if attempt > 0:
                # 上游裝置配額極低:第 2 次起自動輪換新裝置再試(實測換裝置立即恢復);
                # 等待遞增(3s/6s)讓 IP 滑動窗冷卻(實測 5 秒內第二發必回 101000)
                _time_mod.sleep(3.0 * attempt)
                try:
                    _hg_rotate_device_identity()
                except Exception:
                    pass
            _hg_vm_throttle()
            _hg_last_vm_ts[0] = _time_mod.time()
            url, headers, body = _hg_signed_video_request(payload)
            try:
                response = self._http_client().post(
                    url, data=body, headers=headers, timeout=(5, 20)
                )
                if response.status_code != 200:
                    if response.status_code in _CATEGORY_RETRYABLE_STATUS:
                        _time_mod.sleep(0.8)
                        continue
                    raise HongguoPluginError("红果播放信息请求失败")
                parsed = response.json()
                if isinstance(parsed, dict):
                    if int(parsed.get("Code") or parsed.get("code") or 0) == 0:
                        data = parsed
                        break
            except HongguoPluginError:
                raise
            except Exception:
                _time_mod.sleep(0.8)
                continue
        if not isinstance(data, dict):
            # 3 連敗:記錄時間,60 秒內不再打上游(退避)
            _hg_last_hard_fail[0] = _time_mod.time()
            raise _HongguoRetryableRequestError
        mapping = data.get("data") if isinstance(data.get("data"), Mapping) else {}
        entry = mapping.get(vid)
        if not isinstance(entry, Mapping):
            for value in mapping.values():
                if isinstance(value, Mapping) and value.get("video_model"):
                    entry = value
                    break
        model = entry.get("video_model") if isinstance(entry, Mapping) else None
        if isinstance(model, str):
            try:
                model = json.loads(model)
            except Exception:
                model = None
        if not isinstance(model, Mapping):
            raise HongguoPluginError("红果播放模型无效")
        fallback = _hg_parse_fallback(model.get("fallback_api"))
        if not fallback:
            raise HongguoPluginError("红果播放回退地址为空")
        try:
            response = self._http_client().get(
                fallback,
                timeout=(5, 20),
                headers={
                    "User-Agent": _HG_VIDEO_UA,
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Referer": "https://novel.snssdk.com/",
                },
            )
            outer = response.json() if response.status_code == 200 else {}
        except Exception:
            raise _HongguoRetryableRequestError
        if not isinstance(outer, Mapping):
            raise HongguoPluginError("红果播放信息无效")
        info = outer.get("video_info")
        if isinstance(info, Mapping):
            info = info.get("data")
        if not isinstance(info, Mapping):
            info = {}
        video_list = info.get("video_list") if isinstance(info.get("video_list"), Mapping) else {}
        key_seed = str(info.get("key_seed") or "")
        rows = []
        for quality_key, item in list(video_list.items())[:_MAX_MEDIA_OPTIONS * 2]:
            if not isinstance(item, Mapping):
                continue
            main_url = _hg_clean_url(item.get("main_url") or "")
            if not main_url:
                continue
            label = _hg_quality_label(
                item.get("quality_desc") or item.get("vheight")
                or item.get("vwidth") or item.get("height") or quality_key
            )
            media_url = main_url
            if key_seed and not main_url.lower().startswith("http"):
                try:
                    media_url = _hg_decrypt_spade_url(main_url, key_seed)
                except Exception:
                    media_url = main_url
            rows.append((label, media_url, item))
        if not rows:
            raise HongguoPluginError("红果播放档位为空")
        rows.sort(key=lambda row: -_hg_quality_number(row[0]))
        flat = []
        for label, media_url, _item in rows:
            flat.append(label)
            flat.append(media_url)
        options = _media_options(flat)
        key_urls: List[Dict[str, str]] = []
        for label, media_url, item in rows:
            kid = str(item.get("kid") or "").strip().lower()
            spade = str(item.get("spade_a") or "").strip()
            if not kid or not spade or not re.fullmatch(r"[0-9a-f]{16,64}", kid):
                continue
            if not media_url.startswith("https://"):
                continue
            key_urls.append(
                {"name": label, "src": media_url, "kid": kid, "spade_a": spade}
            )
        value = {"options": options, "key_urls": key_urls}
        self._video_cache[vid] = (now, value)
        return value

    def playerContent(
        self,
        flag: str,
        id: str,
        vipFlags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        del flag, vipFlags
        raw_id = _decode_episode_ref(id)
        value = self._video_info(raw_id)
        return {
            "schema_version": "mv.python-playback-resolution.v1",
            "kind": "remote_media_options",
            "value": value,
        }

    def destroy(self) -> None:
        if self._session is not None:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None


def create_plugin(context: Dict[str, Any]) -> HongguoPlugin:
    return HongguoPlugin(context)


try:
    from base.spider import Spider as _BaseSpider
except Exception:
    try:
        import sys as _sys
        _sys.path.append("..")
        from base.spider import Spider as _BaseSpider
    except Exception:
        class _BaseSpider:
            pass


def _spider_vod(item):
    try:
        if not isinstance(item, dict):
            return None
        vid = str(item.get("id") or "")
        name = str(item.get("title") or "")
        if not vid or not name:
            return None
        pic = item.get("poster") or ""
        remarks = item.get("remarks") or ""
        vod = {
            "vod_id": vid,
            "vod_name": name,
            "vod_pic": pic if isinstance(pic, str) else "",
            "vod_remarks": remarks if isinstance(remarks, str) else "",
        }
        # 排行榜文件夹必须带 vod_tag=folder，FongMi 靠它决定点进去走
        # categoryContent（不带就会走 detailContent，/detail 查 rank_folder
        # 返回空，榜单点进去就是白板——这就是“排行榜都不能用”根因）。
        try:
            if str(item.get("navigation") or "") == "category":
                vod["vod_tag"] = "folder"
            elif vid.startswith(_ITEM_PREFIX):
                try:
                    _canon = _decode_item_id(vid)
                except Exception:
                    _canon = ""
                if _canon.startswith("rank_folder:"):
                    vod["vod_tag"] = "folder"
        except Exception:
            pass
        return vod
    except Exception:
        return None


def _spider_vod_list(items):
    out = []
    try:
        for it in (items or []):
            v = _spider_vod(it)
            if v is not None:
                out.append(v)
    except Exception:
        pass
    return out


def _spider_detail(mv):
    try:
        if not isinstance(mv, dict):
            return None
        vid = str(mv.get("id") or "")
        name = str(mv.get("title") or "")
        if not vid or not name:
            return None
        extra = mv.get("extra") if isinstance(mv.get("extra"), dict) else {}
        poster = mv.get("poster") or ""
        remarks = mv.get("remarks") or extra.get("remarks", "") or ""
        content = extra.get("content", "") or ""
        type_name = extra.get("type_name", "") or ""
        sources = mv.get("play_sources") or []
        play_from = []
        play_url = []
        for src in sources:
            try:
                if not isinstance(src, dict):
                    continue
                sname = str(src.get("name") or "红果")
                eps = src.get("episodes") or []
                parts = []
                for ep in eps:
                    try:
                        if not isinstance(ep, dict):
                            continue
                        ename = str(ep.get("name") or "")
                        ref = str(ep.get("ref") or "")
                        if not ref:
                            continue
                        if not ename:
                            ename = "正片"
                        parts.append(f"{ename}${ref}")
                    except Exception:
                        continue
                if parts:
                    play_from.append(sname)
                    play_url.append("#".join(parts))
            except Exception:
                continue
        # 多线路：上游 /detail 只给单线“红果”，同一 episode ref 在 /play 有 5 档
        # （1080P/720P/540P/480P/360P）。这里把单线展开成 5 线，同 ref 复用，
        # FongMi 把行名当 flag 回传，Spider.playerContent 按 flag 选档+走解密代理。
        try:
            if len(play_from) == 1 and len(play_url) == 1 and play_url[0]:
                base_line = play_url[0]
                labels = ["1080P", "720P", "540P", "480P", "360P"]
                play_from = [f"红果·{q}" for q in labels]
                play_url = [base_line for _ in labels]
        except Exception:
            pass
        vod = {
            "vod_id": vid,
            "vod_name": name,
            "vod_pic": poster if isinstance(poster, str) else "",
            "vod_remarks": remarks if isinstance(remarks, str) else "",
            "vod_content": content if isinstance(content, str) else "",
            "vod_play_from": "$$$".join(play_from),
            "vod_play_url": "$$$".join(play_url),
        }
        if type_name:
            vod["vod_class"] = type_name
            vod["type_name"] = type_name
        return vod
    except Exception:
        return None


class Spider(_BaseSpider):
    def __init__(self):
        try:
            self._plug = None
        except Exception:
            pass
        self._name = "红果短剧"

    def getName(self):
        return "红果短剧"

    def init(self, extend=""):
        try:
            self._plug = HongguoPlugin({})
        except Exception:
            self._plug = None
        return None

    def _ensure(self):
        if self._plug is None:
            self._plug = HongguoPlugin({})
        return self._plug

    def homeContent(self, filter):
        try:
            plug = self._ensure()
            doc = plug.homeContent()
            cats = doc.get("categories") or []
            classes = []
            seen = set()
            for c in cats:
                try:
                    if not isinstance(c, dict):
                        continue
                    cid = str(c.get("id") or "")
                    cname = str(c.get("name") or "")
                    if not cid or not cname or cid in seen:
                        continue
                    seen.add(cid)
                    classes.append({"type_id": cid, "type_name": cname})
                except Exception:
                    continue
            filters = doc.get("filters") or {}
            if not isinstance(filters, dict):
                filters = {}
            return {"class": classes, "list": [], "filters": filters}
        except Exception:
            return {"class": [], "list": [], "filters": {}}

    def homeVideoContent(self):
        try:
            plug = self._ensure()
            doc = plug.categoryContent("short", 1)
            return {"list": _spider_vod_list(doc.get("items"))}
        except Exception:
            return {"list": []}

    def categoryContent(self, tid, pg, filter, extend):
        try:
            plug = self._ensure()
            try:
                page = int(str(pg or 1))
            except Exception:
                page = 1
            if page < 1:
                page = 1
            if not isinstance(extend, dict):
                extend = {}
            doc = plug.categoryContent(str(tid or "short"), page, False, extend)
            pagination = doc.get("pagination") or {}
            try:
                p = int(pagination.get("page", page))
            except Exception:
                p = page
            try:
                pc = int(pagination.get("page_count", 9999))
            except Exception:
                pc = 9999
            try:
                limit = int(pagination.get("limit", 18))
            except Exception:
                limit = 18
            lst = _spider_vod_list(doc.get("items"))
            return {"page": p, "pagecount": pc, "limit": limit if limit else 18, "total": 999999, "list": lst}
        except Exception:
            try:
                page = int(str(pg or 1))
            except Exception:
                page = 1
            return {"page": page, "pagecount": page, "limit": 18, "total": 0, "list": []}

    def detailContent(self, ids):
        try:
            plug = self._ensure()
            if not isinstance(ids, list):
                ids = [ids]
            doc = plug.detailContent([str(x) for x in ids if str(x)])
            out = []
            for mv in (doc.get("items") or []):
                v = _spider_detail(mv)
                if v is not None:
                    out.append(v)
            return {"list": out}
        except Exception:
            return {"list": []}

    def searchContent(self, key, quick, pg="1"):
        try:
            plug = self._ensure()
            try:
                page = int(str(pg or 1))
            except Exception:
                page = 1
            if page < 1:
                page = 1
            doc = plug.searchContent(str(key or ""), False, page)
            return {"list": _spider_vod_list(doc.get("items")), "page": page}
        except Exception:
            return {"list": [], "page": 1}

    def playerContent(self, flag, id, vipFlags):
        try:
            plug = self._ensure()
            doc = plug.playerContent(str(flag or ""), str(id or ""), None)
            value = doc.get("value") or {}
            options = value.get("options") or []
            key_urls = value.get("key_urls") or []
            if not options:
                return {"parse": 0, "url": "", "header": {}}
            # 多线路：flag 即 _spider_detail 行名“红果·1080P”等，按档名选档；
            # 默认 1080P（上游最高档）。哪线卡换哪线。
            want = ""
            try:
                want = str(flag or "").strip().upper()
            except Exception:
                want = ""
            best = options[0] if isinstance(options[0], dict) else {}
            try:
                # 默认 1080P：上游最高档；无 1080P 才退 options[0]。
                for opt in options:
                    if isinstance(opt, dict) and str(opt.get("name") or "").strip() == "1080P":
                        best = opt
                        break
                hit = None
                for opt in options:
                    if isinstance(opt, dict) and str(opt.get("name") or "").strip().upper() in want:
                        hit = opt
                        break
                if hit is not None:
                    best = hit
                elif not want or want == "红果":
                    for opt in options:
                        if isinstance(opt, dict) and str(opt.get("name") or "").strip() == "1080P":
                            best = opt
                            break
            except Exception:
                pass
            url = str(best.get("url") or "")
            header = best.get("headers") or {}
            if not isinstance(header, dict):
                header = {}
            header = dict(header)
            # Give CDN a browser UA when upstream provides no header; FongMi
            # merges/overrides UA via checkUa, browser UA is safer for qznovelvod.
            try:
                if not header.get("User-Agent"):
                    header["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
            except Exception:
                pass
            # 走本地解密代理：把选中档的 src+kid+spade_a 包进代理 URL，
            # TV 播代理地址即可拿到明文 mp4。解失败 localProxy 内回退直链。
            try:
                best_name = str(best.get("name") or "").strip()
                ku_hit = None
                if isinstance(key_urls, list) and key_urls:
                    for ku in key_urls:
                        if isinstance(ku, dict) and str(ku.get("name") or "").strip() == best_name:
                            ku_hit = ku
                            break
                    if ku_hit is None:
                        for ku in key_urls:
                            if isinstance(ku, dict) and str(ku.get("src") or "") == url:
                                ku_hit = ku
                                break
                if isinstance(ku_hit, dict):
                    src = str(ku_hit.get("src") or "")
                    kid = str(ku_hit.get("kid") or "")
                    spade = str(ku_hit.get("spade_a") or "")
                    key_hex = _hg_spade_to_key(spade)
                    if src.startswith("https://") and key_hex:
                        proxy = (
                            "http://127.0.0.1:9978/proxy?do=py&type=hgcenc"
                            + "&url=" + quote(src, safe="")
                            + "&kid=" + quote(kid, safe="")
                            + "&spade=" + quote(spade, safe="")
                        )
                        return {"parse": 0, "url": proxy, "header": {}}
            except Exception:
                pass
            return {"parse": 0, "url": url, "header": header}
        except Exception:
            return {"parse": 0, "url": "", "header": {}}

    def localProxy(self, param):
        try:
            if not isinstance(param, dict):
                return None
            typ = str(param.get("type") or "")
            if typ != "hgcenc":
                return None
            src = unquote(str(param.get("url") or ""))
            kid = unquote(str(param.get("kid") or ""))
            spade = unquote(str(param.get("spade") or ""))
            if not src.startswith("https://"):
                return [400, "text/plain", "bad url"]
            key_hex = _hg_spade_to_key(spade)
            if not key_hex:
                # 解不出 key 就 302 回退直链，不比原来更差
                return [302, "video/mp4", None, {"Location": src}]
            # Range 透传：TV seek/边下边播靠它；IJK开播爱发bytes=0-1小探针
            range_header = param.get("range") or param.get("Range") or ""
            try:
                range_header = str(range_header or "").strip()
            except Exception:
                range_header = ""
            # 解析请求区间，判断是否为小探针（<16KB），探针走快通避免超时
            req_lo = None
            req_hi = None
            try:
                _m0 = re.match(r"\s*bytes\s*=\s*(\d*)-(\d*)", range_header or "")
                if _m0:
                    _a, _b = _m0.group(1), _m0.group(2)
                    req_lo = int(_a) if _a else 0
                    req_hi = int(_b) if _b else -1
            except Exception:
                req_lo, req_hi = None, None
            is_probe = False
            try:
                # IJK开播探针 bytes=0-1 只认2字节：必须解密+patch后回，否则IJK判坏流。
                # 只有 <=2字节 的才叫探针，其余哪怕<16KB也要走完整解密链。
                if req_lo is not None and req_hi is not None and req_hi >= req_lo:
                    if req_hi - req_lo <= 1:
                        is_probe = True
            except Exception:
                is_probe = False
            # 區間鉗制(對齊 cjs 實戰設計):open-ended / 超大 Range 一律鉗成 1MB 段,
            # 首包只解 1MB 迅速回應,播放器看到 Accept-Ranges 會分段續拉;
            # 已知 total(快取)時同步把上界鉗到 total-1,避免請求越界。
            if req_lo is not None and not is_probe:
                if req_hi is None or req_hi < 0 or (req_hi - req_lo + 1) > _HG_PROXY_SEG_SIZE:
                    req_hi = req_lo + _HG_PROXY_SEG_SIZE - 1
                try:
                    _known_total = (getattr(_hg_moov_cache_holder, "totals", None) or {}).get(src)
                    if _known_total and req_lo >= _known_total:
                        _cr_total = _known_total
                        return [416, "video/mp4", b"", {"Content-Range": "bytes */%d" % _cr_total}]
                    if _known_total and req_hi > _known_total - 1:
                        req_hi = _known_total - 1
                except Exception:
                    pass
            # 上游 CDN 用浏览器 UA 直拉；Referer 会触发 403（实测），绝不能加。
            headers = {"User-Agent": _USER_AGENT}
            if req_lo is not None:
                if req_hi is not None and req_hi >= req_lo:
                    headers["Range"] = "bytes=%d-%d" % (req_lo, req_hi)
                else:
                    headers["Range"] = "bytes=%d-" % req_lo
            elif range_header:
                headers["Range"] = range_header
            try:
                plug = self._ensure()
                sess = plug._http_client()
            except Exception:
                sess = requests.Session()
                sess.trust_env = False
            # qznovelvod首跳必302到idouyinvod：手动跟5跳，每跳都带Range，真total从落地页拿
            r, _final_url = _hg_fetch_follow(sess, src, headers, (5, 30), True)
            if r is None and req_lo is not None and not is_probe:
                # 帶上界的區間可能因越界被上游拒:改 open-ended 重試一次(上游自動鉗到 total-1)
                try:
                    headers["Range"] = "bytes=%d-" % req_lo
                    r, _final_url = _hg_fetch_follow(sess, src, headers, (5, 30), True)
                except Exception:
                    r = None
            if r is None:
                # 上游連不上:回 503 讓播放器重試(下輪通常換到可用 CDN 節點);
                # 302 給密文直鏈只會讓播放器讀到密文而報 Invalid NAL length。
                return [503, "video/mp4", b"", {"Retry-After": "1"}]
            status = int(r.status_code or 0)
            if status not in (200, 206):
                try:
                    r.close()
                except Exception:
                    pass
                if status == 416 and req_lo is not None and not is_probe:
                    try:
                        headers["Range"] = "bytes=%d-" % req_lo
                        r, _final_url = _hg_fetch_follow(sess, src, headers, (5, 30), True)
                        if r is not None:
                            status = int(r.status_code or 0)
                    except Exception:
                        r = None
                    if r is not None and status in (200, 206):
                        pass  # 416 重試 open-ended 成功,繼續走下方正常流程
                    else:
                        _cr_total = (getattr(_hg_moov_cache_holder, "totals", None) or {}).get(src) or "*"
                        return [416, "video/mp4", b"", {"Content-Range": "bytes */%s" % _cr_total}]
                else:
                    return [503, "video/mp4", b"", {"Retry-After": "1"}]
            # content-range 解析出本次区间 [lo,hi] 与全长；IJK认死total必须真值
            lo = 0
            hi = -1
            total = -1
            try:
                cr = r.headers.get("Content-Range") or r.headers.get("content-range") or ""
                if cr:
                    m = re.match(r"\s*bytes\s+(\d+)-(\d+)/(\d+|\*)", cr)
                    if m:
                        lo = int(m.group(1))
                        hi = int(m.group(2))
                        total = -1 if m.group(3) == "*" else int(m.group(3))
                if total < 0:
                    cl = r.headers.get("Content-Length") or r.headers.get("content-length") or ""
                    if cl and str(cl).strip().isdigit():
                        if status == 206 and hi >= lo:
                            # 206本次长度不能当total；IJK验total对不上就判坏流，
                            # 这里先记下本次长度，稍后用缓存/HEAD补真total
                            pass
                        else:
                            total = int(str(cl).strip())
            except Exception:
                pass
            # total真值补齐：优先内存缓存，其次bytes=0-0探针拿Content-Range；
            # 小探针跳过补齐（探针只求快，上游自带的Content-Range已含真total）
            try:
                _HG_TOTALS: Dict[str, int] = getattr(_hg_moov_cache_holder, "totals", None) or {}
                if total <= 0:
                    _cached_total = _HG_TOTALS.get(src)
                    if _cached_total and _cached_total > 0:
                        total = int(_cached_total)
                if total <= 0 and not is_probe:
                    try:
                        _hr, _ = _hg_fetch_follow(sess, src, {"User-Agent": _USER_AGENT, "Range": "bytes=0-0"}, (5, 15), True)
                        _hcr = ""
                        try:
                            if _hr is not None:
                                _hcr = _hr.headers.get("Content-Range") or _hr.headers.get("content-range") or ""
                        except Exception:
                            _hcr = ""
                        try:
                            if _hr is not None:
                                _hr.close()
                        except Exception:
                            pass
                        _mm = re.match(r"\s*bytes\s+\d+-\d+/(\d+)", _hcr or "")
                        if _mm:
                            total = int(_mm.group(1))
                            try:
                                _HG_TOTALS[src] = total
                                setattr(_hg_moov_cache_holder, "totals", _HG_TOTALS)
                            except Exception:
                                pass
                    except Exception:
                        pass
                # 上游给了真total就记下来，同集下次不再探
                try:
                    if total and total > 0:
                        _HG_TOTALS[src] = int(total)
                        setattr(_hg_moov_cache_holder, "totals", _HG_TOTALS)
                except Exception:
                    pass
            except Exception:
                pass
            chunks: List[bytes] = []
            try:
                for ch in r.iter_content(256 * 1024):
                    if ch:
                        chunks.append(ch)
            finally:
                try:
                    r.close()
                except Exception:
                    pass
            data = b"".join(chunks)
            if not data:
                return [302, "video/mp4", None, {"Location": src}]
            if hi < lo:
                hi = lo + len(data) - 1
            # 关键：必须回 Accept-Ranges/Content-Range/Content-Length 四件套，
            # 否则 MPV 会把代理流判成不可 seek（日志：Cannot seek in this stream）。
            # 上游 206 的 Content-Range 自带 total；200 则 total=全长。
            if total < 0:
                if status == 200:
                    total = len(data)
            buf = bytearray(data)
            # IJK开播探针 bytes=0-1 只求2字节ftyp：原样透传+四件套秒回，不解密。
            # 注意：只有<=2字节才走这；IJK首个大区间/拖动小区间一律走完整解密链。
            if is_probe:
                try:
                    _HG_TOTALS_P: Dict[str, int] = getattr(_hg_moov_cache_holder, "totals", None) or {}
                    if total <= 0:
                        _ct = _HG_TOTALS_P.get(src)
                        if _ct and _ct > 0:
                            total = int(_ct)
                except Exception:
                    pass
                out = bytes(buf)
                if status == 206:
                    if total <= 0:
                        _ct2 = None
                        try:
                            _ct2 = (getattr(_hg_moov_cache_holder, "totals", None) or {}).get(src)
                        except Exception:
                            _ct2 = None
                        if _ct2 and _ct2 > 0:
                            total = int(_ct2)
                        else:
                            total = hi + 1
                    return [206, "video/mp4", out, {"Content-Type": "video/mp4", "Accept-Ranges": "bytes", "Content-Range": f"bytes {lo}-{hi}/{total}", "Content-Length": str(len(out))}]
                if total <= 0:
                    total = len(out)
                return [200, "video/mp4", out, {"Content-Type": "video/mp4", "Accept-Ranges": "bytes", "Content-Length": str(len(out))}]
            # moov 必须在 buf 内才能算样本表；首请求通常含 moov（moov 在文件头）。
            # 若本次区间不含 moov（如 seek 到 mdat 深处），先拉前 512KB 取 moov 算表。
            table = bytes(buf)
            try:
                has_moov = b"moov" in bytes(buf[:8 + 256 * 1024]) if len(buf) else False
            except Exception:
                has_moov = False
            moov_end = -1
            # 否则用切片算出的样本序号 idx 会从 0 重数导致 CTR 错位，拖动必花。
            _HG_MOOV_CACHE: Dict[str, bytes] = getattr(_hg_moov_cache_holder, "cache", None) or {}
            try:
                if not has_moov:
                    cached = _HG_MOOV_CACHE.get(src)
                    if cached and b"moov" in cached:
                        table = cached
                        has_moov = True
            except Exception:
                pass
            try:
                if not has_moov:
                    h, _ = _hg_fetch_follow(sess, src, {"User-Agent": _USER_AGENT, "Range": "bytes=0-1048575"}, (5, 30), True)
                    try:
                        head = b"".join([c for c in h.iter_content(256 * 1024) if c]) if h is not None else b""
                    except Exception:
                        head = b""
                    try:
                        if h is not None:
                            h.close()
                    except Exception:
                        pass
                    if head and b"moov" in head:
                        table = head
                        try:
                            _HG_MOOV_CACHE[src] = head
                            setattr(_hg_moov_cache_holder, "cache", _HG_MOOV_CACHE)
                        except Exception:
                            pass
            except Exception:
                pass
            try:
                mv = _hg_find(table, [b"moov"])
                if mv:
                    moov_end = mv[1]
            except Exception as _e2:
                mv = None
            if not mv:
                # 无 moov 表就原样回（不断播），首区间一般不会走到这
                out = bytes(buf)
                if status == 206:
                    if total <= 0:
                        total = hi + 1
                    return [206, "video/mp4", out, {"Content-Type": "video/mp4", "Accept-Ranges": "bytes", "Content-Range": f"bytes {lo}-{hi}/{total}", "Content-Length": str(len(out))}]
                return [200, "video/mp4", out, {"Content-Type": "video/mp4", "Accept-Ranges": "bytes", "Content-Length": str(len(out))}]
            # 找本文件两条加密轨的 senc base_iv（视频/音频各自身 senc）；
            # 命中缓存表直接复用，不再重复解析（IJK连播/切集省下整次moov遍历）。
            try:
                _HG_TABLES: Dict[str, dict] = getattr(_hg_moov_cache_holder, "tables", None) or {}
                _cached_tb = _HG_TABLES.get(src)
            except Exception:
                _HG_TABLES = {}
                _cached_tb = None
            v_iv = None
            a_iv = None
            vsizes: List[int] = []
            voffs: List[int] = []
            asizes: List[int] = []
            aoffs: List[int] = []
            mv_for_patch = None
            table_for_patch = None
            use_cache = False
            try:
                if isinstance(_cached_tb, dict) and _cached_tb.get("v_iv"):
                    v_iv = _cached_tb.get("v_iv")
                    a_iv = _cached_tb.get("a_iv")
                    vsizes = list(_cached_tb.get("vsizes") or [])
                    voffs = list(_cached_tb.get("voffs") or [])
                    asizes = list(_cached_tb.get("asizes") or [])
                    aoffs = list(_cached_tb.get("aoffs") or [])
                    mv_for_patch = None
                    table_for_patch = None
                    use_cache = True
            except Exception:
                use_cache = False
            if not v_iv and not a_iv and not use_cache:
                # 未命中缓存：现解析moov拿 base_iv + 样本表，解析完即缓存
                try:
                    traks = [(o + hs, o + sz) for t, o, sz, hs in _hg_box_iter(table, mv[0], mv[1]) if t == b"trak"]

                    def _hdlr(tr):
                        h = _hg_find(table, [b"mdia", b"hdlr"], tr[0], tr[1])
                        return table[h[0] + 8:h[0] + 12] if h else None
                    vide_range = None
                    soun_range = None
                    for tr in traks:
                        h = _hdlr(tr)
                        if h == b"vide" and vide_range is None:
                            vide_range = tr
                        elif h == b"soun" and soun_range is None:
                            soun_range = tr
                    v_iv = _hg_trak_senc_iv8(table, vide_range[0], vide_range[1]) if vide_range else None
                    a_iv = _hg_trak_senc_iv8(table, soun_range[0], soun_range[1]) if soun_range else None
                except Exception:
                    v_iv, a_iv = None, None
                # 全片样本偏移是按文件绝对偏移算的；样本序号 idx 必须用全局序号
                try:
                    if v_iv:
                        vsizes, voffs = _hg_track_samples(table, b"vide")
                    if a_iv:
                        asizes, aoffs = _hg_track_samples(table, b"soun")
                except Exception:
                    pass
                # 解析成功即缓存：IJK连播/切集/二次seek直接复用
                try:
                    if v_iv:
                        _HG_TABLES[src] = {"v_iv": v_iv, "a_iv": a_iv, "vsizes": list(vsizes), "voffs": list(voffs), "asizes": list(asizes), "aoffs": list(aoffs)}
                        setattr(_hg_moov_cache_holder, "tables", _HG_TABLES)
                except Exception:
                    pass
                mv_for_patch = mv
                table_for_patch = table
            if not v_iv and not a_iv:
                out = bytes(buf)
                if status == 206:
                    if total <= 0:
                        total = hi + 1
                    return [206, "video/mp4", out, {"Content-Type": "video/mp4", "Accept-Ranges": "bytes", "Content-Range": f"bytes {lo}-{hi}/{total}", "Content-Length": str(len(out))}]
                return [200, "video/mp4", out, {"Content-Type": "video/mp4", "Accept-Ranges": "bytes", "Content-Length": str(len(out))}]
            # _hg_decrypt_range 改為「檔案座標」語義:offs 原樣傳,
            # 區間傳 [lo, lo+len(buf)) — 樣本跨本次回應邊界也解交集部分,
            # 播放器分段請求時每段都正確解密,不再產生密文樣本(Invalid NAL length)。
            try:
                if v_iv and vsizes and voffs:
                    _n_done = _hg_decrypt_range(buf, key_hex, v_iv, vsizes, voffs, lo, lo + len(buf))
                if a_iv and asizes and aoffs:
                    _n_done2 = _hg_decrypt_range(buf, key_hex, a_iv, asizes, aoffs, lo, lo + len(buf))
            except Exception:
                pass
            # IJK认死moov四字符码：buf含moov段时把 encv->hvc1 / enca->mp4a，
            # 同长度替换不影响box尺寸；MPV/EXO不受影响。
            try:
                if lo < moov_end and moov_end > 0:
                    _hg_patch_moov_enc(buf, lo, moov_end)
            except Exception:
                pass
            out = bytes(buf)
            if status == 206:
                if total <= 0:
                    total = hi + 1
                headers_out = {
                    "Content-Type": "video/mp4",
                    "Accept-Ranges": "bytes",
                    "Content-Range": f"bytes {lo}-{hi}/{total}",
                    "Content-Length": str(len(out)),
                }
                return [206, "video/mp4", out, headers_out]
            headers_out = {
                "Content-Type": "video/mp4",
                "Accept-Ranges": "bytes",
                "Content-Length": str(len(out)),
            }
            return [200, "video/mp4", out, headers_out]
        except Exception:
            return None

    def isVideoFormat(self, url):
        try:
            u = str(url or "").lower()
            return ("m3u8" in u) or (".mp4" in u) or ("video_mp4" in u) or ("qznovelvod" in u) or ("mime_type=video" in u) or ("hgcenc" in u) or ("127.0.0.1" in u)
        except Exception:
            return False

    def manualVideoCheck(self):
        return False

    def destroy(self):
        try:
            if self._plug is not None:
                try:
                    self._plug.destroy()
                except Exception:
                    pass
                self._plug = None
        except Exception:
            pass
        return None

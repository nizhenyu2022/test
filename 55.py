import hashlib
import random
import re
import sys
import time
import chardet
import requests
import toml

'''
env.js 路径
'''

env_js = "env.js"


def detect_charset(file, fallback="utf-8"):
	with open(file, "rb") as fp:
		detector = chardet.UniversalDetector()
		for line in fp.readlines():
			detector.feed(line)
			if detector.done:
				return detector.result['encoding']
	return fallback


def jifen(appkey):
	try:
		resp = requests.get(
			'http://api.rrocr.com/api/integral.html?appkey=' + appkey)
		ret = resp.json()
		if ret['status'] == 0 and int(ret['integral']) > 0:
			log(f"人人积分{ret['integral']}")
			return ret['integral']
		elif ret['status'] == 0 and int(ret['integral']) == 0:
			log(f"人人积分不足")
			return False
		else:
			log(f"{ret['msg']}")
			return False
	except:
		log("网络请求失败")
		return False


def generate_random_str(randomlength=8):
	random_str = ''
	key_str = 'abcdefghigklmnopqrstuvwxyz0123456789'
	length = len(key_str) - 1
	for i in range(randomlength):
		random_str += key_str[random.randint(0, length)]
	return random_str


def pattern_search(text, pattern):
	res = []
	len1 = len(text)
	len2 = len(pattern)
	for index in range(0, len1 - len2 + 1):
		for char in range(0, len2):
			if text[index + char] != pattern[char]:
				break
		else:
			res.append(index)
	return res


def log(text):
	with open(f"log/log{time.strftime('%Y-%m-%d', time.localtime(time.time()))}.log", 'a+') as fp:
		fp.write(
			f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))}] {text}" + '\n')
	print(f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))}] {text}")


def recognize(appkey, gt, challenge):
	headers = {'Host': 'api.rrocr.com',
			   'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.835.163 Safari/535.1',
			   'Accept': 'text/html', 'Content-Type': 'application/x-www-form-urlencoded', }
	try:
		resp = requests.post(
			'http://api.rrocr.com/api/recognize.html?appkey=' + appkey + '&gt=' + gt + '&challenge=' + challenge + '&referer=http://passport.bilibili.com&sharecode=43ece1f83708402ab67cd3719ce11a31',
			headers=headers, timeout=(35, 35))
		ret = resp.json()
		print(ret)
		if ret['status'] == 0:
			log('人人打码识别成功')
			validate = ret['data']['validate']
			return validate
		else:
			log(f"{ret['msg']}")
			return False
	except:
		log("网络请求失败")
		return False


def get_challenge():
	url = f"https://passport.bilibili.com/web/captcha/combine?plat=6&t={int(time.time() * 1000)}"
	try:
		resp = requests.get(url, timeout=(35, 35)).json()
	except:
		log("网络请求失败")
		return False, False, False
	if resp and resp.get('code') == 0 and resp.get('data') and resp[
		'data'].get('result'):
		challenge = resp['data']['result']['challenge']
		gt = resp['data']['result']['gt']
		key = resp['data']['result']['key']
		log("get_challenge 完成")
		return key, challenge, gt
	else:
		log(resp)
		return False, False, False



def get_pre(url):
	headers = {
		"User-Agent": "Mozilla/5.0 BiliDroid/7.21.0 (bbcallen@gmail.com) os/android model/MuMu mobi_app/android build/7210300 channel/bili innerVer/7210300 osVer/6.0.1 network/2",
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8", }
	requests.get(url, timeout=(35, 35), headers=headers)
	url = f"https://passport.bilibili.com/x/safecenter/captcha/pre"
	data = {"source": "main-fe"}
	try:
		resp = requests.post(url, data=data, timeout=(35, 35),
							 headers=headers).json()
	except:
		log("网络请求失败")
		return False, False, False
	if resp and resp.get('code') == 0 and resp.get('data'):
		gee_challenge = resp['data']['gee_challenge']
		gee_gt = resp['data']['gee_gt']
		recaptcha_token = resp['data']['recaptcha_token']
		log("get_pre 完成")
		return recaptcha_token, gee_challenge, gee_gt
	else:
		log(resp)
		return False, False, False



def sms_send(type, tel, key, challenge, validate):
	url = "https://passport.bilibili.com/web/sms/general/v2/send"
	headers = {
		"User-Agent": "Mozilla/5.0 BiliDroid/7.21.0 (bbcallen@gmail.com) os/android model/MuMu mobi_app/android build/7210300 channel/bili innerVer/7210300 osVer/6.0.1 network/2",
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8", }
	data = {"cid": type, "tel": tel, "key": key, "captchaType": 6,
			"type": 21, "challenge": challenge, "validate": validate,
			"seccode": validate + "|jordan"}
	try:
		resp = requests.post(url, data=data, headers=headers,
							 timeout=(35, 35)).json()
	except:
		log("网络请求失败")
		return False
	if resp and resp.get('code') == 0:
		log("发送短信验证码 完成")
		return True
	else:
		log(resp)
		return False


def safecenter_sms_send(recaptcha_token, gee_challenge, gee_seccode, tmp_code):
	url = "https://passport.bilibili.com/x/safecenter/common/sms/send"
	headers = {
		"User-Agent": "Mozilla/5.0 BiliDroid/7.21.0 (bbcallen@gmail.com) os/android model/MuMu mobi_app/android build/7210300 channel/bili innerVer/7210300 osVer/6.0.1 network/2",
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8", }
	data = {"gee_challenge": gee_challenge, "gee_seccode": gee_seccode + "|jordan",
			"gee_validate": gee_seccode, "recaptcha_token": recaptcha_token,
			"sms_type": "loginTelCheck", "tmp_code": tmp_code}
	try:
		resp = requests.post(url, data=data, headers=headers,
							 timeout=(35, 35)).json()
	except:
		log("网络请求失败")
		return False
	if resp and resp.get('code') == 0:
		captcha_key = resp['data']['captcha_key']
		log("发送短信验证码 完成")
		return captcha_key
	else:
		log(resp)
		return False


def check_old_code(tel_url):
	log('检查是否有近期验证码数据......')
	try:
		resp = requests.get(tel_url, timeout=(35, 35)).text
	except:
		log("网络请求失败")
		return False
	if 'bilibili' in resp:
		search = pattern_search(resp, '[bilibili]')
		findall = re.findall("\d+", resp[search[0]:])
		old_code = findall[0]
		log(f"获得旧验证码：{old_code}")
		return old_code
	else:
		return False


def get_code(tel_url, old_code, yzmdelay):
	log(f'验证码等待{yzmdelay}秒......')
	resp = ''
	time.sleep(yzmdelay)
	try:
		resp = requests.get(tel_url, timeout=(35, 35)).text
	except:
		log("网络请求失败")
		resp = ''
		pass
	if 'bilibili' not in resp or old_code and old_code in resp:
		log(f'验证码等待{yzmdelay}秒......')
		time.sleep(yzmdelay)
		try:
			resp = requests.get(tel_url, timeout=(35, 35)).text
		except:
			log("网络请求失败")
			return False
	code = 0
	codes = pattern_search(resp, '[bilibili]')
	if len(codes) == 0:
		log('验证码获取失败')
		return False
	if len(codes) > 0:
		find = re.findall("\d+", resp[codes[0]:])
		code = find[0]
		if code != old_code:
			log(f'验证码:{code}')
			return code
		else:
			log(f'未获得新验证码')
			return False

		# smsCode, tmp_token


def login_verify(captcha_key, smsCode, tmp_token):
	url = f"https://passport.bilibili.com/x/safecenter/login/tel/verify"
	headers = {
		"User-Agent": "Mozilla/5.0 BiliDroid/7.21.0 (bbcallen@gmail.com) os/android model/MuMu mobi_app/android build/7210300 channel/bili innerVer/7210300 osVer/6.0.1 network/2",
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8", }
	data = {"captcha_key": captcha_key, "code": smsCode, "tmp_code": tmp_token,
			"type": "loginTelCheck"}
	try:
		resp = requests.post(url, data=data, headers=headers,
							 timeout=(35, 35)).json()
	except:
		log("网络请求失败")
		return False
	if resp and resp.get('code') == 0 and resp.get('data'):
		smsCode = resp['data']['code']
		return smsCode
	else:
		return False


def exchange_cookie(code):
	url = "https://passport.bilibili.com/x/passport-login/web/exchange_cookie"
	headers = {
		"User-Agent": "Mozilla/5.0 BiliDroid/7.21.0 (bbcallen@gmail.com) os/android model/MuMu mobi_app/android build/7210300 channel/bili innerVer/7210300 osVer/6.0.1 network/2",
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8", }
	data = {"code": code, "csrf": '', "source": "main_web", }
	try:
		resp = requests.post(url, data=data, headers=headers,
							 timeout=(35, 35)).json()
	except:
		log("网络请求失败")
		return False
	if resp and resp.get('code') == 0 and resp.get('data'):
		login_url = 'sid=' + generate_random_str(8) + ';' + resp['data']['url'].replace(',', '%2C').replace(
			'&', ';').replace('?', ';')
		return login_url


def web_login(cid, tel, smsCode, appkey, tel_url,
			  yzmdelay):
	url = "https://passport.bilibili.com/web/login/rapid"
	headers = {
		"User-Agent": "Mozilla/5.0 BiliDroid/7.21.0 (bbcallen@gmail.com) os/android model/MuMu mobi_app/android build/7210300 channel/bili innerVer/7210300 osVer/6.0.1 network/2",
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8", }
	data = {"cid": cid, "tel": tel, "smsCode": smsCode,
			"source": "main-mini", "degrade": "true",
			"goUrl": "https://passport.bilibili.com/ajax/miniLogin/redirect"}
	try:
		resp = requests.post(url, data=data, headers=headers,
							 timeout=(35, 35)).json()
	except:
		log("网络请求失败")
		return False
	if resp and resp.get('code') == 0 and resp.get('data') and \
			resp['data']['status'] == 0:
		login_url = 'sid=' + generate_random_str(8) + ';' + resp['data']['url'].replace(',', '%2C').replace(
			'&', ';').replace('?', ';')
		if login_url:
			return login_url
		else:
			return False
	elif resp and resp.get('code') == 0 and resp.get('data') and \
			resp['data']['status'] == 2:
		tmp_token = resp['data']['url'].split("=")[1]
		log("风控触发二次验证")
		count = 0
		while count < 3:
			count += 1
			recaptcha_token, gee_challenge, gee_gt = get_pre(resp['data']['url'])
			if not recaptcha_token:
				if count < 3:
					continue
				return False
			validate = recognize(appkey, gee_gt, gee_challenge)
			if not validate:
				if count < 3:
					continue
				return False
			old_code = check_old_code(tel_url)
			captcha_key = safecenter_sms_send(recaptcha_token, gee_challenge, validate,
											  tmp_token)
			if not captcha_key:
				if count < 3:
					continue
				return False
			smsCode = get_code(tel_url, old_code, yzmdelay)
			if not smsCode:
				if count < 3:
					continue
				return False
			smsCode = login_verify(captcha_key, smsCode, tmp_token)
			if not smsCode:
				if count < 3:
					continue
				return False
			login_url = exchange_cookie(smsCode)
			if login_url:
				return login_url
			else:
				if count < 3:
					continue
				return False
	else:
		return False


def get_ck(type, tel, tel_url, appkey, yzmdelay, count=1):
	# key, challenge, gt
	key, challenge, gt = get_challenge()
	if not key:
		return False
	validate = recognize(appkey, gt, challenge)
	if not validate:
		return False
	old_code = check_old_code(tel_url)

	login_resp = web_login(type, tel, old_code, appkey,
						   tel_url, yzmdelay)
	if login_resp:
		obj = {}
		for key_value in login_resp.split(";"):
			if len(key_value.split("=")) == 2:
				key, value = key_value.split("=")
				obj[key] = value
		login_resp = obj
		return login_resp

	succ = sms_send(type, tel, key, challenge,
					validate)
	if not succ:
		return False
	smsCode = get_code(tel_url, old_code, yzmdelay)
	if not smsCode:
		if count < 3:
			count += 1
			return get_ck(type, tel, tel_url, appkey, yzmdelay, count)
		else:
			return False
	login_resp = web_login(type, tel, smsCode, appkey,
						   tel_url, yzmdelay)
	if not login_resp:
		return False
	obj = {}
	for key_value in login_resp.split(";"):
		if len(key_value.split("=")) == 2:
			key, value = key_value.split("=")
			obj[key] = value
	login_resp = obj
	return login_resp


def ck_check(cookies):
	api_url = f"https://api.bilibili.com/x/space/myinfo"
	headers = {
		"User-Agent": "Mozilla/5.0 BiliDroid/7.21.0 (bbcallen@gmail.com) os/android model/MuMu mobi_app/android build/7210300 channel/bili innerVer/7210300 osVer/6.0.1 network/2", }
	try:
		resp = requests.get(api_url, cookies=cookies, headers=headers,
							timeout=(35, 35)).json()
	except:
		log("网络请求失败")
		return "neterr"
	if resp and resp.get("code") != -101 and resp.get(
			"code") != -400:
		log("Cookie仍有效")
		return True
	else:
		log("Cookie已失效")
		return False


def main():
	config_path = sys.argv[1] if len(sys.argv) > 1 else "config.toml"
	run_completion = True

if run_completion:
    try:
	with open(env_js, "r", encoding='utf-8') as fp:
		lines = fp.readlines()
		for line in range(len(lines)):
			if line > 35 and 'COOKIE: ""' in lines[line]:
				DedeUserID = generate_random_str(7)
				sid = generate_random_str(8)
				DedeUserID__ckMd5 = generate_random_str(9)
				bili_jct = generate_random_str(10)
				SESSDATA = generate_random_str(11)
				cookie_str = 'COOKIE: "' + 'DedeUserID=' + DedeUserID + ';DedeUserID__ckMd5=' + DedeUserID__ckMd5 + ';bili_jct=' + bili_jct + ';SESSDATA=' + SESSDATA + ';sid=' + sid + '"'
				lines[line] = lines[line].replace('COOKIE: ""', cookie_str)
				with open(env_js, "w+", encoding='utf-8') as fp:
									fp.writelines(lines)
				log("空COOKIE补全要素")
				with open(env_js, "r", encoding='utf-8') as fp:
					envs = fp.read()
					ck_configs = []
					ck_config = {}
					ck_key_value = {}
					current = 1
					for line in envs.splitlines():
					  current = current + 1
				if current < 35:
			continue
				if "COOKIE" in line:
					line = line.replace(' ', '').replace('\"', '').replace('\'', '').replace(
						'COOKIE:', '')
					for key_value in line.split(";"):
						if len(key_value.split("=")) == 2:
							name, value = key_value.split("=")
							ck_key_value[name] = value
				if "NOTE" in line:
					note = line.replace('\'', '').replace('\"', '').replace(',', '').split(
						"----")
					if len(note) >= 3:
						tel = note[1]
						tel_url = note[2]
						ck_config['tel'] = tel
						ck_config['tel_url'] = tel_url
						ck_config['ck'] = ck_key_value
					if ck_config:
						ck_configs.append(ck_config)
						ck_config = {}
						ck_key_value = {}
    except Exception as e:
        print(e)
        # 在这里添加适当的错误处理代码，比如记录错误日志等
    print(f"env无法加载")
    time.sleep(10)
    return main()
	log(f"导入了 {len(ck_configs)} 个账号")
	
	try:
		with open(config_path, "r", encoding=detect_charset(config_path)) as fp:
			t_data = toml.load(fp)
	except:
		print(f"无法加载{config_path}")
		time.sleep(10)
		return main()
	
	appkey = t_data['global']['appkey']
	yzmdelay = t_data['global']['yzmdelay']
	
	if not jifen(appkey):
		time.sleep(10)
		return main()
	log("检查失效cookies......")
	for line in ck_configs:
		time.sleep(3)
		log(f"UID: {line['ck']['DedeUserID']} tel: {line['tel']}")
		if ck_check(line['ck']):
			continue
		else:
			shixiao = {}
			DedeUserID = generate_random_str(7)
			sid = generate_random_str(8)
			DedeUserID__ckMd5 = generate_random_str(9)
			bili_jct = generate_random_str(10)
			SESSDATA = generate_random_str(11)
			new_ck = {"DedeUserID": DedeUserID, "DedeUserID__ckMd5": DedeUserID__ckMd5,
					  "bili_jct": bili_jct, "SESSDATA": SESSDATA,
					  "sid": sid, }
			if new_ck:
				shixiao['err_ck'] = line['ck']
				shixiao['new_ck'] = new_ck
				log(f"旧CK：{shixiao['err_ck']}")
				log(f"新CK：{shixiao['new_ck']}")
				err_DedeUserID = 'DedeUserID=' + shixiao['err_ck']['DedeUserID']
				new_DedeUserID = 'DedeUserID=' + shixiao['new_ck']['DedeUserID']
				envs = envs.replace(err_DedeUserID, new_DedeUserID)
				errDedeUserID__ckMd5 = 'DedeUserID__ckMd5=' + shixiao['err_ck']['DedeUserID__ckMd5']
				newDedeUserID__ckMd5 = 'DedeUserID__ckMd5=' + shixiao['new_ck']['DedeUserID__ckMd5']
				envs = envs.replace(errDedeUserID__ckMd5, newDedeUserID__ckMd5)
				errbili_jct = 'bili_jct=' + shixiao['err_ck']['bili_jct']
				newbili_jct = 'bili_jct=' + shixiao['new_ck']['bili_jct']
				envs = envs.replace(errbili_jct, newbili_jct)
				errSESSDATA = 'SESSDATA=' + shixiao['err_ck']['SESSDATA']
				newSESSDATA = 'SESSDATA=' + shixiao['new_ck']['SESSDATA']
				envs = envs.replace(errSESSDATA, newSESSDATA)
				with open(env_js, "w+", encoding='utf-8') as fp:
					fp.write(envs)
				log("失效cookies随机替换完成")
	try:
		with open(env_js, "r", encoding='utf-8') as fp:
			envs = fp.read()
			ck_configs = []
			ck_config = {}
			ck_key_value = {}
			current = 1
			for line in envs.splitlines():
				current = current + 1
				if current < 35:
					continue
				if "COOKIE" in line:
					line = line.replace(' ', '').replace('\"', '').replace('\'', '').replace(
						'COOKIE:', '')
					for key_value in line.split(";"):
						if len(key_value.split("=")) == 2:
							name, value = key_value.split("=")
							ck_key_value[name] = value
				if "NOTE" in line:
					note = line.replace('\'', '').replace('\"', '').replace(',', '').split(
						"----")
					if len(note) >= 3:
						tel = note[1]
						tel_url = note[2]
						ck_config['tel'] = tel
						ck_config['tel_url'] = tel_url
						ck_config['ck'] = ck_key_value
					if ck_config:
						ck_configs.append(ck_config)
						ck_config = {}
						ck_key_value = {}
	except:
		print(f"env无法加载")
		time.sleep(10)
		return main()
	log(f"导入了 {len(ck_configs)} 个账号")
	try:
		with open(config_path, "r", encoding=detect_charset(config_path)) as fp:
			t_data = toml.load(fp)
	except:
		print(f"无法加载{config_path}")
		time.sleep(10)
		return main()
	for line in ck_configs:
		time.sleep(3)
		log(f"UID: {line['ck']['DedeUserID']} tel: {line['tel']}")
		if line['tel'].startswith('1'):
			log(f'当前号码不进行处理:{line["tel"]}')
			continue
		if ck_check(line['ck']):
			continue
		else:
			shixiao = {}
			new_ck = get_ck(4, line['tel'], line['tel_url'], appkey,
							yzmdelay)
			if new_ck:
				shixiao['err_ck'] = line['ck']
				shixiao['new_ck'] = new_ck
				log(f"旧CK：{shixiao['err_ck']}")
				log(f"新CK：{shixiao['new_ck']}")
				err_DedeUserID = 'DedeUserID=' + shixiao['err_ck']['DedeUserID']
				new_DedeUserID = 'DedeUserID=' + shixiao['new_ck']['DedeUserID']
				envs = envs.replace(err_DedeUserID, new_DedeUserID)
				errDedeUserID__ckMd5 = 'DedeUserID__ckMd5=' + shixiao['err_ck']['DedeUserID__ckMd5']
				newDedeUserID__ckMd5 = 'DedeUserID__ckMd5=' + shixiao['new_ck']['DedeUserID__ckMd5']
				envs = envs.replace(errDedeUserID__ckMd5, newDedeUserID__ckMd5)
				errbili_jct = 'bili_jct=' + shixiao['err_ck']['bili_jct']
				newbili_jct = 'bili_jct=' + shixiao['new_ck']['bili_jct']
				envs = envs.replace(errbili_jct, newbili_jct)
				errSESSDATA = 'SESSDATA=' + shixiao['err_ck']['SESSDATA']
				newSESSDATA = 'SESSDATA=' + shixiao['new_ck']['SESSDATA']
				envs = envs.replace(errSESSDATA, newSESSDATA)
				with open(env_js, "w+", encoding='utf-8') as fp:
					fp.write(envs)
				log("cookies更新完成")
	runflash = t_data['global']['runflash']
	for line in range(0, runflash):
		print('\rWaiting %s 秒 ' % (runflash - line - 1), end='')
		time.sleep(1)
	print('\n')
	main()


if __name__ == '__main__':
	main()

# -*- coding: utf-8 -*-
import requests, json, re
import time, datetime, os
import sys, getopt
import getpass
from halo import Halo
from apscheduler.schedulers.blocking import BlockingScheduler
import ddddocr

DEBUG = False


class HitCarder(object):
    """Hit carder class

    Attributes:
        username: (str) 浙大统一认证平台用户名（一般为学号）
        password: (str) 浙大统一认证平台密码
        login_url: (str) 登录url
        base_url: (str) 打卡首页url
        save_url: (str) 提交打卡url
        captcha_url: (str) 验证码url
        max_retry: (int) 验证码最多尝试次数
        headers: (dict) 请求头
        sess: (requests.Session) 用于打卡的统一session
        info: (dict) 打卡信息
    """

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.login_url = "https://zjuam.zju.edu.cn/cas/login?service=https%3A%2F%2Fhealthreport.zju.edu.cn%2Fa_zju%2Fapi%2Fsso%2Findex%3Fredirect%3Dhttps%253A%252F%252Fhealthreport.zju.edu.cn%252Fncov%252Fwap%252Fdefault%252Findex"
        self.base_url = "https://healthreport.zju.edu.cn/ncov/wap/default/index"
        self.save_url = "https://healthreport.zju.edu.cn/ncov/wap/default/save"
        self.captcha_url = "https://healthreport.zju.edu.cn/ncov/wap/default/code"
        self.max_retry = 5
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36"
        }
        self.sess = requests.Session()

    def login(self):
        """Login to ZJU platform."""
        res = self.sess.get(self.login_url, headers=self.headers)
        execution = re.search('name="execution" value="(.*?)"', res.text).group(1)
        res = self.sess.get(
            url='https://zjuam.zju.edu.cn/cas/v2/getPubKey', headers=self.headers).json()
        n, e = res['modulus'], res['exponent']
        encrypt_password = self._rsa_encrypt(self.password, e, n)

        data = {
            'username': self.username,
            'password': encrypt_password,
            'execution': execution,
            '_eventId': 'submit'
        }
        res = self.sess.post(url=self.login_url, data=data, headers=self.headers)

        # check if login successfully
        if '统一身份认证' in res.content.decode():
            raise LoginError('登录失败，请核实账号密码重新登录')
        return self.sess

    def post(self):
        """Post the hit card info."""
        res = self.sess.post(self.save_url, data=self.info, headers=self.headers)
        return json.loads(res.text)

    def get_captcha(self, update=False):
        """Get, OCR and return the captcha."""
        ocr = ddddocr.DdddOcr(show_ad=False)
        res = self.sess.get(self.captcha_url, headers=self.headers)
        code = ocr.classification(res.content)
        if update and self.info:
            self.info['verifyCode'] = code
        else:
            return code

    def get_date(self):
        """Get current date."""
        today = datetime.date.today()
        return "{:4d}{:02d}{:02d}".format(today.year, today.month, today.day)

    def get_info(self, html=None):
        """Get hit card info, which is the old info with updated new time."""
        if not html:
            res = self.sess.get(self.base_url, headers=self.headers)
            html = res.content.decode()

        try:
            old_infos = re.findall(r'oldInfo: ({[^\n]+})', html)
            if len(old_infos) != 0:
                old_info = json.loads(old_infos[0])
            else:
                raise RegexMatchError("未发现缓存信息，请先至少手动成功打卡一次再运行脚本")

            new_info_tmp = json.loads(re.findall(r'def = ({[^\n]+})', html)[0])
            new_id = new_info_tmp['id']
            name = re.findall(r'realname: "([^\"]+)",', html)[0]
            number = re.findall(r"number: '([^\']+)',", html)[0]
        except IndexError as err:
            raise RegexMatchError('Relative info not found in html with regex: ' + str(err))
        except json.decoder.JSONDecodeError as err:
            raise DecodeError('JSON decode error: ' + str(err))

        if DEBUG:
            with open('info.json', 'w') as f:
                json.dump(old_info, f, indent=2)
            print('\n[DEBUG/old_info]', old_info)

        new_info = old_info.copy()
        new_info['id'] = new_id
        new_info['name'] = name
        new_info['number'] = number
        new_info["date"] = self.get_date()
        new_info["created"] = round(time.time())
        # form change
        new_info['jrdqtlqk[]'] = 0
        new_info['jrdqjcqk[]'] = 0
        new_info['sfsqhzjkk'] = 1   # 是否申领杭州健康码
        new_info['sqhzjkkys'] = 1   # 杭州健康码颜色，1:绿色 2:红色 3:黄色
        new_info['sfqrxxss'] = 1    # 是否确认信息属实
        new_info['jcqzrq'] = ""     # 接触确诊人群
        new_info['gwszdd'] = ""
        new_info['szgjcs'] = ""
        new_info['verifyCode'] = self.get_captcha()
        self.info = new_info
        return new_info

    def _rsa_encrypt(self, password_str, e_str, M_str):
        password_bytes = bytes(password_str, 'ascii')
        password_int = int.from_bytes(password_bytes, 'big')
        e_int = int(e_str, 16)
        M_int = int(M_str, 16)
        result_int = pow(password_int, e_int, M_int)
        return hex(result_int)[2:].rjust(128, '0')


# Exceptions 
class LoginError(Exception):
    """Login Exception"""
    pass


class RegexMatchError(Exception):
    """Regex Matching Exception"""
    pass


class DecodeError(Exception):
    """JSON Decode Exception"""
    pass


def main(username, password):
    """Hit card process

    Arguments:
        username: (str) 浙大统一认证平台用户名（一般为学号）
        password: (str) 浙大统一认证平台密码
    """
    print("\n[Time] {}".format(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    print("🚌 打卡任务启动")
    spinner = Halo(text='Loading', spinner='dots')
    spinner.start('正在新建打卡实例...')
    hit_carder = HitCarder(username, password)
    spinner.succeed('已新建打卡实例')

    spinner.start(text='登录到浙大统一身份认证平台...')
    try:
        hit_carder.login()
        spinner.succeed('已登录到浙大统一身份认证平台')
    except Exception as err:
        spinner.fail(str(err))
        return

    spinner.start(text='正在获取个人信息...')
    try:
        hit_carder.get_info()
        spinner.succeed('{} {}同学, 你好~'.format(hit_carder.info['number'], hit_carder.info['name']))
    except Exception as err:
        spinner.fail('获取信息失败，请手动打卡，更多信息: ' + str(err))
        return

    spinner.start(text='正在为您打卡...')
    try:
        try_cnt = 1
        while try_cnt < hit_carder.max_retry:
            res = hit_carder.post()
            if DEBUG:
                print('\n[DEBUG/res]', res, '尝试：', try_cnt)
            if str(res['e']) == '0':
                spinner.stop_and_persist(symbol='🦄 '.encode('utf-8'),
                    text='已为您打卡成功！' + ('尝试次数：{}'.format(try_cnt) if try_cnt > 1 else ''))
                break
            elif res['m'] == '验证码错误':
                hit_carder.get_captcha(update=True)     # update the captcha
                spinner.fail('验证码错误，已尝试次数：{}'.format(try_cnt))
                try_cnt += 1
                spinner.start('正在尝试...')
            else:
                spinner.stop_and_persist(symbol='🦄 '.encode('utf-8'), text=res['m'])
                break
        else:
            spinner.fail('超出验证码最大错误尝试次数（{}），请手动打卡'.format(try_cnt))
    except Exception as err:
        spinner.fail('数据提交失败 ' + str(err))
        return


if __name__ == "__main__":
    # Get command line options
    config_file = 'config.json'
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hf:', ['help', 'config-file=', 'DEBUG'])
    except getopt.GetoptError:
        print("Usage: python3 {} [-f|--config-file <config-file>]".format(os.path.basename(__file__)))
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print("Usage: python3 {} [-f|--config-file <config-file>]".format(os.path.basename(__file__)))
            sys.exit()
        elif opt in ('-f', '--config-file'):
            config_file = arg
        elif opt == '--DEBUG':
            DEBUG = True
            print('[DEBUG] Debug mode enabled.')

    # Read config file
    if os.path.exists(config_file):
        configs = json.loads(open(config_file, 'r').read())
        username = configs["username"]
        password = configs["password"]
        hour = configs["schedule"]["hour"]
        minute = configs["schedule"]["minute"]
    else:
        username = input("👤 浙大统一认证用户名: ")
        password = getpass.getpass('🔑 浙大统一认证密码: ')
        print("⏲  请输入定时时间（默认每天6:05）")
        hour = input("\thour: ") or 6
        minute = input("\tminute: ") or 5
    main(username, password)

    # Start schedule task
    scheduler = BlockingScheduler()
    scheduler.add_job(main, 'cron', args=[username, password], hour=hour, minute=minute)
    print('⏰ 已启动定时程序，每天 {:02d}:{:02d} 为您打卡'.format(int(hour), int(minute)))
    print('Press Ctrl+{} to exit'.format('Break' if os.name == 'nt' else 'C'))

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        pass

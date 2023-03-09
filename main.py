"""360自动绑定网站 自动提交sitemap"""

import time
from urllib import parse
from pprint import pprint
import configparser
import datetime
import linecache
import random
import re
import httpx
import tldextract
from retrying import retry
import test
from orc import dama, orc
from user import api


class Bind():
    """
    360自动绑定网站 自动提交sitemap
    """

    def __init__(self):
        self.conf = configparser.ConfigParser()
        self.conf.read('user/config.ini')
        with open(self.conf['filePath']['cookie'], 'r', encoding='utf-8')as txt_f:
            self.cookie = txt_f.read().strip()
        self.urls = self.getlines(self.conf['filePath']['urls'])
        self.headers = {'accept': 'application/json, text/plain, */*',
                        'accept-encoding': 'gzip, deflate, br',
                        'accept-language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
                        'content-type': 'application/x-www-form-urlencoded',
                        'cookie': self.cookie,
                        'origin': 'https://zhanzhang.so.com',
                        'sec-ch-ua': '"Chromium";v="110", "Not A(Brand";v="24", "Google '
                        'Chrome";v="110"',
                        'sec-ch-ua-mobile': '?0',
                        'sec-ch-ua-platform': '"Windows"',
                        'sec-fetch-dest': 'empty',
                        'sec-fetch-mode': 'cors',
                        'sec-fetch-site': 'same-origin',
                        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        ' (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'}
        self.sitemap_urls = self.getlines(self.conf['filePath']['sitemap'])
        self.fuck_webs = []
        self.init_urls()
        print(f'本次需要更新的域名：{len(self.urls)}个')
        print(self.urls)
        for i in self.sitemap_urls:
            print(i)

    def init_urls(self):
        """初始化self.urls"""
        if int(self.conf["user"]["domain_count"]) > 0:
            self.urls = self.auto_create_son_url(self.urls)

    def getlines(self, file_path):
        """获取文件内数据 去重返回列表"""
        new_list = [i.strip()
                    for i in linecache.getlines(file_path) if i.strip() != ""]
        new_list = list(set(new_list))
        return new_list

    def random_str(self, min_count, max_count):
        """随机字符"""
        abc = "abcdefghijklmnopqrstuvwxyz0123456789"
        count = random.randint(min_count, max_count)
        return "".join(random.choices(abc, k=count))

    def auto_create_son_url(self, urls):
        """自动生成二级域名"""
        root_domains = []
        for url in urls:
            root_domain = self.get_domain_info(url)[-1]
            root_domains.append(root_domain)
        son_domains = []
        for rdomain in root_domains:
            for _ in range(int(self.conf["user"]["domain_count"])):
                son_domain = f"{self.random_str(5,8)}.{rdomain}"
                son_domains.append(son_domain)
        print(f'自动生成二级域名：{len(son_domains)}个')
        print(son_domains)
        urls.extend(son_domains)
        return list(set(urls))

    def get_domain_info(self, domain):
        """获取域名前后缀"""
        tld = tldextract.extract(domain)
        subdomain = tld.subdomain
        full_domain = ".".join([tld.subdomain, tld.domain, tld.suffix])
        root_domain = ".".join([tld.domain, tld.suffix])
        return subdomain, full_domain, root_domain

    @retry(stop_max_attempt_number=3)
    def add_site(self, domain):
        """
        360站长 添加网站
        """
        url = "https://zhanzhang.so.com/?m=Site&a=add"
        headers = self.headers.copy()
        headers.update(
            {'referer': 'https://zhanzhang.so.com/sitetool/site_manage'})
        data = {"site": domain}
        resp = httpx.post(url, data=data, headers=headers, timeout=30)
        if resp.json()['status'] == 0:
            print(f"添加网站：{domain} 成功 {resp.json()['info']}")

    @retry(stop_max_attempt_number=3)
    def add_son_site(self, www_domain, son_domains):
        """
        360站长 添加二级网站
        """
        url = "https://zhanzhang.so.com/?m=Sitemanager&a=psite"
        headers = self.headers.copy()
        headers.update(
            {'referer': 'https://zhanzhang.so.com/sitetool/site_manage'})
        data = {"action": "add",
                "psite": www_domain,
                "site": son_domains}
        resp = httpx.post(url, data=data, headers=headers, timeout=30)
        if resp.json()['status'] == 0:
            print(f"添加二级网站：{son_domains} 成功")

    @retry(stop_max_attempt_number=3)
    def get_file_code(self, domain):
        """
        360站长 获取验证文件内容
        """
        url = f"https://zhanzhang.so.com/?m=Site&a=get_auth_file&file={domain}"
        resp = httpx.get(url, headers=self.headers, timeout=30)
        print(f"[{domain}]获取验证文件内容：", resp.text)
        return resp.text

    @retry(stop_max_attempt_number=3)
    def get_code(self, domain):
        """
        360站长 获取meta验证代码内容
        """
        url = f"https://zhanzhang.so.com/?m=Site&a=get_auth_html&html={domain}"
        resp = httpx.get(url, headers=self.headers, timeout=30)
        print(f"[{domain}]获取验证代码内容：", resp.json())
        name = re.findall('name=\"(.*?)\"', resp.json()['data'])[0]
        code = re.findall('content=\"(.*?)\"', resp.json()['data'])[0]
        return name, code

    @retry(stop_max_attempt_number=3)
    def verify(self, domain, v_type):
        """
        360站长 验证站点
        """
        url = "https://zhanzhang.so.com/?m=Site&a=auth"
        data = {"auth_method": v_type,
                "site": domain, }
        print('360站长验证中...')
        resp = httpx.post(url, data=data, headers=self.headers, timeout=30)
        print(f"{domain} 绑定结果：", resp.json(), '\n')

    @retry(stop_max_attempt_number=3)
    def get_vimg_code(self):
        """
        360站长 获取验证码
        """
        result = ''
        while True:
            img_path = "orc/v.jpg"
            url = 'https://zhanzhang.so.com/index.php?a=checkcode&m=Utils'
            resp = httpx.get(url, headers=self.headers, timeout=30)
            with open(img_path, 'wb') as img_f:
                img_f.write(resp.content)

            if int(self.conf["user"]['imgvcode']):
                # 图鉴打码
                result = dama.base64_api(
                    img_path, uname=self.conf['www.ttshitu.com']["uname"],
                    pwd=self.conf['www.ttshitu.com']["pwd"])
            else:
                # orc识别
                result = orc.ocr(img_path)
            if len(result) == 4:
                print(f'验证码code：{result}')
                break
            if result == "err":
                print('验证码code: 识别失败 重试')
            else:
                print(f'验证码code：{result} {len(result)} 不符合格式要求 重试')
        return result

    @retry(stop_max_attempt_number=3)
    def push_url(self, urls, checkcode):
        """
        360站长 推送URL
        """
        url = 'https://zhanzhang.so.com/?m=PageInclude&a=upload'
        headers = self.headers.copy()
        headers.update(
            {'referer': 'https://zhanzhang.so.com/sitetool/page_include'})
        data = {'url': urls,
                'checkcode': checkcode, }
        resp = httpx.post(url, headers=headers, data=data, timeout=30)
        return resp.json()

    @retry(stop_max_attempt_number=3)
    def add_sitemap(self, domain, sitemap_url, checkcode):
        """
        360站长 添加sitemap链接
        """
        url = f'https://zhanzhang.so.com/?m=Sitemap&a=add&host={domain}'
        headers = self.headers.copy()
        headers.update(
            {'referer': 'https://zhanzhang.so.com/sitetool/page_include'})
        data = {"seed": "\n".join(sitemap_url),
                "code": checkcode}
        resp = httpx.post(url, headers=headers, data=data, timeout=30)
        return resp.json()

    @retry(stop_max_attempt_number=3)
    def ping_sitemap(self, domain, sitemap_url):
        """
        360站长 点击更新sitemap
        """
        url = f'https://zhanzhang.so.com/?m=Sitemap&a=ping&host={domain}'
        headers = self.headers.copy()
        headers.update(
            {'referer': 'https://zhanzhang.so.com/sitetool/page_include'})
        data = {"seed": "\n".join(sitemap_url)}
        resp = httpx.post(url, headers=headers, data=data, timeout=30)
        result = resp.json()
        print(domain, result["info"], sitemap_url)
        return result

    @retry(stop_max_attempt_number=3)
    def web_list(self):
        """
        360站长 获取当前账号绑定的网站
        """
        url = 'https://zhanzhang.so.com/?m=Userinfo&a=sites'
        resp = httpx.get(url, headers=self.headers, timeout=30)
        result = [i['site'] for i in resp.json()['data']]
        return result

    @retry(stop_max_attempt_number=3)
    def sitemap_list(self, domain):
        """360站长 获取当前域名绑定的sitemap链接"""
        url = f'https://zhanzhang.so.com/?m=Sitemap&a=get_list&host={domain}&p=1'
        resp = httpx.get(url, headers=self.headers, timeout=30)
        result = resp.json()['data']['list']
        return result

    def del_site(self,domains): 
        """360站长 删除报风险sitemap的网站"""
        url = 'https://zhanzhang.so.com/?m=Site&a=delete'
        headers = self.headers.copy()
        headers.update({'referer': 'https://zhanzhang.so.com/sitetool/site_manage'})
        lines = ['{"roleId":7,"siteName":"域名"}'.replace('域名',i) for i in domains]
        data = f'sites_delete=[{",".join(lines)}]'
        resp = httpx.post(url, headers=headers, data=data, timeout=30)
        result = resp.json()
        print(f'删除网站{len(domains)}个',result)

    def del_fuck_webs(self):
        """360站长 删除风险sitemap"""
        if len(self.fuck_webs) > 0:
            print('\n## 开始删除报风险sitemap的网站')
            webs = self.web_list()
            del_webs = []
            for web in webs:
                root_domain = self.get_domain_info(web)[-1]
                if root_domain in self.fuck_webs:
                    del_webs.append(web)
            print(del_webs)
            self.del_site(del_webs)

    def update_sitemap_func(self):
        """
        360站长 点击更新sitemap
        """
        webs = self.web_list()
        count = len(webs)
        success_count = 0
        for index,domain in enumerate(webs):
            full_domain, root_domain = self.get_domain_info(domain)[1:]
            if root_domain in self.fuck_webs:
                print(f'{full_domain} 风险sitemap url请删除')
                continue
            if not int(self.conf['user']['ping_all']) and domain not in self.urls:
                continue
            online_sitemap_urls = [i['url'] for i in self.sitemap_list(domain)]
            local_sitemap_urls = [
                i.strip().replace('{域名}', domain) for i in self.sitemap_urls]
            need_add_sitemap_urls = []
            for local_sitemap in local_sitemap_urls:
                if local_sitemap not in online_sitemap_urls:
                    need_add_sitemap_urls.append(local_sitemap)
            # 如果发现没有绑定的sitemap地址，则添加
            if len(need_add_sitemap_urls) > 0:
                status = -1
                info = '验证码有误~'
                while status == -1 and info == '验证码有误~':
                    verify_code = self.get_vimg_code()
                    result = self.add_sitemap(domain, need_add_sitemap_urls, verify_code)
                    status = result['status']
                    info = result['info']
                if info != '验证码有误~' and status != 0:
                    print(f"[{index+1}/{count}]",domain, info)
                    if "风险sitemap" in info:
                        self.fuck_webs.append(root_domain)
                    continue
                online_sitemap_urls = [i['url'] for i in self.sitemap_list(domain)]
            if len(online_sitemap_urls) > 0:
                # 最后统一提交蜘蛛sitemap
                for sitemap_url in online_sitemap_urls:
                    result = self.ping_sitemap(domain, sitemap_url)
                    success_count += 1
                # 写入推送日志
                with open(f'log/{datetime.date.today()}.txt', 'a', encoding='utf-8')as txt_f:
                    txt_f.write("\n".join(online_sitemap_urls)+"\n")
        print(f'\n本次成功更新sitemap {success_count}条')
        # 是否删除风险sitemap
        if int(self.conf['user']['del_domain']):
            self.del_fuck_webs()

    def bind_site_func(self):
        """360站长 绑定网站"""
        webs = self.web_list()
        # 先绑定www主站
        www_webs = []
        son_webs = {}
        son_keys = []
        for domain in self.urls:
            if domain in webs:
                print(f'{domain} 已绑定')
            else:
                domain_sub, full_domain, root_domain = self.get_domain_info(
                    domain)
                if domain_sub == 'www':
                    www_webs.append(full_domain)
                elif domain_sub != '':
                    if root_domain not in son_keys:
                        son_webs[root_domain] = [full_domain,]
                        son_keys.append(root_domain)
                    else:
                        son_webs[root_domain].append(full_domain)
        for index, domain in enumerate(www_webs):
            # 绑定网站
            print(f'[{index + 1}/{len(www_webs)}]', end=' ')
            self.add_site(domain)
            # 360平台网站归属验证方式
            if int(self.conf['user']['vtype']):
                name, code = self.get_code(domain)
                api.create_web_page(domain, name, code)
                self.verify(domain, 'html')
            else:
                file_content = self.get_file_code(domain)
                api.create_web_file(domain, file_content)
                self.verify(domain, 'file')
        webs = self.web_list()
        for domain in list(son_webs.keys()):
            if "www."+domain in webs:
                print(f'www.{domain} 已绑定 开始批量绑定{domain}的二级域名')
                son_domains = ",".join(son_webs[domain])
                self.add_son_site("www."+domain, son_domains)
            else:
                print(f'www.{domain} 未绑定 跳过绑定{domain}的二级域名，请绑定www主域名')


def main():
    """主程"""
    b360 = Bind()
    print('\n## 开始绑定网站')
    b360.bind_site_func()
    print('\n## 开始推送sitemap')
    b360.update_sitemap_func()

if __name__ == '__main__':
    main()

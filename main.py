"""360自动绑定网站，自动提交sitemap"""
import configparser
import linecache
import re
import httpx
import tldextract
from orc import dama, orc
from user import api


class Bind():
    """
    360自动绑定网站，自动提交sitemap
    """

    def __init__(self):
        with open('user/cookie.txt', 'r', encoding='utf-8')as txt_f:
            self.cookie = txt_f.read().strip()
        with open('user/urls.txt', 'r', encoding='utf-8')as txt_f:
            self.urls = list(set(txt_f.read().strip().split('\n')))
        self.conf = configparser.ConfigParser()
        self.conf.read('user/user.ini')
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
                        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                        '(KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'}

        self.sitemap_urls = linecache.getlines('user/sitemap.txt')

    def get_domain_info(self, domain):
        """获取域名前后缀"""
        tld = tldextract.extract(domain)
        subdomain = tld.subdomain
        full_domain = ".".join([tld.subdomain, tld.domain, tld.suffix])
        root_domain = ".".join([tld.domain, tld.suffix])
        return subdomain, full_domain, root_domain

    def add_site(self, domain):
        """
        360站长 添加网站
        """
        url = "https://zhanzhang.so.com/?m=Site&a=add"
        headers = self.headers.copy()
        headers.update(
            {'referer': 'https://zhanzhang.so.com/sitetool/site_manage'})
        data = {"site": domain}
        resp = httpx.post(url, data=data, headers=headers)
        if resp.json()['status'] == 0:
            print(f"添加网站：{domain} 成功")

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
        resp = httpx.post(url, data=data, headers=headers)
        if resp.json()['status'] == 0:
            print(f"添加二级网站：{son_domains} 成功")

    def get_file_code(self, domain):
        """
        360站长 获取验证文件内容
        """
        url = f"https://zhanzhang.so.com/?m=Site&a=get_auth_file&file={domain}"
        resp = httpx.get(url, headers=self.headers)
        print(f"[{domain}]获取验证文件内容：", resp.text)
        return resp.text

    def get_code(self, domain):
        """
        360站长 获取meta验证代码内容
        """
        url = f"https://zhanzhang.so.com/?m=Site&a=get_auth_html&html={domain}"
        resp = httpx.get(url, headers=self.headers)
        print(f"[{domain}]获取验证代码内容：", resp.json())
        name = re.findall('name=\"(.*?)\"', resp.json()['data'])[0]
        code = re.findall('content=\"(.*?)\"', resp.json()['data'])[0]
        return name, code

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

    def get_vimg_code(self):
        """
        360站长 获取验证码
        """
        result = ''
        while len(result) != 4:
            img_path = "orc/v.jpg"
            url = 'https://zhanzhang.so.com/index.php?a=checkcode&m=Utils'
            resp = httpx.get(url, headers=self.headers)
            with open(img_path, 'wb') as img_f:
                img_f.write(resp.content)

            if int(self.conf["user"]['imgvcode']):
                # 图鉴打码
                result = dama.base64_api(
                    img_path, uname=self.conf['www.ttshitu.com']["uname"], pwd=self.conf['www.ttshitu.com']["pwd"])
            else:
                # orc识别
                result = orc.ocr(img_path)
                # print(result)
        return result

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
        resp = httpx.post(url, headers=headers, data=data)
        return resp.json()

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
        resp = httpx.post(url, headers=headers, data=data)
        return resp.json()

    def ping_sitemap(self, domain, sitemap_url):
        """
        360站长 点击更新sitemap
        """
        url = f'https://zhanzhang.so.com/?m=Sitemap&a=ping&host={domain}'
        headers = self.headers.copy()
        headers.update(
            {'referer': 'https://zhanzhang.so.com/sitetool/page_include'})
        data = {"seed": "\n".join(sitemap_url)}
        resp = httpx.post(url, headers=headers, data=data)
        result = resp.json()
        print(domain, result["info"], sitemap_url)
        return result

    def web_list(self):
        """
        360站长 获取当前账号绑定的网站
        """
        url = 'https://zhanzhang.so.com/?m=Userinfo&a=sites'
        resp = httpx.get(url, headers=self.headers)
        result = [i['site'] for i in resp.json()['data']]
        return result

    def sitemap_list(self, domain):
        """360站长 获取当前域名绑定的sitemap链接"""
        url = f'https://zhanzhang.so.com/?m=Sitemap&a=get_list&host={domain}&p=1'
        resp = httpx.get(url, headers=self.headers)
        result = resp.json()['data']['list']
        return result

    def update_sitemap(self):
        """
        360站长 点击更新sitemap
        """
        webs = self.web_list()
        fuck_webs = []
        success_count = 0
        for domain in webs:
            full_domain, root_domain = self.get_domain_info(domain)[1:]
            if root_domain in fuck_webs:
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
                    result = self.add_sitemap(
                        domain, need_add_sitemap_urls, verify_code)
                    status = result['status']
                    info = result['info']
                if info != '验证码有误~' and status != 0:
                    print(domain, info)
                    if "风险sitemap" in info:
                        fuck_webs.append(root_domain)
                    continue
                online_sitemap_urls = [i['url']
                                       for i in self.sitemap_list(domain)]
            # 最后统一提交蜘蛛sitemap
            for sitemap_url in online_sitemap_urls:
                result = self.ping_sitemap(domain, sitemap_url)
                success_count += 1
        print(f'\n本次成功更新sitemap {success_count}条')

    def bind_site(self):
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
        print(webs)
        for domain in list(son_webs.keys()):
            if "www."+domain in webs:
                print(f'www.{domain} 已绑定 开始批量绑定{domain}的二级域名')
                son_domains = ",".join(son_webs[domain])
                self.add_son_site("www."+domain, son_domains)
            else:
                print(f'www.{domain} 未绑定 跳过绑定{domain}的二级域名，请绑定www主域名')


if __name__ == '__main__':
    B = Bind()
    print('##开始绑定网站')
    B.bind_site()
    print('\n##开始推送sitemap')
    B.update_sitemap()

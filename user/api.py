"""
用户自定义程序验证接口
将网址修改为自己的程序验证接口格式即可，也可以直接修改你的web程序新增一个此类型api接口
"""

import httpx


def create_web_page(domain, name, code):
    """
    调用web程序api 首页meta标签验证
    使程序首页生成对应<meta 标签
    """
    url = f"http://{domain}/verification?name={name}&content={code}"
    resp = httpx.get(url)
    print(resp)
    print(f"{domain} 调用API 生成验证代码 {name} {code}")


def create_web_file(domain, content):
    """
    调用web程序api txt文件验证
    使程序首页生成对应页面内容
    """
    url = f"http://{domain}/22.php?type=add&bd={content}"
    resp = httpx.get(url)
    print(resp)
    print(f"{domain} 调用API 生成验证文件 {content}.txt")

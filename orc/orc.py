"""导入ddddocr"""

import ddddocr

def docr(img_path):
    """fuck ddddocr"""
    myocr = ddddocr.DdddOcr(show_ad=False)
    with open(img_path, 'rb') as img_f:
        image = img_f.read()
    res = myocr.classification(image)
    # print(f'验证码图片AI识别结果：{res}')
    return res

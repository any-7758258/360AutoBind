"""导入easyocr"""

# 导入easyocr
import easyocr


def ocr(img_path):
    """fuck easyOCR"""
    # 创建reader对象
    reader = easyocr.Reader(['en'], gpu=False)
    # 读取图像
    result = reader.readtext(img_path)
    # 结果
    if len(result) > 0 and len(result[0]) > 1:
        code = "".join([i for i in result[0][1] if i.isalpha()])
        print(f'验证码图片AI识别结果：{code}', result)
        return code
    # print('验证码图片识别失败 正在重试...')
    return 'err'

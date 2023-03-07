"""导入easyocr"""

# 导入easyocr
import easyocr


def ocr(img_path):
    """fuck easyOCR"""
    # 创建reader对象
    reader = easyocr.Reader(['en'])
    # 读取图像
    result = reader.readtext(img_path)
    # 结果
    if len(result) > 0 and len(result[0]) > 1:
        code = "".join([i for i in result[0][1] if i.isalpha()])
        print('img_path识别结果：', result)
        return code
    print('img_path识别结果：err', result)
    return 'err'

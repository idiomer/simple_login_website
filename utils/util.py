def generate_captcha(length=4, output_format='base64'):
    """
    生成验证码
    :return:
    """
    from io import BytesIO
    import base64, random, string
    from captcha.image import ImageCaptcha

    # 生成随机字符串
    label_str = ''.join(random.sample(string.ascii_letters + string.digits, length))
    # 生成图片
    image = ImageCaptcha().generate_image(label_str)

    if output_format.lower() == 'base64':
        output_buffer = BytesIO()
        image.save(output_buffer, format='JPEG')
        base64_str = base64.b64encode(output_buffer.getvalue())
        return label_str, base64_str.decode()
    else:
        # 保存图片
        output_captcha_path = f'/tmp/captcha_{label_str}.jpg'
        image.save(output_captcha_path)
        return label_str, output_captcha_path



def hash_password(password, salt=None):
    import hashlib
    import os
    if not salt:
        salt = os.urandom(16)  # 生成16字节的随机盐
    # 将盐和密码拼接起来
    salted_password = salt + password.encode('utf-8')
    # 使用SHA-256进行哈希
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password, salt


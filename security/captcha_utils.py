# security/captcha_utils.py

import random
import string
import logging
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont, ImageFilter
from datetime import datetime

logger = logging.getLogger(__name__)

class CaptchaGenerator:
    def __init__(self, length=6, width=200, height=70, font_size=36,
                 font_path='/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'):
        self.length = length
        self.width = width
        self.height = height
        self.font_size = font_size
        self.font_path = font_path

    def generate_code(self):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.length))

    def create_captcha_image(self, code=None):
        if code is None:
            code = self.generate_code()

        image = Image.new('RGB', (self.width, self.height), (255, 255, 255))
        draw = ImageDraw.Draw(image)

        try:
            font = ImageFont.truetype(self.font_path, self.font_size)
        except IOError:
            logger.warning("Captcha font not found. Falling back to default.")
            font = ImageFont.load_default()

        for _ in range(random.randint(2, 4)):
            self._draw_noise_line(draw)

        spacing = (self.width - 20) // self.length
        for i, char in enumerate(code):
            x = 10 + i * spacing + random.randint(-2, 2)
            y = (self.height - self.font_size) // 2 + random.randint(-5, 5)
            draw.text((x, y), char, font=font, fill=self._random_color())

        image = image.filter(ImageFilter.GaussianBlur(radius=1))

        buffer = BytesIO()
        image.save(buffer, 'PNG')
        buffer.seek(0)
        return buffer, code

    def _random_color(self):
        return tuple(random.randint(0, 150) for _ in range(3))

    def _draw_noise_line(self, draw):
        start = (random.randint(0, self.width), random.randint(0, self.height))
        end = (random.randint(0, self.width), random.randint(0, self.height))
        draw.line([start, end], fill=self._random_color(), width=2)

    def validate_captcha(self, user_input, actual_code):
        return user_input.strip().upper() == actual_code.strip().upper()

    def create_captcha_with_metadata(self):
        buffer, code = self.create_captcha_image()
        metadata = {
            'length': self.length,
            'width': self.width,
            'height': self.height,
            'font_size': self.font_size,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        return buffer, code, metadata

    def generate_captcha_as_base64(self):
        import base64
        buffer, code = self.create_captcha_image()
        image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        return image_base64, code

    def save_captcha_image_to_disk(self, filename='captcha.png', code=None):
        buffer, _code = self.create_captcha_image(code)
        with open(filename, 'wb') as f:
            f.write(buffer.read())
        return filename, _code

# Singleton instance
_default_captcha = CaptchaGenerator()

def generate_captcha():
    return _default_captcha.create_captcha_image()

def generate_code():
    return _default_captcha.generate_code()

def validate_captcha(user_input, actual_code):
    return _default_captcha.validate_captcha(user_input, actual_code)

def generate_captcha_with_metadata():
    return _default_captcha.create_captcha_with_metadata()

def generate_captcha_as_base64():
    return _default_captcha.generate_captcha_as_base64()

def save_captcha_to_file(filename='captcha.png', code=None):
    return _default_captcha.save_captcha_image_to_disk(filename, code)

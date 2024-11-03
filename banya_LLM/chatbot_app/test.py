# ... 기존 코드 ...
from dotenv import load_dotenv
import os

# .env 파일 로드
load_dotenv('../.env')

# NVIDIA_API_KEY 출력
nvidia_api_key = os.getenv("NVIDIA_API_KEY")
# print(nvidia_api_key)
# ... 기존 코드 ...




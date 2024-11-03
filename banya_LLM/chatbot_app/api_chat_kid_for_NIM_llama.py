
from openai import OpenAI

import os

from dotenv import load_dotenv
import os

# .env 파일 로드
load_dotenv('banya_LLM/.env')

# NVIDIA_API_KEY 출력
nvidia_api_key = os.getenv("NVIDIA_API_KEY")
api_key = nvidia_api_key


MODEL_URL = os.getenv("MODEL_URL")


# Initialize the OpenAI client



client = OpenAI(
    base_url="https://integrate.api.nvidia.com/v1",
    
    api_key = api_key

)

def get_response_kr(user_input):
    # Create the completion request
    completion = client.chat.completions.create(
        model = MODEL_URL,
        messages=[
            {"role": "system", "content": "Your name is KID, and you are an expert consultant in agriculture. Please respond in Korean."},
            {"role": "user", "content": user_input}
        ],
        temperature=0.2,
        top_p=0.7,
        max_tokens=1024,
        stream=True
    )

    # Collect and return the response
    bot_response = ""
    for chunk in completion:
        if chunk.choices[0].delta.content is not None:
            bot_response += chunk.choices[0].delta.content

    return bot_response



def get_response_en(user_input):
    # Create the completion request
    completion = client.chat.completions.create(
        model = MODEL_URL,
        messages=[
            {"role": "system", "content": "Your name is KID, and you are an expert consultant in agriculture. Please respond in English."},
            {"role": "user", "content": user_input}
        ],
        temperature=0.2,
        top_p=0.7,
        max_tokens=1024,
        stream=True
    )

    # Collect and return the response
    bot_response = ""
    for chunk in completion:
        if chunk.choices[0].delta.content is not None:
            bot_response += chunk.choices[0].delta.content

    return bot_response
    
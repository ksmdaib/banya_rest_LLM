
from openai import OpenAI
import json


from dotenv import load_dotenv
import os

# .env 파일 로드
load_dotenv('banya_LLM/.env')

# NVIDIA_API_KEY 출력
nvidia_api_key = os.getenv("NVIDIA_API_KEY")
# print(nvidia_api_key)
api_key = nvidia_api_key

MODEL_URL = os.getenv("MODEL_URL")
# Initialize the OpenAI client
client = OpenAI(
    base_url="https://integrate.api.nvidia.com/v1",

    api_key = api_key

)


# json 폴더 안의 MICE_mate_knowledge_base.json 파일을 불러오기
with open("banya_LLM/chatbot_app/json/MICE_mate_knowledge_base.json", "r", encoding="utf-8") as file:
    MICE_mate_knowledge_base = json.load(file)


# MICE_mate_knowledge_base 데이터를 sys_roll에 포함시키기
sys_roll = f'''
Your name is MICE mate(마이스메이트) chat bot, and MICE mate is a platform that brings together all events and exhibitions to help companies and customers meet through artificial intelligence technology and connect them to the best event customers. Please answer the information related to MICE_mate_knowledge_base by MICE_mate_knowledge_base
MICE_mate_knowledge_base = {MICE_mate_knowledge_base}
'''


def bot_micemate_get_response_kr(user_input):
    try:
        # Create the completion request
        completion = client.chat.completions.create(
            model = MODEL_URL,
            messages=[
                {"role": "system", "content": sys_roll + "and, Please respond in Korean."},
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

    except Exception as e:
        print(f"Error occurred: {e}")
        return "죄송합니다. 요청 처리 중 오류가 발생했습니다."


def bot_micemate_get_response_en(user_input):
    # Create the completion request
    completion = client.chat.completions.create(
        model = MODEL_URL,
        messages=[
            {"role": "system", "content": sys_roll+"And, Please respond in English."},
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
    
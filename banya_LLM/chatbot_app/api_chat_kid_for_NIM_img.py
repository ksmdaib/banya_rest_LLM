
import requests, base64
import json

import os

from dotenv import load_dotenv
import os

# .env 파일 로드
load_dotenv('banya_LLM/.env')

# NVIDIA_API_KEY 출력
nvidia_api_key = os.getenv("NVIDIA_API_KEY")
# print(nvidia_api_key)
api_key = nvidia_api_key


IMG_INVOKE_URL = os.getenv("IMG_INVOKE_URL")


def get_response_img_en(user_input, image_b64,image_type):

    # Define API endpoint and other configuration variables
    # invoke_url = "https://ai.api.nvidia.com/v1/vlm/nvidia/neva-22b"
    invoke_url = IMG_INVOKE_URL
    stream = True  # Use stream for real-time response, if required

    # Check if image size exceeds 180,000 characters for the direct upload method
    assert len(image_b64) < 66_500_000, \
        "To upload larger images, use the assets API (see docs)."

    # Define the headers and payload for the request
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "text/event-stream" if stream else "application/json"
    }

    payload = {
        "messages": [
            {"role": "system", "content": "Your name is KID, and you are an expert consultant in agriculture. Please respond in English."},
            
            {
                "role": "user",
                "content": f'{user_input} Tell me about this image.<img src="data:image/{image_type};base64,{image_b64}" />'
            }
        ],
        "max_tokens": 1024,
        "temperature": 0.20,
        "top_p": 0.70,
        "seed": 0,
        "stream": stream
    }

    # Send the request and handle the response
    response = requests.post(invoke_url, headers=headers, json=payload)
    
    bot_response = ""
    for chunk in response.iter_lines():
        # Decode the byte stream into a string
        chunk = chunk.decode('utf-8')
        
        # Skip any 'data:' markers and handle only valid JSON content
        if chunk.startswith('data:'):
            chunk_data = chunk[len('data: '):]  # Remove the 'data: ' prefix
            try:
                chunk_json = json.loads(chunk_data)
                # If the chunk contains a content delta, append it to the bot_response
                if 'choices' in chunk_json and 'delta' in chunk_json['choices'][0]:
                    content = chunk_json['choices'][0]['delta'].get('content')
                    if content:
                        bot_response += content
            except json.JSONDecodeError:
                # Handle any decoding errors, you may log or ignore these
                continue
    
    return bot_response











def get_response_img_kr(user_input, image_b64,image_type):

    # Define API endpoint and other configuration variables
    invoke_url = "https://ai.api.nvidia.com/v1/vlm/nvidia/neva-22b"
    stream = True  # Use stream for real-time response, if required

    # Check if image size exceeds 180,000 characters for the direct upload method
    assert len(image_b64) < 66_500_000, \
        "To upload larger images, use the assets API (see docs)."

    # Define the headers and payload for the request
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "text/event-stream" if stream else "application/json"
    }

    payload = {
        "messages": [
            {"role": "system", "content": "Your name is KID, and you are an expert consultant in agriculture. Please respond in Korean."},
            
           {
                "role": "user",
                "content": f'{user_input} Tell me about this image.<img src="data:image/{image_type};base64,{image_b64}" />'
            }


        ],
        "max_tokens": 1024,
        "temperature": 0.20,
        "top_p": 0.70,
        "seed": 0,
        "stream": stream
    }

    # Send the request and handle the response
    response = requests.post(invoke_url, headers=headers, json=payload)
    
    bot_response = ""
    for chunk in response.iter_lines():
        # Decode the byte stream into a string
        chunk = chunk.decode('utf-8')
        
        # Skip any 'data:' markers and handle only valid JSON content
        if chunk.startswith('data:'):
            chunk_data = chunk[len('data: '):]  # Remove the 'data: ' prefix
            try:
                chunk_json = json.loads(chunk_data)
                # If the chunk contains a content delta, append it to the bot_response
                if 'choices' in chunk_json and 'delta' in chunk_json['choices'][0]:
                    content = chunk_json['choices'][0]['delta'].get('content')
                    if content:
                        bot_response += content
            except json.JSONDecodeError:
                # Handle any decoding errors, you may log or ignore these
                continue
    
    return bot_response

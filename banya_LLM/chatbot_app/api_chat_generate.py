import transformers
import torch
import time
from dotenv import load_dotenv
import os

# .env 파일 로드
load_dotenv('banya_LLM/.env')

# NVIDIA_API_KEY 출력
nvidia_api_key = os.getenv("NVIDIA_API_KEY")
# print(nvidia_api_key)
api_key = nvidia_api_key

MODEL_URL = os.getenv("MODEL_URL")
# Initialize the model and pipeline
model_id = MODEL_URL

pipeline = transformers.pipeline(
    "text-generation",
    model=model_id,
    tokenizer=model_id,
    model_kwargs={"torch_dtype": torch.float16},
    device_map="auto",
)

max_length = 1024
stride = 768

def sliding_window_text_generation(text, do_sample, max_new_tokens, temperature=0.7, top_p=0.9):
    results = []
    start_time = time.time()

    for start in range(0, len(text), stride):
        end = min(start + max_length, len(text))
        input_text = text[start:end]

        generation_kwargs = {
            "max_new_tokens": max_new_tokens,
            "repetition_penalty": 1.2,
            "pad_token_id": pipeline.tokenizer.eos_token_id
        }

        if do_sample:
            generation_kwargs.update({
                "do_sample": True,
                "temperature": temperature,
                "top_p": top_p
            })
        else:
            generation_kwargs.update({
                "do_sample": False,
                "num_beams": 5
            })

        outputs = pipeline(input_text, **generation_kwargs)
        generated_text = outputs[0]["generated_text"]

        if start + max_length >= len(text):
            generated_text = generated_text.rstrip(pipeline.tokenizer.eos_token)

        results.append(generated_text)

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Prediction took {elapsed_time:.2f} seconds")

    combined_result = ' '.join(results)

    return combined_result.strip()

conversation_history = ["You are KID, a Master Farmer AI who responds in English."]

def get_response(user_input):
    conversation_history.append(f"User: {user_input}")
    input_text = "\n".join(conversation_history)

    if len(user_input) < 20:
        max_new_tokens = 48
        do_sample = False
    elif "explain" in user_input.lower() or "why" in user_input.lower():
        max_new_tokens = 128
        do_sample = True
    else:
        max_new_tokens = 64
        do_sample = False

    response = sliding_window_text_generation(input_text, do_sample, max_new_tokens)
    bot_response = response.split("\n")[-1].strip()

    conversation_history.append(f"Bot: {bot_response}")

    return bot_response

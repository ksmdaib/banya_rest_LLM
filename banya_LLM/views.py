from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

import json
from .chatbot_app.api_chat_kid_for_NIM_llama import *
from .chatbot_app.api_chat_kid_for_NIM_img import *
from .chatbot_app.api_micemate_chat_for_NIM_llama import *




#MICEmate
@csrf_exempt
@require_http_methods(["POST"])
def micemate_get_response_kr(request):
    try:
        data = json.loads(request.body)
        print(data)
        user_input = data.get('message', '')
        
        if not user_input:
            return JsonResponse({'error': 'Missing "message" field in JSON'}, status=400)

        bot_response = bot_micemate_get_response_kr(user_input)

        return JsonResponse({'bot': bot_response})
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)


@csrf_exempt
@require_http_methods(["POST"])
def micemate_get_response_en(request):
    try:
        data = json.loads(request.body)
        user_input = data.get('message', '')
        
        if not user_input:
            return JsonResponse({'error': 'Missing "message" field in JSON'}, status=400)

        bot_response = bot_micemate_get_response_en(user_input)

        return JsonResponse({'bot': bot_response})
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
        













#KID
@csrf_exempt
@require_http_methods(["POST"])
def generate_response_kr(request):
    try:
        data = json.loads(request.body)
        user_input = data.get('message', '')
        
        if not user_input:
            return JsonResponse({'error': 'Missing "message" field in JSON'}, status=400)

        bot_response = get_response_kr(user_input)

        return JsonResponse({'bot': bot_response})
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)


@csrf_exempt
@require_http_methods(["POST"])
def generate_response_en(request):
    try:
        data = json.loads(request.body)
        user_input = data.get('message', '')
        
        if not user_input:
            return JsonResponse({'error': 'Missing "message" field in JSON'}, status=400)

        bot_response = get_response_en(user_input)

        return JsonResponse({'bot': bot_response})
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)



@csrf_exempt
@require_http_methods(["GET"])
def getconnect(request):
    # Respond to GET requests with a success message
    return JsonResponse({'message': 'success connected'}, status=200)




@csrf_exempt
def generate_response_img_en(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        if 'image' not in request.FILES and 'message' not in request.POST:
            return JsonResponse({'error': 'Missing image or message in the request'}, status=400)

        user_input = request.POST.get('message', '')
        image_file = request.FILES.get('image', None)

        if image_file:
            # Read the image file as binary and encode it to base64
            image_data = image_file.read()
            image_b64 = base64.b64encode(image_data).decode('utf-8')

            # Get the image format (e.g., png, jpeg)
            image_type = image_file.content_type.split('/')[-1]

            # Call the function to process the image with NVIDIA API
            bot_response = get_response_img_en(user_input, image_b64, image_type)
        else:
            bot_response = get_response_en(user_input)  # Handle text input only

        return JsonResponse({'response': bot_response})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
def generate_response_img_kr(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        if 'image' not in request.FILES and 'message' not in request.POST:
            return JsonResponse({'error': 'Missing image or message in the request'}, status=400)

        user_input = request.POST.get('message', '')
        image_file = request.FILES.get('image', None)

        if image_file:
            # Read the image file as binary and encode it to base64
            image_data = image_file.read()
            image_b64 = base64.b64encode(image_data).decode('utf-8')

            # Get the image format (e.g., png, jpeg)
            image_type = image_file.content_type.split('/')[-1]

            # Call the function to process the image with NVIDIA API
            bot_response = get_response_img_kr(user_input, image_b64, image_type)
        else:
            bot_response = get_response_kr(user_input)  # Handle text input only

        return JsonResponse({'response': bot_response})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

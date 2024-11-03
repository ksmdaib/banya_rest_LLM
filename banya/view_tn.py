from datetime import datetime
import pytz
from django.http import JsonResponse, HttpResponse
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from banya_utils import file_upload
from .model_tn import *
from banya_utils.crypto import RSAEncryption

User = get_user_model()


def tony(request):
    return HttpResponse("토니의 뷰!")


def list_users(request):
    users = User.objects.all()
    data = [{'username': user.username, 'email': user.email} for user in users]
    return JsonResponse(data, safe=False)


def project_data_sort(request):
    data = list(ProjectDataSort.objects.all().values('id', 'project_data_sort_name'))
    return JsonResponse(data, safe=False)


def artifact_sort(request):
    data = list(ArtifactSort.objects.all().values('id', 'artifact_sort_name'))
    return JsonResponse(data, safe=False)

@csrf_exempt  # CSRF 토큰을 무시하도록 설정 (개발 환경에서 사용, 운영 환경에선 주의)
def project_detail_ready(request):
    data = list(ProjectDetailReady.objects.all().values())
    result = {}
    for item in data:
        source = item["source"]
        # 각 source 키가 없으면 빈 리스트로 초기화
        if source not in result:
            result[source] = []
        # 리스트에 데이터 추가
        result[source].append({
            "id": item["id"],
            "artifact_sort_name": item["artifact_sort_name"]
        })

    return JsonResponse(result)

@csrf_exempt  # CSRF 토큰을 무시하도록 설정 (개발 환경에서 사용, 운영 환경에선 주의)
def project_detail_list(request):
    user_email = request.POST.get('user_email')
    project_id = request.POST.get('project_id')

    data = list(Project.objects.filter(user_email=user_email, id=project_id).values())
    return JsonResponse(data, safe=False)


@csrf_exempt  # CSRF 토큰을 무시하도록 설정 (개발 환경에서 사용, 운영 환경에선 주의)
def register_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        if not username or not email or not password:
            return JsonResponse({"success": False, "message": "All fields are required"}, status=400)

        # 비밀번호를 해싱하고 사용자 생성
        try:
            user = User.objects.create(
                username=username,
                email=email,
                password_hash=make_password(password)
            )
            return JsonResponse({"success": True, "message": "User registered successfully"}, status=201)

        except Exception as e:
            return JsonResponse({"success": False, "message": str(e)}, status=500)

    return JsonResponse({"success": False, "message": "Invalid request method"}, status=405)


@csrf_exempt  # CSRF 토큰을 무시하도록 설정 (개발 환경에서 사용, 운영 환경에선 주의)
def project_card_list(request):
    user_email = request.POST.get('user_email')
    data = list(Project.objects.filter(user_email=user_email).values())
    return JsonResponse(data, safe=False)


@csrf_exempt  # CSRF 토큰을 무시하도록 설정 (개발 환경에서 사용, 운영 환경에선 주의)
def insert_project(request):
    project_name = request.POST.get('project_name')
    project_desc = request.POST.get('project_desc')
    project_sort = request.POST.get('project_sort')
    project_data_sort = request.POST.get('project_data_sort')
    artifact_selected = request.POST.get('artifact_selected')
    banya_api_key = request.POST.get('banya_api_key')
    thum_image_url = request.POST.get('thum_image_url')
    user_email = request.POST.get('user_email')

    project = Project(
        project_name=project_name,
        project_desc=project_desc,
        project_sort=project_sort,
        project_data_sort=project_data_sort,
        artifact_selected=artifact_selected,
        banya_api_key=banya_api_key,
        thum_image_url=thum_image_url,
        user_email=user_email,
        created_date=datetime.now(pytz.timezone('Asia/Seoul'))
    )
    project.save()
    return JsonResponse({"success": True, "message": "Inserted successfully."}, status=201)

#단일 파일 업로드
@csrf_exempt
def upload_public(request):
    if request.method == 'POST' and 'file' in request.FILES:
        uploaded_file = request.FILES['file']
        bucket_name = 'banya_public'
        destination_blob_name = uploaded_file.name

        # 구글 클라우드 스토리지에 파일 업로드 및 URL 생성
        file_url = file_upload.upload_blob(bucket_name, uploaded_file, destination_blob_name)
        print("file uploaded : ", file_url)
        return JsonResponse({'file_url': file_url})

    return JsonResponse({'error': 'Invalid request'}, status=400)

#다중 파일 업로드
@csrf_exempt
def upload_user_files(request):
    if request.method == 'POST' and 'files' in request.FILES:
        uploaded_files = request.FILES.getlist('files')  # 여러 파일 가져오기
        bucket_name = 'banya_training_data'

        # 구글 클라우드 스토리지에 파일 업로드 및 URL 생성
        file_urls = file_upload.upload_files(bucket_name, uploaded_files)
        print("Files uploaded:", file_urls)

        return JsonResponse({'file_urls': file_urls})

    return JsonResponse({'error': 'Invalid request'}, status=400)

phrase = "lokiversedaib"


#키 생성 후 저장 함수
@csrf_exempt  # CSRF 토큰을 무시하도록 설정 (개발 환경에서 사용, 운영 환경에선 주의)
def create_save_keys(request):
    user_email = request.POST.get('user_email')
    key_name = request.POST.get('key_name')

    #프레이즈로 키쌍 생성
    rsa_encryption = RSAEncryption(phrase)
    rsa_encryption.generate_key_pair()

    private_key = rsa_encryption.get_private_key_strings()
    public_key = rsa_encryption.get_public_key_strings()
    enc_key_name = rsa_encryption.encrypt(key_name)
    api_key = rsa_encryption.generate_hash_key()

    user_api = UserApi(
        user_email = user_email,
        api_key = api_key,
        public_key = public_key,
        key_name = enc_key_name,
        created_date = datetime.now(pytz.timezone('Asia/Seoul'))
    )
    user_api.save()
    return JsonResponse({'pk':private_key}, status=201)


@csrf_exempt  # CSRF 토큰을 무시하도록 설정 (개발 환경에서 사용, 운영 환경에선 주의)
def delete_user_api(request):
    user_email = request.POST.get('user_email')
    return_msg = "Deleted successfully"
    return_flag = True
    return_status = 201
    try:
        user_api = UserApi.objects.get(user_email=user_email)
        user_api.delete()
    except UserApi.DoesNotExist:
        return_msg = "Error occurred!!"
        return_flag = False
        return_status = 400
    return JsonResponse({"success": return_flag, "message": return_msg }, status=return_status)


@csrf_exempt  # CSRF 토큰을 무시하도록 설정 (개발 환경에서 사용, 운영 환경에선 주의)
def get_user_api(request):
    user_email = request.POST.get('user_email')
    data = list(UserApi.objects.filter(user_email=user_email).values())
    return JsonResponse(data, safe=False)

def decrypt_message(request):
    encrypted_message = request.GET.get('encrypted_message')
    rsa_encryption = RSAEncryption(phrase)
    rsa_encryption.generate_key_pair()
    return rsa_encryption.decrypt(encrypted_message)

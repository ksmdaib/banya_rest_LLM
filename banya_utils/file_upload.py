from google.cloud import storage
import os

# 서비스 계정 키 파일 경로 설정
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = '/Users/daib-01/PycharmProjects/banya_rest/banya_utils/top-opus-433400-m0-4f3b1de4a55f.json'


def upload_blob(bucket_name, source_file, destination_blob_name):
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)

    blob = bucket.blob(destination_blob_name)
    base_name, extension = os.path.splitext(destination_blob_name)
    count = 1

    while blob.exists():
        new_blob_name = f"{base_name}_{count}{extension}"
        blob = bucket.blob(new_blob_name)
        count += 1

    blob.upload_from_file(source_file)
    file_url = f"https://storage.googleapis.com/{bucket_name}/{blob.name}"
    return file_url

# # 사용 예시
# if __name__ == "__main__":
#     upload_blob(
#         bucket_name='banya_public',        # 외부 오픈 버킷
#         source_file_name='/Users/daib-01/Downloads/dog.jpeg',  # 업로드할 파일의 경로
#         destination_blob_name='dog.jpeg'  # 스토리지에 저장될 경로
#     )


def upload_files(bucket_name, uploaded_files):
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)

    uploaded_urls = []

    for uploaded_file in uploaded_files:
        try:
            destination_blob_name = uploaded_file.name
            blob = bucket.blob(destination_blob_name)
            blob.upload_from_file(uploaded_file)

            # 파일의 URL 생성
            file_url = f"https://storage.googleapis.com/{bucket_name}/{destination_blob_name}"
            uploaded_urls.append(file_url)

        except Exception as e:
            print(f"에러 발생: {str(e)}")

    return uploaded_urls

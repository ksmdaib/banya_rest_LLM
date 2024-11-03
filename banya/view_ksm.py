from django.http import JsonResponse, HttpResponse



from django.http import JsonResponse
from .model_ksm import *


def ksm(request):
    return HttpResponse("수명의 뷰!")

def project_sort_list(request):
    project_sorts = ProjectSort.objects.all().values('id', 'project_sort_name')
    data = list(project_sorts)
    return JsonResponse(data, safe=False)

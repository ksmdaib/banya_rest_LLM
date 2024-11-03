from django.shortcuts import render

# Create your views here.
from django.http import HttpResponse


def yj(request):
    return HttpResponse("예진의 뷰!")
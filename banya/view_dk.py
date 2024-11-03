from django.shortcuts import render

# Create your views here.
from django.http import HttpResponse


def dk(request):
    return HttpResponse("동욱의 뷰!")
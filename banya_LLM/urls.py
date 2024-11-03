from django.urls import path
from . import views

urlpatterns = [
    path('generate/kid/kr', views.generate_response_kr, name='generate_response_kr'),
    path('generate/kid/en', views.generate_response_en, name='generate_response_en'),
    path('generate/getconnect', views.getconnect, name='getconnect'),
    path('generate/kid/img/kr', views.generate_response_img_kr, name='generate_response_kr'),
    path('generate/kid/img/en', views.generate_response_img_en, name='generate_response_en'),

    #micemate
    path('generate/micemate/kr', views.micemate_get_response_kr, name='generate_response_kr'),
    path('generate/micemate/en', views.micemate_get_response_en, name='generate_response_en'),

]
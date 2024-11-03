"""
URL configuration for banya_rest project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.urls import include

import banya.views
import banya.view_dk
import banya.view_tn
import banya.view_yj
import banya.view_ksm

import banya_LLM.views

urlpatterns = [
    path('admin/', admin.site.urls, name="admin"),
    path('home/', banya.views.home, name="home"),


    #tn
    path('tony/', banya.view_tn.tony, name="tn"),
    path('register/', banya.view_tn.register_user, name='register'),
    path('list_users/', banya.view_tn.list_users, name='list_users'),
    path('project_sort/', banya.view_ksm.project_sort_list, name='project_sort'),
    path('project_data_sort/', banya.view_tn.project_data_sort, name='project_data_sort'),
    path('artifact_sort/', banya.view_tn.artifact_sort, name='artifact_sort'),
    path('project_card_list/', banya.view_tn.project_card_list, name='project_card_list'),
    path('project_detail_list/', banya.view_tn.project_detail_list, name='project_detail_list'),
    path('project_detail_ready/', banya.view_tn.project_detail_ready, name='project_detail_ready'),
    path('insert_project/', banya.view_tn.insert_project, name='insert_project'),
    path('file_upload/', banya.view_tn.upload_public, name='upload_public'),
    path('upload_user_files/', banya.view_tn.upload_user_files, name='upload_user_files'),
    path('create_save_keys/', banya.view_tn.create_save_keys, name='create_save_keys'),
    path('delete_user_api/', banya.view_tn.delete_user_api, name='delete_user_api'),
    path('get_user_api/', banya.view_tn.get_user_api, name='get_user_api'),


    path('dk/', banya.view_dk.dk, name="dk"),
    path('yj/', banya.view_yj.yj, name="yj"),
    
    
    
    
    
    
    #ksm
    path('ksm/', banya.view_ksm.ksm, name="ksm"),
    path('ksm/projects', banya.view_ksm.project_sort_list, name="project_sort_list"),

    path("llm/", include("banya_LLM.urls")),






]

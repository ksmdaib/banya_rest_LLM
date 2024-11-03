from django.contrib.auth.models import AbstractBaseUser, BaseUserManager



from django.db import models

class ProjectSort(models.Model):
    project_sort_name = models.CharField(max_length=100)

    class Meta:
        db_table = 'project_sort'  # 실제 테이블 이름을 지정합니다.

    def __str__(self):
        return self.project_sort_name

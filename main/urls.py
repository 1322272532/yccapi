from django.urls import path
from  . import  views
from django.conf import settings   #引入配置文件
from django.views.static import serve as serve_media
from django.views.static import serve as serve_static
from .views import UserRegisterApi,UserRegisterCode,UserLoginCode,UserLoginApi,UserLogoutApi,ApiMain,ApiLikes,ApiFavorites

app_name = 'app'




urlpatterns = [
    path('', views.index),
    #API管理平台自用API接口(不包含任何公开的资源接口)
    path('register',UserRegisterApi.as_view(),name='register'),
    path('login', UserLoginApi.as_view(), name='login'),
    path('logout',UserLogoutApi.as_view(),name='logout'),
    path('user/register/code', UserRegisterCode.as_view(), name='register_code'),
    path('user/login/code', UserLoginCode.as_view(), name='login_code'),
    path('api',ApiMain.as_view(),name='apimain'),
    path('api/likes',ApiLikes.as_view(),name='apilikes'),
    path('api/favorites',ApiFavorites.as_view(),name='apifavorites'),
    # -----------//
    path(r'media/<path:path>',serve_media,{'document_root':settings.MEDIA_ROOT},),#开放media的访问权限
    path(r'static/<path:path>', serve_static, {'document_root': settings.STATIC_ROOT}, ),  # 开放static的访问权限

]

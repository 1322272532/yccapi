import re,uuid

#数据验证
from django.core.exceptions import ValidationError #数据验证错误捕捉（返回可供用户查看的错误信息）
from django.core.files.images import ImageFile
from django.core.mail import send_mail
from django.core.validators import validate_email, FileExtensionValidator
from django.contrib.auth import password_validation

#视图函数
from django.views import View
from django.shortcuts import render,HttpResponseRedirect,redirect
from django.http import HttpResponse, JsonResponse
from django.contrib import messages

#其他基本库
import requests,json,os,datetime
import requests.sessions
from django.apps import apps
#模板
from django.db.models import Q, Count, Sum, F  # 复杂查询
from .models import User,User_access_record,Api,Api_tag,Api_info,Api_likes,Api_favorites,Api_visit_param,Api_respon_param,User_register_code,User_login_code,\
    Api_access,Api_access_record
from django.contrib.sessions.models import Session
from django.core import serializers #序列化
#数据加密
import hashlib #哈希算法
from cryptography.fernet import Fernet #可逆加密
cipher_key = b'03qH0OPB0EE5pC36gHbHCsvbq5_qIZzjK2Ahve7kDOw='
jm = Fernet(cipher_key)  # 使用密钥 #相同数据每次加密都不一样
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
#crsf 验证
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt #crsf

#图片处理
from PIL import Image

def login_adorner(func): #装饰器
    def wrap(request, *args, **kwargs):
        if 'username' not in request.session or 'uid' not in request.session or 'email' not in request.session or 'name' not in request.session:
            re_json = {
                'code':200,
                'msg':"登录信息不存在，请重新登录!",
                'redirect': '/login',
            }
            return JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})

        else:
            session_key = request.COOKIES.get('sessionid')
            get_key = Session.objects.get(session_key=session_key)
            expire_time = get_key.expire_date
            if expire_time <now_time():
                re_json = {
                    'code': 200,
                    'msg': "登录信息已过期，请重新登录!",
                    'redirect':'/login',
                }
                return JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})
            #检查cookie
            c_uid = request.COOKIES.get('uid')
            if not c_uid:
                re_json = {
                    'code': 200,
                    'msg': "登录Cookie信息已过期，请重新登录!",
                    'redirect': '/login',
                }
                return JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})
        return func(request, *args, **kwargs)#返回视图
    return wrap

def now_time():
    now_time = datetime.datetime.now()
    return now_time
def jiami_def(request,jiami):
    try:
        jiami_str = str(jiami)
        jiami_str_byt = jiami_str.encode('utf-8')
        jiami_str_str = b'%s' % (jiami_str_byt) #固定格式
        jiami_no1 = jm.encrypt(jiami_str_str)
        jiami_over = eval(str(jiami_no1)[1:])
        #返回的是str的纯净密码
        return jiami_over
    except:
        pass

def jiemi_def(request,jiemi):
    try:
        jiemi_str_byt = jiemi.encode('utf-8')
        jiemi_str_str = b'%s' % (jiemi_str_byt) #解密格式

        jiemi_no1 = jm.decrypt(jiemi_str_str)
        jiemi_over = eval(str(jiemi_no1)[1:])
        return jiemi_over
    except:
        pass

@login_adorner
def index(request):
    re_json={
        'code':200,
        'msg':"Api服务器运行正常",
        'send_time':now_time(),
        'data':'',
        'path':'/',
    }
    return JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})



@method_decorator(csrf_exempt,name='dispatch')
class UserRegisterApi(View):
    def get(self,request):
        re_json = {
            'code': 500,
            'msg': "你正在访问易次次公益API-注册api",
            'action':"未授权的接口",
            're_code':'Get',
            'send_time': now_time(),
            'data': '',
            'path': '/register',
        }
        return JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})


    def post(self,request):
        code = request.POST.get('code')
        name = request.POST.get('name')
        username = request.POST.get('username')
        password = request.POST.get('password')
        photo =request.FILES.get("photo")
        email = request.POST.get('email')
        #首先验证验证码code
        try:
            test = User_register_code.objects.get(username=username,code=code,email=email)
            #检查时间
            expire_time =test.expire_time
            if now_time()>expire_time:
                re_json = {
                    'code': 500,
                    'msg': '验证码已过期,请重新生成。',
                    'action': '注册账号',
                    're_code': 'Post',
                    'send_time': now_time(),
                    'data': '',
                    'path': '/register',
                }
                return JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})
        except:
            re_json = {
                'code': 500,
                'msg': '验证码不正确或与提交验证码账户不匹配，请重试。',
                'action': '注册账号',
                're_code': 'Post',
                'send_time': now_time(),
                'data': '',
                'path': '/register',
            }
            return JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})
        validate = validate_user(name, password,photo,username,email) #验证数据
        if validate['code']==False:
            re_json = {
                'code': 500,
                'msg': str(validate['msg']),
                'action': '注册账号',
                're_code': 'Post',
                'send_time': now_time(),
                'data': '',
                'path': '/register',
            }
            return JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})
        try:
            #写入数据库
            password_jm =make_password(password)

            User.objects.create(username=username,name=name,power=0,active=True,password=password_jm,photo=photo,email=email)
        except Exception as e:
            print(e)
            re_json = {
                'code': 500,
                'msg': '注册失败，请重试，多次出错请联系管理员。',
                'action': '注册账号',
                're_code': 'Post',
                'send_time': now_time(),
                'data': '',
                'path': '/register',
            }
            return JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})
        re_json = {
            'code': 200,
            'msg': "恭喜您,成功注册账号。",
            'action':'注册账号',
            're_code': 'Post',
            'send_time': now_time(),
            'data': '',
            'path': '/register',
        }
        return JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})

class UserRegisterCode(View):
    def get(self,request):
        #发送用户注册所需的email邮件
        email = request.GET.get('email')
        username = request.GET.get('username')
        code = ''

        #验证是否已存在
        try:
            test = User_register_code.objects.get(username=username)
            #删除
            test.delete()
        except Exception as e:
            print(e)
            #创建验证码数据库

        try:
            create = User_register_code.objects.create(username=username,email=email)
            code = create.code
        except Exception as e:
            print(e)
            re_json = {
                'code': 500,
                'msg': "创建注册验证码数据库失败。",
                'action': "创建注册验证码数据库",
                're_code': 'Get',
                'send_time': now_time(),
                'data': '',
                'path': '/user/register/code',
            }
            return JsonResponse(re_json)

        subject = '易次次Api注册验证码'  # 邮件头部信息
        # 邮件信息
        print(code)
        message = '<h2>'+code+'<h2><br>验证码有效时间为10分钟，请你尽快完成账号注册。'
        try:
            result = send_mail(subject=subject, message='', from_email='dwy9997@163.com', recipient_list=[email, ],
                               html_message=message)  # html 因为里面含有 html标签
            print('邮箱发送成功' + email, result)
        except Exception as e:
            print(e)
            re_json = {
                'code': 500,
                'msg': "注册验证码发送失败",
                'action': "注册验证码",
                're_code': 'Get',
                'send_time': now_time(),
                'data': '',
                'path': '/user/register/code',
            }
            return JsonResponse(re_json)
        re_json = {
            'code': 200,
            'msg': "已发送注册验证码",
            'action': "注册验证码",
            're_code': 'Get',
            'send_time': now_time(),
            'data': '',
            'path': '/user/register/code',
        }
        return JsonResponse(re_json)

class UserLoginApi(View):
    def get(self,request):
        username = request.GET.get("username")
        password =request.GET.get('password')
        code = request.GET.get("code")
        remember = request.GET.get('remember')
        #检查验证码

        password_jm =make_password(password)
        try:
            test = User_login_code.objects.get(username=username,code=code)
            #检查时间
            expire_time =test.expire_time
            if now_time()>expire_time:
                re_json = {
                    'code': 500,
                    'msg': '验证码已过期,请重新生成。',
                    'action': '登录账号',
                    're_code': 'Get',
                    'send_time': now_time(),
                    'data': '',
                    'path': '/login',
                }
                return JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})
        except Exception as e:
            print(e)
            re_json = {
                'code': 500,
                'msg': '验证码不正确或与提交验证码账户不匹配，请重试。',
                'action': '登录账号',
                're_code': 'Get',
                'send_time': now_time(),
                'data': '',
                'path': '/login',
            }
            return JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})
        #检查是否账号密码是否正确
        try:
            get_password = User.objects.get(username=username)
            test_password_hax = check_password(password, get_password.password)
            if test_password_hax ==False:
                re_json = {
                    'code': 500,
                    'msg': '账号密码不正确！',
                    'action': '登录账号',
                    're_code': 'Get',
                    'send_time': now_time(),
                    'data': '',
                    'path': '/login',
                }
                return JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})
            #设置登录Cookie/session
            #session 统一保存60天
            request.session['username'] = get_password.username
            request.session['uid'] = get_password.id
            request.session['email'] = get_password.email
            request.session['name'] = get_password.name

            re_json = {
                'code': 200,
                'msg': '成功登陆!',
                'action': '登录账号',
                're_code': 'Get',
                'send_time': now_time(),
                'data': '',
                'path': '/login',
            }
            id_jiami = jiami_def(request,get_password.id)
            respon = JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})
            respon.set_cookie('uid', id_jiami)  # 保持关闭浏览器即取消


            if remember ==True:  # 检查复选框
                respon.set_cookie('uid', id_jiami, 60 * 60 * 24 * 60)  # 保持登录60*24 MIN
            return respon
        except Exception as e:
            print(e)
            re_json = {
                'code': 500,
                'msg': '账号未注册！',
                'action': '登录账号',
                're_code': 'Get',
                'send_time': now_time(),
                'data': '',
                'path': '/login',
            }
            return JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})

class UserLoginCode(View):
    def get(self,request):
        #发送用户登录所需的email邮件
        email = request.GET.get('email')
        username = request.GET.get('username')
        code = ''

        #验证是否已存在
        try:
            test = User_login_code.objects.get(username=username)
            #删除
            test.delete()
        except Exception as e:
            print(e)
            #创建验证码数据库

        try:
            create = User_login_code.objects.create(username=username,email=email)
            code = create.code
        except Exception as e:
            print(e)
            re_json = {
                'code': 500,
                'msg': "创建登录验证码数据库失败。",
                'action': "创建登录验证码数据库",
                're_code': 'Get',
                'send_time': now_time(),
                'data': '',
                'path': '/user/login/code',
            }
            return JsonResponse(re_json)

        subject = '易次次Api登录验证码'  # 邮件头部信息
        # 邮件信息
        print(code)
        message = '<h2>'+code+'<h2><br>验证码有效时间为10分钟，请你尽快完成账号登录。'
        try:
            result = send_mail(subject=subject, message='', from_email='dwy9997@163.com', recipient_list=[email, ],
                               html_message=message)  # html 因为里面含有 html标签
            print('邮箱发送成功' + email, result)
        except Exception as e:
            print(e)
            re_json = {
                'code': 500,
                'msg': "登录验证码发送失败",
                'action': "登录验证码",
                're_code': 'Get',
                'send_time': now_time(),
                'data': '',
                'path': '/user/login/code',
            }
            return JsonResponse(re_json)
        re_json = {
            'code': 200,
            'msg': "已发送登录验证码",
            'action': "登录验证码",
            're_code': 'Get',
            'send_time': now_time(),
            'data': '',
            'path': '/user/login/code',
        }
        return JsonResponse(re_json)

class UserLogoutApi(View):
    def get(self,request):
        if 'username' in request.session:
            del request.session['username']
        if 'uid' in request.session:
            del request.session['uid']
        if 'name' in request.session:
            del request.session['name']
        if 'email' in request.session:
            del request.session['email']
        re_json = {
            'code':200,
            'msg':"成功注销用户!",
            'redirect':'/login',
        }
        resp = JsonResponse(re_json)
        if 'uid' in request.COOKIES:
            resp.delete_cookie('uid')
        return resp

@method_decorator(csrf_exempt,name='dispatch')
class ApiMain(View):
    def get(self,request):
        api_access_record(request,16)

        sort = request.GET.get("sort") #排序类型 逆 正
        sort_key = request.GET.get("sort_key") #排序内容 #点赞、收藏、调用、点踩、时间

        page = int(request.GET.get("page",1))
        per_page = int(request.GET.get("per_page",5))

        tag = request.GET.get("tag")
        tags = request.GET.get("tags")

        api_uid = request.GET.get("api_uid")
        api_title = request.GET.get('api_title')
        if sort_key==True and sort_key not in ['like','dislike','favorites','access','updated_time']:
            re_json = {
                "code":202,
                "msg":f"无效的查询集，请符合['like','dislike','favorites','access','updated_time']其中一个。",
                're_code':"Get",
                'data':'',
                'path':'/api',
            }
            return JsonResponse(re_json)
        elif sort==True and  sort not in ['0','1']:
            re_json = {
                "code":202,
                "msg":f"无效的sort参数，请符合['1','0']其中一个。",
                're_code':"Get",
                'data':'',
                'path':'/api',
            }
            return JsonResponse(re_json)
        elif per_page >40:
            re_json = {
                "code":202,
                "msg":f"per_page超出范围，最大为:40",
                're_code':"Get",
                'data':'',
                'path':'/api',
            }
            return JsonResponse(re_json)
        elif page < 1:
            page = 1

        elif tag and tags:
            re_json = {
                "code": 202,
                "msg": "tag 和 tags不能共同存在！",
                're_code': "Get",
                'data': '',
                'path': '/api',
            }
            return JsonResponse(re_json)
        elif api_uid:
            #当存在id时，只会根据id返回信息！其他参数不予理会
            try:
                obj_data = Api.objects.get(id=api_uid)
                list_data = []
                # 多对多关系取值
                tag_names = obj_data.tags.values_list('name', flat=True)
                # 将name属性放入到一个列表中
                tag_list = list(tag_names)

                # 获取点赞数、收藏数
                likes = Api_info.objects.get(api=obj_data).likes
                dislike = Api_info.objects.get(api=obj_data).dislike
                favorites = Api_info.objects.get(api=obj_data).favorites
                num = Api_access.objects.get(api=obj_data).num

                json_data = {
                    'id': obj_data.id,
                    'title': obj_data.title,
                    'photo': obj_data.photo.name,
                    'details': obj_data.details,
                    'tags': tag_list,
                    'request_mode': obj_data.request_mode,
                    'data_type': obj_data.data_type,
                    'user': obj_data.user.username,
                    'likes': likes,
                    'dislike': dislike,
                    'favorites': favorites,
                    'num': num,
                }
                list_data.append(json_data)

                return get_re_json(202, f"正常返回数据", '根据id搜索', 'get', list_data, '/api')
            except:
                re_json = {
                    "code": 500,
                    "msg": "当前api_uid不存在，请自行修改重试",
                    're_code': "Get",
                    'data': '',
                    'path': '/api',
                }
                return JsonResponse(re_json)
        elif api_title:
            mysql_get = [] #查询到的数据对象
            list_data = [] #已处理的数据，用于回传
            info ={}
            try:
                # 计算这些数据的相关信息
                mysql_get = Api.objects.filter(active=True,title__icontains=api_title)
                AllApi = mysql_get.count()
                max_page = int(AllApi / int(per_page)) + 1
                if page > max_page:
                    return get_re_json(202, f"page页数超出范围！当前最大页数:{str(max_page)}", '', 'get', '', '/api')

                info = {
                    'page': page,
                    'per_page': per_page,
                    'max_page': max_page,
                    'total': AllApi,
                }

                for obj_data in mysql_get:
                    # 多对多关系取值
                    tag_names = obj_data.tags.values_list('name', flat=True)
                    # 将name属性放入到一个列表中
                    tag_list = list(tag_names)

                    # 取多个值的范例
                    # tag_data = obj_data.tags.values_list('name', 'age')
                    # dict_list = [dict(zip(('name', 'age'), data)) for data in tag_data]

                    # 获取点赞数、收藏数
                    likes = Api_info.objects.get(api=obj_data).likes
                    dislike = Api_info.objects.get(api=obj_data).dislike
                    favorites = Api_info.objects.get(api=obj_data).favorites
                    num = Api_access.objects.get(api=obj_data).num

                    json_data = {
                        'id': obj_data.id,
                        'title': obj_data.title,
                        'photo': obj_data.photo.name,
                        'details': obj_data.details,
                        'tags': tag_list,
                        'request_mode': obj_data.request_mode,
                        'data_type': obj_data.data_type,
                        'user': obj_data.user.username,
                        'likes': likes,
                        'dislike': dislike,
                        'favorites': favorites,
                        'num': num,
                    }
                    list_data.append(json_data)

                all_data_json = {
                    "api_data": list_data,
                    'api_info': info
                }

                return get_re_json(200, '成功返回数据', '根据标题返回数据', 'get', all_data_json, '/api')
            except:
                return get_re_json(500, "当前api_title不存在，请自行修改重试", '', 'get', '', '/api')

        if not tag and not tags:
            #不通过tag查询数据
            mysql_get = [] #查询到的数据对象
            list_data = [] #已处理的数据，用于回传
            info ={}
            if sort_key=="updated_time":
                #按照时间排序
                if sort =='0':
                    mysql_get = get_sort_data(sort_key,'Api',reverse=False)[per_page*(page-1):per_page*page]
                else:
                    mysql_get = get_sort_data(sort_key,'Api',reverse=True)[per_page*(page-1):per_page*page]


            elif sort_key=='like':
                # 根据like升序排序输出
                if sort =='1':

                    mysql_get = Api.objects.annotate(like_count=F('apiinfo__likes')).order_by('like_count')[per_page*(page-1):per_page*page]
                elif sort == '0':
                    mysql_get = Api.objects.annotate(like_count=F('apiinfo__likes')).order_by('-like_count')[per_page*(page-1):per_page*page]
                else:
                    mysql_get = Api.objects.annotate(like_count=F('apiinfo__likes'))[per_page*(page-1):per_page*page]

            elif sort_key=='dislike':
                # 根据like升序排序输出
                if sort =='1':
                    mysql_get = Api.objects.annotate(dislike_count=F('apiinfo__dislike')).order_by('dislike_count')[per_page*(page-1):per_page*page]
                elif sort == '0':
                    mysql_get = Api.objects.annotate(dislike_count=F('apiinfo__dislike')).order_by('-dislike_count')[per_page*(page-1):per_page*page]
                else:
                    mysql_get = Api.objects.annotate(dislike_count=F('apiinfo__dislike'))[per_page*(page-1):per_page*page]

            elif sort_key=='favorites':
                # 根据like升序排序输出
                if sort =='1':
                    mysql_get = Api.objects.annotate(favorites_count=F('apiinfo__favorites')).order_by('favorites_count')[per_page*(page-1):per_page*page]
                elif sort=='0':
                    mysql_get = Api.objects.annotate(favorites_count=F('apiinfo__favorites')).order_by('-favorites_count')[per_page*(page-1):per_page*page]
                else:
                    mysql_get = Api.objects.annotate(favorites_count=F('apiinfo__favorites'))[per_page*(page-1):per_page*page]

            elif sort_key=='access':
                if sort =='1':
                    mysql_get = Api.objects.annotate(access_count=F('apiaccess__num')).order_by('access_count')[per_page*(page-1):per_page*page]
                elif sort == '0':
                    mysql_get = Api.objects.annotate(access_count=F('apiaccess__num')).order_by('-access_count')[per_page*(page-1):per_page*page]
                else:
                    mysql_get = Api.objects.annotate(access_count=F('apiaccess__num'))[per_page*(page-1):per_page*page]

            else:
                #正常获取,无任何标签、排序
                mysql_get = Api.objects.filter(active=True)[per_page*(page-1):per_page*page]

            #计算这些数据的相关信息
            AllApi = Api.objects.filter(active=True).count()
            max_page = int(AllApi / int(per_page)) + 1
            if page > max_page:
                return get_re_json(202, f"page页数超出范围！当前最大页数:{str(max_page)}", '', 'get', '', '/api')

            info = {
                'page': page,
                'per_page': per_page,
                'max_page': max_page,
                'total': AllApi,
            }

            for obj_data in mysql_get:
                #多对多关系取值
                tag_names = obj_data.tags.values_list('name', flat=True)
                # 将name属性放入到一个列表中
                tag_list = list(tag_names)

                #取多个值的范例
                # tag_data = obj_data.tags.values_list('name', 'age')
                # dict_list = [dict(zip(('name', 'age'), data)) for data in tag_data]

                #获取点赞数、收藏数
                likes = Api_info.objects.get(api=obj_data).likes
                dislike = Api_info.objects.get(api=obj_data).dislike
                favorites = Api_info.objects.get(api=obj_data).favorites
                num = Api_access.objects.get(api=obj_data).num

                json_data = {
                    'id':obj_data.id,
                    'title':obj_data.title,
                    'photo':obj_data.photo.name,
                    'details':obj_data.details,
                    'tags':tag_list,
                    'request_mode':obj_data.request_mode,
                    'data_type':obj_data.data_type,
                    'user':obj_data.user.username,
                    'likes':likes,
                    'dislike':dislike,
                    'favorites':favorites,
                    'num':num,
                }
                list_data.append(json_data)

            all_data_json = {
                "api_data":list_data,
                'api_info':info
            }

            return get_re_json(200,'成功返回数据','无标签查询','get',all_data_json,'/api')
        elif tag or tags:
            #不通过tag查询数据
            mysql_get = [] #查询到的数据对象
            list_data = [] #已处理的数据，用于回传
            info ={}
            if tag:
                mysql_get = Api.objects.filter(tags__name=tag)[per_page*(page-1):per_page*page]

            else:
                #分别查询 如何去重
                tag_list = tags.split(',')
                query = Q()
                for tag in tag_list:
                    query |= Q(tags__name=tag)
                    #与运算符 |   同时&(不可用，因为tag不可能同时是两个)
                mysql_get = Api.objects.filter(query).distinct()[per_page*(page-1):per_page*page]
                #结果筛选 .distinct() (去重) .intersection()(并集)  [intersection_result = queryset1.intersection(queryset2)]

            # 计算这些数据的相关信息
            AllApi = mysql_get.count()
            max_page = int(AllApi / int(per_page)) + 1
            if page > max_page:
                return get_re_json(202, f"page页数超出范围！当前最大页数:{str(max_page)}", '', 'get', '', '/api')

            info = {
                'page': page,
                'per_page': per_page,
                'max_page': max_page,
                'total': AllApi,
            }
            for obj_data in mysql_get:

                # 多对多关系取值
                tag_names = obj_data.tags.values_list('name', flat=True)
                # 将name属性放入到一个列表中
                tag_list = list(tag_names)


                # 获取点赞数、收藏数
                likes = Api_info.objects.get(api=obj_data).likes
                dislike = Api_info.objects.get(api=obj_data).dislike
                favorites = Api_info.objects.get(api=obj_data).favorites
                num = Api_access.objects.get(api=obj_data).num

                json_data = {
                    'id': obj_data.id,
                    'title': obj_data.title,
                    'photo': obj_data.photo.name,
                    'details': obj_data.details,
                    'tags': tag_list,
                    'request_mode': obj_data.request_mode,
                    'data_type': obj_data.data_type,
                    'user': obj_data.user.username,
                    'likes': likes,
                    'dislike': dislike,
                    'favorites': favorites,
                    'num': num,
                }
                list_data.append(json_data)

            all_data_json = {
                "api_data": list_data,
                'api_info': info
            }

            return get_re_json(200, '成功返回数据', '根据标签返回数据', 'get', all_data_json, '/api')
        else:
            return get_re_json(50, '错误的参数', '', 'get', '', '/api')

    def post(self,request):
        uid = request.session['uid']
        tags = request.POST.get('tags')

        photo =request.FILES.get("photo")
        title = request.POST.get("title")
        details = request.POST.get("details")
        request_mode = request.POST.get("request_mode")
        data_type = request.POST.get("data_type")
        doc_url = request.POST.get("doc_url")
        or_web_url = request.POST.get("or_web_url")
        #数据验证
        data_test = AddApiValidate(photo,title,details,request_mode,data_type,doc_url,or_web_url)
        if data_test['code']==False:
            return JsonResponse(data_test)
        #写入数据库
        try:
            tags = tags.split(",")
            user = User.objects.get(id=uid)
            #处理标签
            tags = list(set(tags))
            #去重
            tag_list = []
            for tag in tags:
                try:
                    tag_id = Api_tag.objects.get(name=tag).id
                except:
                    tag_id = Api_tag.objects.create(name=tag).id
                tag_list.append(tag_id)

            create_api =Api.objects.create(doc_url=doc_url,or_web_url=or_web_url,request_mode=request_mode,data_type=data_type,title=title,details=details,photo=photo,user=user)
            #写入数据库
            tags = Api_tag.objects.filter(id__in=tag_list)  # 通过主键列表获取标签对象
            create_api.tags.add(*tags)  # 将标签对象添加到文章对象的多对多关系中
            re_json={
                'code':200,
                'msg':"成功新增Api",
                'action':"新增Api",
                're_code': 'Post',
                'send_time': now_time(),
                'data': '',
                'path': '/api',
            }
            return JsonResponse(re_json)
        except Exception as e:
            print(e)
            re_json={
                'code':500,
                'msg':"新增Api失败",
                'action':"新增Api",
                're_code': 'Post',
                'send_time': now_time(),
                'data': '',
                'path': '/api',
            }
            return JsonResponse(re_json)

    def delete(self,request):
        uid = request.GET.get("api_uid")
        uids = request.GET.get("api_uids")
        if uid and uids:
            return get_re_json(500,'uid和uids不能同时存在','删除api','delete','','/api')

        if uid:
            delete = Api.objects.get(id=uid)
            delete.active= False
            delete.save()
            return get_re_json(200,'成功删除数据','删除api','delete','','/api')

        elif uids:
            total= 0
            uid_list  = uids.split(',')
            query = Q()
            for api_uid in uid_list:
                query |= Q(id=api_uid)
                myslq_get = Api.objects.filter(query).distinct()
                for delete in myslq_get:
                    delete.active= False
                    delete.save()

                total = len(myslq_get)
            re_json = {
                'total':total,
            }
            return get_re_json(200,'成功删除数据','删除api','delete',re_json,'/api')

        else:
            return get_re_json(500, '参数不正确！', '删除api', 'delete', '', '/api')

    def put(self,request):
        pass

class ApiLikes(View):
    def get(self,request):
        api_id = request.GET.get('api_id')
        status =request.GET.get('status')
        uid = request.session['uid']
        if status!='0':
            status =1
        else:
            status=0
        try:
            get_user = User.objects.get(id=uid)
            get_api = Api.objects.get(id=api_id)
            get_likes = Api_likes.objects.filter(user=get_user,api=get_api)
            if get_likes:
                if bool(status) ==get_likes[0].status:
                    print(bool(status),get_likes[0].status)
                    re_json = {
                        'code': 200,
                        'msg': '请不要重复点赞或点踩',
                        'action': "点赞",
                        're_code': 'Get',
                        'path': '/api/likes',
                    }
                    return JsonResponse(re_json)
                else:
                    get_likes[0].status =bool(status)
                    get_likes[0].save()
                    msg ='成功点踩'
                    if bool(status):
                        msg = '成功点赞'
                    re_json = {
                        'code': 200,
                        'msg': msg,
                        'action': "点赞",
                        're_code': 'Get',
                        'path': '/api/likes',
                    }
                    return JsonResponse(re_json)
            create_like = Api_likes.objects.create(user=get_user,api=get_api,status=bool(status))
            re_json = {
                'code':200,
                'msg':'成功点赞',
                'action':"点赞",
                're_code':'Get',
                'path':'/api/likes',
            }
            return  JsonResponse(re_json)
        except Exception as e:
            print(e)
            re_json = {
                'code':500,
                'msg':'点赞失败，请联系管理员',
                'action':"点赞",
                're_code':'Get',
                'path':'/api/likes',
            }
            return  JsonResponse(re_json)

class ApiFavorites(View):
    def get(self,request):
        api_id = request.GET.get('api_id')
        status =request.GET.get('status')
        uid = request.session['uid']
        if status!='0':
            status =1
        else:
            status=0
        try:
            get_user = User.objects.get(id=uid)
            get_api = Api.objects.get(id=api_id)
            get_favorites = Api_favorites.objects.filter(user=get_user,api=get_api)
            if get_favorites:
                if bool(status) ==get_favorites[0].status:
                    re_json = {
                        'code': 200,
                        'msg': '请不要重复点击收藏和取消收藏',
                        'action': "收藏",
                        're_code': 'Get',
                        'path': '/api/favorites',
                    }
                    return JsonResponse(re_json)
                else:
                    get_favorites[0].status =bool(status)
                    get_favorites[0].save()
                    msg ='成功取消收藏'
                    if bool(status):
                        msg = '成功收藏'
                    re_json = {
                        'code': 200,
                        'msg': msg,
                        'action': "收藏",
                        're_code': 'Get',
                        'path': '/api/favorites',
                    }
                    return JsonResponse(re_json)
            create_favorites = Api_favorites.objects.create(user=get_user,api=get_api,status=bool(status))
            re_json = {
                'code':200,
                'msg':'成功收藏',
                'action':"收藏",
                're_code':'Get',
                'path':'/api/favorites',
            }
            return  JsonResponse(re_json)
        except Exception as e:
            print(e)
            re_json = {
                'code':500,
                'msg':'收藏失败，请联系管理员',
                'action':"点赞",
                're_code':'Get',
                'path':'/api/favorites',
            }
            return  JsonResponse(re_json)

def validate_user(name, password,photo,username,email):
    try:
        validate_email(email)
    except:
        re_json = {
            'code': False,
            'msg': '邮箱格式不正确'
        }
        return re_json
    try:
        test = User.objects.get(username=username)
        re_json = {
            'code': False,
            'msg': '已存在相同账号，请你修改账号重试。'
        }
        return re_json
    except:
        pass

    img_test_re = img_test(photo, 1980,200,1080, 200,['jpg', 'jpeg', 'png', 'bmp'])
    if img_test_re['code']==False:
        print(img_test_re)
        return img_test_re
    try:
        pattern = re.compile(r'^[\u4e00-\u9fa5\w]{2,28}$')
        # 对字符串进行匹配操作
        match = pattern.match(name)
        if match.group()==False:
            re_json = {
                'code': False,
                'msg': '用户名不可用，请确保其字符准确,只能包括中文、字母、数字、下划线，且位数在2-28之间。'
            }
            return re_json
    except:
        re_json = {
            'code': False,
            'msg': '用户名不可用，请确保其字符准确,只能包括中文、字母、数字、下划线，且位数在2-28之间。'
        }
        return re_json

    try:
        # 验证密码是否符合规定
        password_validation.validate_password(password)
    except password_validation.ValidationError as e:
        # 密码不合法
        re_json = {
            'code': False,
            'msg': e
        }
        return re_json

    re_json = {
        'code': True,
    }
    return re_json

def AddApiValidate(photo,title,details,request_mode,data_type,doc_url,or_web_url):
    #Api新增 验证函数/字符串格式化

    img_test_re = img_test(photo, 1980, 200, 1080, 200, ['jpg', 'jpeg', 'png', 'bmp'])
    if img_test_re['code'] == False:
        print(img_test_re)
        return img_test_re


    if 30<len(title) or len(title)<2:
        re_json = {
            'code': False,
            'msg': "标题位数2-30"
        }
        return re_json

    if 300<len(details) or len(details)<10:
        re_json = {
            'code': False,
            'msg': "详情不可为空，位数10-300"
        }
        return re_json
    if 30<len(title) or len(title)<2:
        re_json = {
            'code': False,
            'msg': "标题位数2-30"
        }
        return re_json
    url_pattern = re.compile(r'^https?://[\w\-]+(\.[\w\-]+)+[\w\-\._~:/\?#\[\]@!\$&\'\(\)*\+,;=]*$')
    # 判断URL是否为合法的格式
    if or_web_url:
        if url_pattern.match(or_web_url) ==False:
            re_json = {
                'code': False,
                'msg': "原文地址填写错误，请更改。"
            }
            return re_json
    if doc_url:
        if url_pattern.match(doc_url) ==False:
            re_json = {
                'code': False,
                'msg': "文档地址填写错误，请更改。"
            }
            return re_json


    if request_mode.lower() not in ['get','post','put','delete','patch','head','options']:
        re_json = {
            'code': False,
            'msg': "请求类型不正确，只能在其中选择一种['get','post','put','delete','patch','head','options']。"
        }
        return re_json

    if data_type.lower() not in ['json','html','xml','picture','str','video']:
        re_json = {
            'code': False,
            'msg': "返回数据类型不正确，只能在其中选择一种['json','html','xml','picture','str','video']。"
        }
        return re_json

    re_json = {
        'code': True,
        'msg': "通过验证"
    }
    return re_json

def img_test(photo,max_size_w,min_size_w,max_size_h,min_size_h,code):
    # 验证图片的大小、类型、尺寸

    # 通过 Django 内置的 FileExtensionValidator 验证传入的文件类型是否是符合规定的图片类型
    try:
        validator = FileExtensionValidator(allowed_extensions=code)
        validator(photo)
    except:
        re_json = {
            'code': False,
            'msg': f'请上传 {str(code)} 格式的图片文件！'
        }
        return re_json
    # 打开图片并获取尺寸
    try:
        with Image.open(photo) as im:
            width, height = im.size
            if width < min_size_w or width>max_size_w or height< min_size_h or height> max_size_h:
                re_json = {
                    'code': False,
                    'msg': f'请保存图片尺寸为:{min_size_w}x{min_size_h}-{max_size_w}x{max_size_h},(长x宽)'
                }
                return re_json
    except:
        re_json = {
            'code': False,
            'msg': '该图片缺失,请确保图片能正常打开！'
        }
        return re_json

    re_json = {
        'code': True,
        'msg': '图片验证通过！'
    }
    return re_json


def get_sort_data(field_name,model_name,reverse=False):
    #返回已排序好的对象
    if reverse:
        field_name = f"-{field_name}"  # 如果要降序排序，添加负号
    model_class = apps.get_model('main', model_name)
    return model_class.objects.order_by(field_name)


def get_re_json(code,msg,action,re_code,data,path):
    re_json = {
        'code':code,
        "msg": msg,
        'action':action,
        're_code': re_code,
        'data': data,
        'path': path,
        'now_time':now_time()
    }
    re_json_respon = JsonResponse(re_json, safe=False, json_dumps_params={'ensure_ascii': False})
    return re_json_respon

def api_access_record(request,api_id):
    try:
        uid = request.session['uid']
        user = User.objects.get(id=uid)
        api = Api.objects.get(id=api_id)
        add_record = Api_access_record.objects.create(api=api,user=user)
    except Exception as e:
        print(e)

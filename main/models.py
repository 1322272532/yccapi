import datetime
import random

from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver


class User(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField('姓名',max_length=30,null=True)
    username = models.CharField('账户名',max_length=30,unique=True)
    password = models.CharField('密码',max_length=200)
    email = models.EmailField(default='',unique=True)
    power = models.CharField('权限等级',max_length=3,default='0')
    photo = models.FileField('用户头像',upload_to='user_photo',default='user_photo/1.jpg')
    active = models.BooleanField('是否活跃',default=True)
    create_time = models.DateTimeField('创建时间', auto_now_add=True)  # 自动添加
    updated_time = models.DateTimeField('更新时间', auto_now=True)
    class Meta:
        db_table = 'user'
        verbose_name_plural = '用户'

    def __str__(self):
        return self.name

class Api(models.Model):
    mode=[
        ('get', 'get'),
        ('post', 'post'),
        ('put','put'),
        ('delete','delete'),
        ('patch','patch'),
        ('head','head'),
        ('options','options')
    ]
    data_type=[
        ('json','json'),
        ('xml', 'xml'),
        ('html', 'html'),
        ('picture', 'picture'),
        ('video', 'video'),
        ('str', 'str'),
    ]
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User,on_delete=models.CASCADE,default='')
    photo = models.FileField('Api封面',upload_to='api_photo',default='api_photo/1.jpg')
    title =models.CharField('接口名称',max_length=255,default='')
    details = models.TextField('详情')
    active = models.BooleanField(default=True)
    tags = models.ManyToManyField('Api_tag', blank=True)
    request_mode = models.CharField('访问类型',max_length=20,choices=mode,default=1)
    data_type = models.CharField('数据类型',max_length=20,choices=data_type,default=1)
    doc_url = models.CharField('文档地址',max_length=100,default='',null=True)
    or_web_url = models.CharField('来源地址',max_length=100,default='',null=True)
    create_time = models.DateTimeField('创建时间', auto_now_add=True)  # 自动添加
    updated_time = models.DateTimeField('更新时间', auto_now=True)
    class Meta:
        db_table = 'api'
        verbose_name_plural = 'API列表'

    def __str__(self):
        return self.title

class Api_access_record(models.Model):
    id = models.AutoField(primary_key=True)
    api = models.ForeignKey(Api,on_delete=models.CASCADE)
    user = models.ForeignKey(User,on_delete=models.CASCADE,default='')
    create_time = models.DateTimeField('创建时间', auto_now_add=True)  # 自动添加
    updated_time = models.DateTimeField('更新时间', auto_now=True)
    class Meta:
        db_table = 'api_access_record'
        verbose_name_plural = 'API访问'

    def __str__(self):
        return self.id


class Api_access(models.Model):
    id = models.AutoField(primary_key=True)
    api = models.OneToOneField(Api,on_delete=models.CASCADE,related_name='apiaccess')
    num = models.PositiveIntegerField(default=0)
    create_time = models.DateTimeField('创建时间', auto_now_add=True)  # 自动添加
    updated_time = models.DateTimeField('更新时间', auto_now=True)
    class Meta:
        db_table = 'api_access'
        verbose_name_plural = 'API访问统计表'

    def __str__(self):
        return self.num

class Api_tag(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField('标签',max_length=10,default='')
    create_time = models.DateTimeField('创建时间', auto_now_add=True)  # 自动添加
    updated_time = models.DateTimeField('更新时间', auto_now=True)
    class Meta:
        db_table = 'api_tag'
        verbose_name_plural = 'API标签'

    def __str__(self):
        return self.name

class Api_info(models.Model):
    id = models.AutoField(primary_key=True)
    api = models.OneToOneField(Api,on_delete=models.CASCADE,related_name='apiinfo')
    #可以在Api中 利用apiinfo获取此表字段数据
    likes = models.PositiveIntegerField(default=0)
    dislike = models.PositiveIntegerField(default=0)
    favorites = models.PositiveIntegerField(default=0)
    create_time = models.DateTimeField('创建时间', auto_now_add=True)  # 自动添加
    updated_time = models.DateTimeField('更新时间', auto_now=True)
    class Meta:
        db_table = 'api_info'
        verbose_name_plural = 'API信息'
    def __str__(self):
        return self.id

class Api_likes(models.Model):
    id = models.AutoField(primary_key=True)
    api = models.ForeignKey(Api, on_delete=models.CASCADE)
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    status = models.BooleanField('点赞状态',default=0)
    create_time = models.DateTimeField('创建时间', auto_now_add=True)  # 自动添加
    updated_time = models.DateTimeField('更新时间', auto_now=True)
    class Meta:
        db_table = 'api_likes'
        verbose_name_plural = 'API点赞'
        constraints = [
            models.UniqueConstraint(fields=['api', 'user'], name='unique_like'),
        ]
    def __str__(self):
        return self.id


class Api_favorites(models.Model):
    id = models.AutoField(primary_key=True)
    api = models.ForeignKey(Api, on_delete=models.CASCADE)
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    status = models.BooleanField('收藏状态',default=0)
    create_time = models.DateTimeField('创建时间', auto_now_add=True)  # 自动添加
    updated_time = models.DateTimeField('更新时间', auto_now=True)
    class Meta:
        db_table = 'api_favorites'
        verbose_name_plural = 'API收藏'
        constraints = [
            models.UniqueConstraint(fields=['api', 'user'], name='unique_favorite'),
        ]
    def __str__(self):
        return self.id

#当其Api创建时，自动创建info表 access表
@receiver(post_save, sender=Api)
def create_api_info(sender, instance, created, **kwargs):
    """
    创建 API 对象时，创建对应的 Api_info 对象
    """
    if created:
        Api_info.objects.create(api=instance,likes=0,favorites=0,dislike=0)
        Api_access.objects.create(api=instance,num=0)

#自动修改 info的likes 和dislikes数量
@receiver(post_save, sender=Api_likes)
def update_api_like(sender, instance, **kwargs):
    api_id = instance.api.id  # 获取特定 api_id
    api = Api_info.objects.get(api=api_id)
    api.likes = a = Api_likes.objects.filter(api=api_id, status=True).count()
    api.dislike = b = Api_likes.objects.filter(api=api_id,status=False).count()
    api.save()


# 自动修改 info的favorites数量
@receiver(post_save, sender=Api_favorites)
def update_api_like(sender, instance, **kwargs):
    api_id = instance.api.id  # 获取特定 api_id
    api = Api_info.objects.get(api=api_id)
    api.favorites = Api_favorites.objects.filter(api=api_id, status=True).count()
    api.save()


# 自动修改 access的num数量
@receiver(post_save, sender=Api_access_record)
def update_api_like(sender, instance, **kwargs):
    api_id = instance.api.id  # 获取特定 api_id
    api = Api_access.objects.get(api=api_id)
    api.num = Api_access_record.objects.filter(api=api_id).count()
    api.save()

class Api_visit_param(models.Model):
    data_type_c=[
        ('number','number'),
        ('str', 'str'),
        ('boolean','boolean'),
    ]
    id = models.AutoField(primary_key=True)
    api = models.ForeignKey(Api, on_delete=models.CASCADE)
    title = models.CharField('参数昵称',max_length=50,default='')
    data_type = models.CharField('数据类型',choices=data_type_c,max_length=20,default='number')
    is_null = models.BooleanField('是否允许为空',default=False)
    details = models.TextField('详情',default='')
    create_time = models.DateTimeField('创建时间', auto_now_add=True)  # 自动添加
    updated_time = models.DateTimeField('更新时间', auto_now=True)
    class Meta:
        db_table = 'api_visit_param'
        verbose_name_plural = 'API访问参数说明'

    def __str__(self):
        return self.title


class Api_respon_param(models.Model):
    mode=[
        ('get', 'get'),
        ('post', 'post'),
        ('put','put'),
        ('delete','delete'),
        ('patch','patch'),
        ('head','head'),
        ('options','options')
    ]
    id = models.AutoField(primary_key=True)
    api = models.ForeignKey(Api, on_delete=models.CASCADE)
    request_eg = models.TextField('请求实例',default='')
    respon_eg = models.TextField('返回实例',default='')
    request_mode = models.CharField('请求方式',default='get',max_length=20)
    create_time = models.DateTimeField('创建时间', auto_now_add=True)  # 自动添加
    updated_time = models.DateTimeField('更新时间', auto_now=True)
    class Meta:
        db_table = 'api_respon_param'
        verbose_name_plural = 'API返回实例'

    def __str__(self):
        return self.id


class User_access_record(models.Model):
    id = models.AutoField(primary_key=True)
    api = models.ForeignKey(Api, on_delete=models.CASCADE)
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    create_time = models.DateTimeField('创建时间', auto_now_add=True)  # 自动添加
    updated_time = models.DateTimeField('更新时间', auto_now=True)
    class Meta:
        db_table = 'user_access_record'
        verbose_name_plural = '用户浏览记录'
        constraints = [
            models.UniqueConstraint(fields=['api', 'user'], name='unique_access_record'),
        ]
    def __str__(self):
        return self.id

class Comment(models.Model):
    id = models.AutoField(primary_key=True)
    content = models.TextField()
    create_time = models.DateTimeField('创建时间', auto_now_add=True)  # 自动添加
    updated_time = models.DateTimeField('更新时间', auto_now=True)
    reply_to = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='replies')
    api = models.ForeignKey(Api, on_delete=models.CASCADE)
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    class Meta:
        db_table = 'Comment'
        verbose_name_plural = 'Api评论'
    def __str__(self):
        return self.content




class User_register_code(models.Model):
    id = models.AutoField(primary_key=True)
    username =models.CharField('账号',max_length=200,default='',unique=True)
    code =models.CharField('验证码',max_length=6,default='')
    email = models.EmailField(default='',unique=True)
    create_time = models.DateTimeField('创建时间', auto_now_add=True)  # 自动添加
    expire_time = models.DateTimeField('过期时间')

    class Meta:
        db_table = 'User_register_code'
        verbose_name_plural = '注册验证码'
    def __str__(self):
        return self.code

    def save(self,*args,**kwargs):
        self.expire_time = datetime.datetime.now() +datetime.timedelta(minutes=10)
        self.code = ''.join(random.sample('1234567890',6))
        super().save(*args,**kwargs)
        return datetime.datetime.now() <self.expire_time

class User_login_code(models.Model):
    id = models.AutoField(primary_key=True)
    username =models.CharField('账号',max_length=200,default='',unique=True)
    code =models.CharField('验证码',max_length=6,default='')
    email = models.EmailField(default='',unique=True)
    create_time = models.DateTimeField('创建时间', auto_now_add=True)  # 自动添加
    expire_time = models.DateTimeField('过期时间')

    class Meta:
        db_table = 'User_login_code'
        verbose_name_plural = '登录验证码'
    def __str__(self):
        return self.code

    def save(self,*args,**kwargs):
        self.expire_time = datetime.datetime.now() +datetime.timedelta(minutes=10)
        self.code = ''.join(random.sample('1234567890',6))
        super().save(*args,**kwargs)
        return datetime.datetime.now() <self.expire_time
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import authenticate
from rest_framework import serializers
from rest_framework.authtoken.models import Token
from user.models import User

class UserSerializer(serializers.Serializer):
    # 序列化器类的第一部分定义了序列化/反序列化的字段,与Form相似
    id = serializers.IntegerField(read_only=True)
    username = serializers.CharField(max_length=20, min_length=3)
    password = serializers.CharField(max_length=16, min_length=8, style={'input_type': 'password'})
    email = serializers.EmailField()
    is_active = serializers.BooleanField(default=False)

    def create(self, validated_data):
        # 验证给定数据，创建并返回一个新的User实例
        # print(validated_data)
        # username = validated_data.get('username')
        # if(User.objects.filter(username=username).exists()):
        #     raise Response({"username": "用户名已存在"}, status=status.HTTP_400_BAD_REQUEST)
        # else:
        #     user = User.objects.create_user(**validated_data)
        #     return user
        return User.objects.create_user(**validated_data)

    def update(self, instance, validated_data):
        # 验证给定数据，更新并返回一个已存在User实例
        print(validated_data.get('is_active'))
        instance.username = validated_data.get('username', instance.username)
        instance.set_password(validated_data.get('password', instance.password))
        instance.email = validated_data.get('email', instance.email)
        instance.is_active = validated_data.get('is_active', instance.is_active)
        instance.save()
        return instance

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=20, min_length=3)
    password = serializers.CharField(max_length=16, min_length=8, style={'input_type': 'password'})

    # def create(self, validated_data):
    #     username = validated_data.get('username')
    #     password = validated_data.get('password')
    #     try:
    #         user = authenticate(username=username, password=password)
    #     except ObjectDoesNotExist:
    #         return ''
    #     token = Token.objects.update_or_create(user)
    #     return token
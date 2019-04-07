import hashlib
import time

from django.core.exceptions import ObjectDoesNotExist
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed
from user.serializers import UserSerializer, LoginSerializer
from user.models import User

def md5(user):
    ctime = str(time.time())
    m = hashlib.md5(bytes(user, encoding='utf-8'))
    m.update(bytes(ctime, encoding='utf-8'))
    return m.hexdigest()

class RegisterView(APIView):
    '''用户注册'''

    def get(self, request, format=None):
        pass

    def post(self, request, format=None):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.data.get('username')
            if (User.objects.filter(username=username).exists()):
                return Response({"username": ["用户名已存在"]}, status=status.HTTP_400_BAD_REQUEST)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):

    def get(self, request, format=None):
        pass

    def post(self, request, format=None):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.data.get('username')
            password = serializer.data.get('password')
            try:
                user = User.objects.get(username=username)
            except ObjectDoesNotExist:
                return Response({"message": "用户名不存在"}, status=status.HTTP_401_UNAUTHORIZED)
            if user.check_password(password):
                token = Token.objects.filter(user_id=user.pk).first()
                print(token)
                if token:
                    token.delete()
                content = {}
                token = md5(username)
                Token.objects.update_or_create(defaults={'key': token}, user_id=user.pk)
                content['username'] = user.username
                content['email'] = user.email
                content['token'] = token

                return Response(content, status=status.HTTP_200_OK)
        return Response({"message": "密码不正确"}, status=status.HTTP_401_UNAUTHORIZED)

    def delete(self, request):
        token = request.data.get('token')
        try:
            Token.objects.get(key=token).delete()
            return Response({'logout': 'OK'}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({'message': '用户未登录'}, status=status.HTTP_400_BAD_REQUEST)


class Authtication(object):
    def authenticate(self, request):
        token = request.data.get('token')
        token_obj = Token.objects.filter(key=token).first()
        if not token_obj:
            raise AuthenticationFailed('用户认证失败')
        user = User.objects.get(pk=token_obj.user_id)
        return (user, token_obj)
    def authenticate_header(self, request):
        pass

class UserDetailView(APIView):

    authentication_classes = [Authtication, ]

    def get(self, request, format=None):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data)

    def put(self, request, format=None):
        user = request.user
        serializer = UserSerializer(user, request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


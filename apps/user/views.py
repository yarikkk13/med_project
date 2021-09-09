import os

import jwt
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse

from rest_framework import status
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateAPIView, UpdateAPIView, GenericAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken

from .serializers import (  # UserStartChangePasswordSerializer,
    UserChangePasswordSerializer,
    UserSerializer,
    UserUpdateSerializer,
)
from core.services.mail_service import MailService

UserModel: User = get_user_model()


class UserListCreateView(ListCreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = UserSerializer
    queryset = UserModel.objects.all().filter(deleted=False)


class UserRetrieveUpdateSoftDeleteView(RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserUpdateSerializer
    queryset = UserModel.objects.all()

    def delete(self, *args, **kwargs):
        pk = kwargs.get('pk')
        try:
            data = UserModel.objects.get(pk=pk)
        # except Exception as e:
        except UserModel.DoesNotExist:
            return Response('Not Found', status.HTTP_404_NOT_FOUND)
        data.is_active = False
        data.deleted = True
        data.save()
        return Response('deleted', status.HTTP_204_NO_CONTENT)


class UserChangePasswordView(UpdateAPIView):
    serializer_class = UserChangePasswordSerializer
    permission_classes = (IsAuthenticated,)
    queryset = UserModel.objects.all()

    def perform_update(self, serializer):
        instance = serializer.save()
        instance.set_password(instance.password)
        instance.save()


class UserActivatorView(APIView):
    permission_classes = (AllowAny,)

    def patch(self, *args, **kwargs):
        pk = kwargs.get('pk')
        try:
            data = UserModel.objects.get(pk=pk)
        except UserModel.DoesNotExist:
            return Response('Not Found', status.HTTP_404_NOT_FOUND)
        data.is_active = True
        data.save()
        return Response('activated', status.HTTP_202_ACCEPTED)


# start changing View
class UserStartChangePasswordView(TokenObtainPairView):
    permission_classes = (AllowAny,)
    # serializer_class = UserStartChangePasswordSerializer


class Registering(GenericAPIView):
    serializer_class = UserSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = UserModel.objects.get(email=user_data['email'])

        token = RefreshToken.for_user(user).access_token

        # current_site = get_current_site(request).domain
        # relative_link = reverse('email-verify')
        # absurl = 'http://'+current_site+relative_link+"?token="+str(token)
        absurl = 'http://localhost:8000/api/v1/auth/verify/?token=' + str(token)
        email_body = 'Hi ' + user.name + 'Use link below to verify email \n' + absurl
        data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Verify your email'}

        MailService.verify_email(data)

        return Response(user_data, status=status.HTTP_201_CREATED)


class VerifyEmail(GenericAPIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        token = request.GET.get('token')
        try:
            access_token = AccessToken(token)
            user_id = access_token.payload.get('user_id')
            # payload = jwt.decode(token, os.environ.get("SECRET_KEY"))
            user = UserModel.objects.get(id=user_id)
            if not user.is_active:
                user.is_active = True
                user.save()
            return Response({'email': 'Successfully activated'}, status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Activation expired'}, status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response({'error': 'invalid token'}, status.HTTP_400_BAD_REQUEST)


class ResetPassword(GenericAPIView):
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        print(request.data)
        email = request.data['email']
        name = request.data['name']
        print(email)
        try:
            user = UserModel.objects.get(email=email)
        except UserModel.DoesNotExist:
            return Response('Not Found', status.HTTP_404_NOT_FOUND)

        token = RefreshToken.for_user(user).access_token

        absurl = 'http://localhost:8000/api/v1/auth/reset/?token=' + str(token)
        email_body = 'Hi ' + name + 'Use link below to reset password \n' + absurl
        data = {'email_body': email_body, 'to_email': email, 'email_subject': 'Reset password'}

        MailService.reset_password(data)

        return Response('email send', status=status.HTTP_200_OK)


class ChangePass(GenericAPIView):
    permission_classes = (AllowAny,)

    def get(self, request, *args, **kwargs):
        print(request.data)

        token = request.GET.get('token')
        password = request.GET.get('password')
        print(password)
        try:
            access_token = AccessToken(token)
            user_id = access_token.payload.get('user_id')
            # payload = jwt.decode(token, os.environ.get("SECRET_KEY"))
            user = UserModel.objects.get(id=user_id)
            print(user.password)
            if not user.is_active:
                user.is_active = True
                user.save()
            return Response({'email': 'Successfully activated'}, status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Activation expired'}, status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response({'error': 'invalid token'}, status.HTTP_400_BAD_REQUEST)
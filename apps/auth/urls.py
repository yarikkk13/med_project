from django.urls import path

from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from apps.user.views import Registering, VerifyEmail, ResetPassword, ChangePass

urlpatterns = [
    path('', TokenObtainPairView.as_view(), name='auth_login'),
    path('/refresh', TokenRefreshView.as_view(), name='auth_refresh'),
    path('/register', Registering.as_view(), name='register_acc_with_sending_email_activation'),
    path('/verify/', VerifyEmail.as_view(), name='verify_email'),
    path('/reset', ResetPassword.as_view(), name='reset_password'),
    path('/change_pass', ChangePass.as_view(), name='reset_password')
]

from django.urls import path
from .views import *
from django.contrib.auth.views import PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView

urlpatterns = [
    path('', IndexView.as_view(), name ='index'),
    path('register', RegisterView.as_view(), name ='register'),
    path('verify_email/<str:uidb64>/<str:token>/', VerifyEmailView.as_view(), name='verify_email'),
    path('login', LoginView.as_view(), name ='login'),
    path('logout', LogoutView, name='logout'),
    path('home', HomeView, name ='home'),
    path('payamount', PayamountView, name ='payamount'),
    path('payment', PaymentView, name ='payment'),
    path('paymentcallbackhandler/', paymentcallbackhandler, name='paymentcallbackhandler'),


    path('services', ServicesView, name ='services'),
    path('reverify_email', RegenerateVerificationEmailView.as_view(), name='reverify_email'),
    path('api/spam_classifier', SpamClassifierApi.as_view(), name ='api_sc'),    
    
    
    path('password_reset/', CustomPasswordResetView.as_view(template_name='reset/password_reset.html'), name='password_reset'),
    path('password_reset/done/', PasswordResetDoneView.as_view(template_name='reset/password_reset_done.html'), name='password_reset_done'),
    path('password-reset-confirm/<str:uidb64>/<str:token>/', PasswordResetConfirmView.as_view(template_name='reset/password_reset_confirm.html'), name='password_reset_confirm'),
    path('password-reset-complete/', PasswordResetCompleteView.as_view(template_name='reset/password_reset_complete.html'), name='password_reset_complete'),

]
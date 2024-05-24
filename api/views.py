import os
from django.views import View
from .forms import UserInputForm, RegistrationForm, LoginForm, RegenerateResetEmailForm, ResetPasswordForm
from .Classification import classify_spam
from django.contrib.auth import authenticate, login, logout
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .models import MyUser
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils import timezone
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.urls import reverse
from django.contrib import messages
from .serializers import SpamClassifierSerializer
from django_ratelimit.decorators import ratelimit
from datetime import timedelta
from django.core.cache import cache
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.views import PasswordResetView
from .models import FileModel
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import hashlib
from api import forms
import razorpay
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseBadRequest
from django.http import JsonResponse


import logging
logger = logging.getLogger('app')

RAZOR_KEY_ID = os.environ.get('RAZOR_KEY_ID')
RAZOR_KEY_SECRET = os.environ.get('RAZOR_KEY_SECRET')
razorpay_client = razorpay.Client(auth=(RAZOR_KEY_ID, RAZOR_KEY_SECRET))


def get_tokens_for_user_api(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh' : str(refresh),
        'access' : str(refresh.access_token), 
    }


def generate_verification_link(request, email, verification_type):
    user = MyUser.objects.filter(email=email).first()
    if not user:
        raise forms.ValidationError("This email is not associated with any user.")

    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    current_site = get_current_site(request)
    domain = current_site.domain

    if verification_type == 'password_reset':
        verify_url = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
    else :
        verify_url = reverse('verify_email', kwargs={'uidb64': uid, 'token': token})
    
    expiry_time = timezone.now() + timedelta(minutes=2)
    timestamp = int(expiry_time.timestamp())
    request.session['verification_timestamp'] = timestamp     # Store timestamp in the user's session

    verify_url = f'http://{domain}{verify_url}'
    subject = 'Verify your Email'
    message = f'Click the following link to verify your email:\n{verify_url}'
    from_email = os.environ.get('EMAIL_HOST_USER')
    recipient_list = [user.email]
    send_mail(subject, message, from_email, recipient_list)
    

def ratelimit_error(request, exception=None):
    return render(request, 'ratelimit_error.html')


@method_decorator(ratelimit(key='ip', rate='10/m', block=True),name="dispatch")
@method_decorator(ratelimit(key='user', rate='10/m', block=True), name="dispatch")
class IndexView(View):
    def get(self, request):
        if request.user.is_authenticated:
            return redirect('home')
        user_input_form = UserInputForm()
        logger.info(f'Request made by user: {request.user}, IP address: {request.META["REMOTE_ADDR"]}, Request: {request.GET}')
        return render(request, 'index.html', {'user_input_form': user_input_form})

    def post(self, request):
        user_input_form = UserInputForm(request.POST, request.FILES)
        logger.info(f'Request made by user: {request.user}, IP address: {request.META["REMOTE_ADDR"]}, Request: {request.POST}')
        if user_input_form.is_valid():
            user_input = user_input_form.cleaned_data['user_input']
            user_selected_model = user_input_form.cleaned_data['user_selected_model']
            
            file_instance = None
            if 'email_files' in request.FILES:
                email_files = request.FILES['email_files']
                file_content = email_files.read()
                file_hash = hashlib.sha256(file_content).hexdigest()
                
                if not FileModel.objects.filter(file=file_hash).exists():
                    file_path = default_storage.save('uploads/' + email_files.name, ContentFile(file_content))
                    file_instance = FileModel.objects.create(file=file_path, file_hash=file_hash)
                else:
                    file_instance = FileModel.objects.get(file=file_hash)      
            
            form_submission_count = request.session.get('form_submission_count', 0)
            if form_submission_count >= 10:
                return redirect('register') 
            try:
                result_message = classify_spam(user_input, user_selected_model, file_instance.file if file_instance else None)
                user_input_form = UserInputForm()
                content = {'user_input_form': user_input_form, 'result_message': result_message}
                request.session['form_submission_count'] = form_submission_count + 1
                return render(request, 'index.html', content)
            except Exception as e:
                error_message = str(e)
                user_input_form.add_error('user_input', error_message)
                logger.error(f'Error occurred: {error_message}, Timestamp: {timezone.now()}, Context: {request.POST}')
        else:
            result_message = "Invalid input. Please try again."
            user_input_form = UserInputForm()
            content = {'user_input_form': user_input_form, 'result_message': result_message}
            return render(request, 'index.html', content)
    
        try:
            if request.limited:
                return render(request, 'ratelimit_error.html')
        except Exception as e:
            logger.error(f'Error occurred: {str(e)}, Timestamp: {timezone.now()}, Context: {request.GET}')
            return render(request, 'ratelimit_error.html')
        return render(request, 'index.html', {'user_input_form': user_input_form})
    

class RegisterView(View):
    def get(self, request):
        if request.user.is_authenticated:
            return redirect('home')
        form = RegistrationForm()
        logger.info(f'Register Page request made by user: {request.user}, IP address: {request.META["REMOTE_ADDR"]}, Request: {request.GET}')
        return render(request, 'register.html', {'form': form})

    def post(self, request):
        form = RegistrationForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data['name']
            email = form.cleaned_data['email'].strip()
            password = form.cleaned_data['password']
            user = MyUser.objects.create_user(name=name, email=email, password=password, is_email_verified=False)
            if user is not None:
                verification_type = 'register'
                generate_verification_link(request, email, verification_type)
                logger.info(f'Registration Request made by user: {request.user}, IP address: {request.META["REMOTE_ADDR"]}, Request: {request.POST}')
                return render(request, 'mailvalid/checkbox.html')
            else:
                logger.error(f'Error occurred during registration. Timestamp: {timezone.now()}, Context: {request.POST}')
                messages.error(request, 'An error occurred during registration.')
                return render(request, 'register.html', {'form': form})
        return render(request, 'register.html', {'form': form})


class VerifyEmailView(View):
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode('utf-8')
            user = MyUser.objects.get(pk=uid)
            
            if user is not None and not user.is_email_verified:
                if default_token_generator.check_token(user, token):
                    timestamp = request.session.get('verification_timestamp')
                    if timestamp:
                        timestamp = int(timestamp)
                        expiry_time = timezone.make_aware(timezone.datetime.fromtimestamp(timestamp))
                        now = timezone.now()
                        if now <= expiry_time:
                            del request.session['verification_timestamp']
                            user.is_email_verified = True
                            user.save()
                            return render(request, 'mailvalid/email_verification_success.html')                       
                    else:
                        return render(request, 'mailvalid/email_verification_failure.html', {'email': user.email})
                else:
                    email = user.email
                    return render(request, 'mailvalid/email_verification_failure.html', {'email': email})
            else:
                return render(request, 'mailvalid/email_verification_failure.html')
        except Exception as e:
            
            messages.error(request, str(e))
            return render(request, 'mailvalid/email_verification_failure.html')


class LoginView(View):
    def get(self, request):
        if request.user.is_authenticated:
            logger.info(f'User with IP {request.META["REMOTE_ADDR"]} accessed the login page. {request.user} is already authenticated.')
            return redirect('home')
        
        logger.info(f'User with IP {request.META["REMOTE_ADDR"]} accessed the login page.')
        form = LoginForm()
        return render(request, 'login.html', {'form': form})

    def post(self, request):
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, email=email, password=password)
            if user is not None:
                if user.is_email_verified:
                    logger.info(f'User with IP {request.META["REMOTE_ADDR"]} logged in successfully. User email: {email}')
                    login(request, user)
                    return redirect('home')
                else:
                    logger.warning(f'User with IP {request.META["REMOTE_ADDR"]} tried to log in without verifying their email. User email: {email}')
                    messages.error(request, 'Please verify your email before logging in.')
                    return render(request, 'login.html', {'form': form})
            else:
                logger.warning(f'User with IP {request.META["REMOTE_ADDR"]} tried to log in with invalid credentials. User email: {email}')
                messages.error(request, 'Invalid email or password.')
                return render(request, 'login.html', {'form': form})
        else:
            logger.warning(f'User with IP {request.META["REMOTE_ADDR"]} submitted an invalid login form.')
            return render(request, 'login.html', {'form': form})


class RegenerateVerificationEmailView(View):
    def get(self, request):
        form = RegenerateResetEmailForm()
        if request.user.is_authenticated:
            logger.info(f'User with IP {request.META["REMOTE_ADDR"]} accessed the email regeneration page. User is already authenticated.')
            return redirect('home')
        logger.info(f'User with IP {request.META["REMOTE_ADDR"]} accessed the email regeneration page.')
        return render(request, 'mailvalid/email_verification_failure.html', {'form': form})

    def post(self, request):
        form = RegenerateResetEmailForm(request.POST)
        try:
            if form.is_valid():
                email = form.cleaned_data['email']
                user = MyUser.objects.filter(email=email).first()
                if user is not None:
                    if user.is_email_verified:
                        logger.info(f'User with IP {request.META["REMOTE_ADDR"]} tried to regenerate email for an already verified account. User email: {email}')
                        messages.error(request, 'Already verified, please log in.')
                        return redirect('login')
                    else:
                        logger.info(f'User with IP {request.META["REMOTE_ADDR"]} successfully requested email regeneration. User email: {email}')
                        generate_verification_link(request, email)
                        messages.success(request, 'A new verification email has been sent.')
                        return render(request, 'mailvalid/checkbox.html')
                else:
                    logger.info(f'User with IP {request.META["REMOTE_ADDR"]} tried to regenerate email for a non-existing account.')
                    messages.error(request, 'Please register your account first')
                    return redirect('register')
            else:
                logger.error(f'User with IP {request.META["REMOTE_ADDR"]} submitted an invalid email regeneration form.')
                return render(request, 'mailvalid/email_verification_failure.html', {'form': form})
        except Exception as e:
            logger.error(f'Error sending verification email: {str(e)}')
            messages.error(request, f'Error sending verification email: {str(e)}')
            return redirect('login')  # Redirect to the login page
        else:
            return redirect('home')


@login_required(login_url='login')
def HomeView(request):
    if request.user.is_authenticated:
        user = request.user
        jwttoken = None
        token_generated_today = False
        # payment_success = request.session.pop('payment_success', False)
        # payment_cancelled = request.session.pop('payment_cancelled', False)
        # payment_error = request.session.pop('payment_error', None)

        logger.info(f'User with IP {request.META["REMOTE_ADDR"]} accessed the home page. {request.user} is authenticated.')

        if request.method == 'POST' and 'generate_token' in request.POST:
            cache_key = f"user_token_{user.id}"
            if cache.get(cache_key):
                token_generated_today = True
                logger.info(f'User with IP {request.META["REMOTE_ADDR"]} requested a token, but a token was already generated today for user {user.email}.')
            if not cache.get(cache_key):
                jwttoken = get_tokens_for_user_api(user)
                cache.set(cache_key, True, timedelta(days=1).total_seconds())
                subject = 'Your Spam Api generate Token'
                message = f'Please carefully store your token. \n{jwttoken}'
                from_email = os.environ.get('EMAIL_HOST_USER')
                recipient_list = [user.email]
                send_mail(subject, message, from_email, recipient_list)
                logger.info(f'User with IP {request.META["REMOTE_ADDR"]} successfully requested and received a token. User email: {user.email}')
    
        return render(request, 'home.html', {'user': user, 'jwttoken': jwttoken, 'token_generated_today': token_generated_today})


@login_required(login_url='login')
def PaymentPageView(request):
    form = LoginForm(request.POST)
    if request.user.is_authenticated:
        user = request.user
        currency = 'INR'
        amount = 100
        razorpay_order = razorpay_client.order.create(dict(amount=amount, currency=currency,payment_capture='0'))

        razorpay_order_id = razorpay_order['id']
        callback_url = 'paymenthandler/'
        context = {}
        context['razorpay_order_id'] = razorpay_order_id
        context['razorpay_merchant_key'] = RAZOR_KEY_ID
        context['razorpay_amount'] = amount
        context['currency'] = currency
        context['callback_url'] = callback_url
        context['user_id'] = user.id
        return render(request, 'payment.html', context=context)
    else:
        return render(request, 'login.html', {'form': form})


@csrf_exempt
def paymenthandler(request):
    if request.method == "POST":
        try:
            payment_id = request.POST.get('razorpay_payment_id', '')
            razorpay_order_id = request.POST.get('razorpay_order_id', '')
            signature = request.POST.get('razorpay_signature', '')
            params_dict = {
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': payment_id,
                'razorpay_signature': signature
            }
            result = razorpay_client.utility.verify_payment_signature(params_dict)
            if result is not None:
                amount = 100
                try:
                    razorpay_client.payment.capture(payment_id, amount)
                    user_id = request.POST.get('user_id')
                    user = MyUser.objects.get(id=user_id)
                    user.paid = True
                    user.save()
                    request.session['payment_success'] = True
                    print('success')
                    return redirect('home')
                except:
                    request.session['payment_error'] = 'Payment failed'
                    print('failed')
                    return redirect('home')
            else:
                request.session['payment_error'] = 'Payment failed'
                print('success')
                return redirect('home')
        except:
            return HttpResponseBadRequest()
    else:
        return HttpResponseBadRequest()


class SpamClassifierApi(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        token_key = f"user_token_{user.id}"
        token_count = cache.get(token_key, 0)

        logger.info(f'User with IP {request.META["REMOTE_ADDR"]} accessed the Spam Classifier API.')

        if token_count < 10:
            cache.set(token_key, token_count + 1, timeout=None)
            serializer = SpamClassifierSerializer(data=request.data)        
            if serializer.is_valid():
                email_content = serializer.validated_data.get('user_message')
                user_selected_model = serializer.validated_data.get('user_selected_model')

                try:
                    message = classify_spam(email_content, user_selected_model)
                    if message:
                        logger.info(f'Spam detected in the email content submitted by user with IP {request.META["REMOTE_ADDR"]}.')
                        return Response({"error": "Request processed within limit"}, status=status.HTTP_200_OK)
                    else:
                        logger.info(f'No spam detected in the email content submitted by user with IP {request.META["REMOTE_ADDR"]}.')
                        return Response({"message": "Request processed within limit"}, status=status.HTTP_200_OK)
                except Exception as e:
                    logger.error(f'Error occurred while classifying spam. User IP: {request.META["REMOTE_ADDR"]}, Error: {str(e)}')
                    return Response({"error": "An error occurred while classifying spam."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                logger.warning(f'User with IP {request.META["REMOTE_ADDR"]} submitted an invalid request to the Spam Classifier API.')
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            if user.paid:
                # If user has paid, reset the token count
                cache.set(token_key, 0, timeout=None)
                # Your existing spam classification logic here
                return Response({"message": "Request processed after payment"}, status=status.HTTP_200_OK)
            else:
                # Prompt for payment
                payment_message = "Payment required for additional requests. Login in your account and pay"
                return Response({"error": payment_message}, status=status.HTTP_402_PAYMENT_REQUIRED)



class CustomPasswordResetView(PasswordResetView):
    def get(self, request):
        logger.info(f'User with IP {request.META["REMOTE_ADDR"]} accessed the password reset page.')
        form = ResetPasswordForm(request.POST)
        return render(request, 'reset/password_reset.html', {'form': form})
    
    def post(self, request):
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user = MyUser.objects.filter(email=email).first()
            if user is not None:
                verification_type = 'password_reset'
                generate_verification_link(request, email, verification_type)
                logger.info(f'Password reset link generated for user with email: {email}')
                return redirect('password_reset_done')
            else:
                logger.warning(f'User with email {email} tried to reset password but is not registered.')
                messages.error(request, 'Please register your account first')
                return redirect('register')
        else:
            logger.warning(f'User with IP {request.META["REMOTE_ADDR"]} submitted an invalid password reset form.')
            return render(request, 'reset/password_reset.html', {'form': form})

def ServicesView(request):
    return render(request, 'service.html')

def LogoutView(request):
    logout(request)
    return redirect('login')
from django import forms
from django.contrib.auth.forms import UserCreationForm, PasswordResetForm
from .models import MyUser
import re
from django.core import validators
from .models import FileModel


class RegistrationForm(forms.ModelForm):
    email = forms.EmailField(required=True, validators=[validators.EmailValidator(
        message='Please enter a valid email address.')],)
    password = forms.CharField(
        widget=forms.PasswordInput,
        validators=[
            validators.MinLengthValidator(
                limit_value=8, message='Password must be at least 8 characters long.'),
            validators.RegexValidator(
                regex=r'^(?=.*[0-9])(?=.*[a-zA-Z])(?=.*[\W_]).*$',
                message='Password must contain at least one digit, one alphabet character, and one special character.',
            ),
        ],
    )
    name = forms.CharField(
        validators=[
            validators.RegexValidator(
                regex=r'^[a-zA-Z]+$',
                message='Username must contain only alphabetic characters.',
            ),
        ],
    )

    class Meta:
        model = MyUser
        fields = ["name", "email", "password"]

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        password = cleaned_data.get('password')
        name = cleaned_data.get('name')
        if MyUser.objects.filter(email=email).exists():
            self.add_error('email', 'A user with this email already exists.')
        if password and len(password) < 8:
            self.add_error('password', 'Password must be at least 8 characters long.')

    def save(self, commit=True):
        user = super().save(commit=False)
        password = self.cleaned_data["password"]
        user.set_password(password)
        user.save()
        return user


class LoginForm(forms.Form):
    email = forms.EmailField(required=True)
    password = forms.CharField(widget=forms.PasswordInput)
    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get("email")
        password = cleaned_data.get("password")

        if email and password:
            user = MyUser.objects.filter(email=email).first()
            if user is not None:
                if not user.check_password(password):
                    raise forms.ValidationError("Invalid email or password")
            else:
                raise forms.ValidationError("User does not exist")
        return cleaned_data


class RegenerateResetEmailForm(forms.ModelForm):
    email = forms.EmailField(required=True)
    class Meta:
        model = MyUser
        fields = ['email']


class ResetPasswordForm(forms.Form):
    email = forms.EmailField()
    

class FileModelForm(forms.ModelForm):
    class Meta:
        model = FileModel
        fields = ['file']

class UserInputForm(forms.Form):
    user_input = forms.CharField(
        max_length=1000,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
        label="Enter your mail ",
        required=False
    )
    user_selected_model = forms.ChoiceField(
        choices=[('rfmodel.pkl', 'RandomForest'), 
                 ('knmodel.pkl', 'KNeighbors'),
                 ('gbdtmodel.pkl', 'GradientBoosting'),
                 ('mnbmodel.pkl', 'Multinaibayes'),],
        widget=forms.RadioSelect(attrs={'class': 'radio-buttons'}),
        label="Select Any Model or Leave empty to use default model",
        required=False
    )
    email_files = forms.FileField(
        label="Upload Files",
        required=False,
        widget=forms.FileInput()
    )
    def clean_email_files(self):
        email_files = self.cleaned_data['email_files']
        if email_files:
            file_instance = FileModel(file=email_files)
            file_instance.save()
        return email_files

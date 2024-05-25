from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
import hashlib
from .constants import PaymentStatus


class MyUserManager(BaseUserManager):
    def create_user(self, email, name, password=None, is_email_verified=False):
        if not email:
            raise ValueError('Please enter email address')
        user = self.model(
            email=self.normalize_email(email),
            name=name,
            is_email_verified=is_email_verified,
            paid=False
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None):
        user = self.create_user(email, name, password)
        user.is_admin = True
        user.save(using=self._db)
        return user


class MyUser(AbstractBaseUser):
    email = models.EmailField(verbose_name='Email',max_length=255,unique=True)
    name = models.CharField(max_length=20)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    paid = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True) 

    objects = MyUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does user have specific permission?"
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does user have permission to view app 'app_label'?" 
        return True

    @property
    def is_staff(self):
        "Is the user member of the staff?"
        return self.is_admin


class Order(models.Model):
    email = models.CharField(("Customer Email"), max_length=254, blank=False, null=False)
    amount = models.FloatField(("Amount"), null=False, blank=False)    
    status = models.CharField(("Payment Status"),default=PaymentStatus.PENDING, max_length=254,blank=False, null=False,)
    provider_order_id = models.CharField(("Order ID"), max_length=40, null=False, blank=False)
    payment_id = models.CharField(("Payment ID"), max_length=36, null=False, blank=False)
    signature_id = models.CharField(("Signature ID"), max_length=128, null=False, blank=False)
    def __str__(self):
        return f"{self.id}-{self.email}-{self.status}"

    def save(self, *args, **kwargs):
        if self.status == PaymentStatus.SUCCESS:
            user = MyUser.objects.filter(email=self.email).first() 
            if user:
                user.paid = True
                user.save()
        super().save(*args, **kwargs)



class FileModel(models.Model):
    file = models.FileField(upload_to='uploads/')
    file_hash = models.CharField(max_length=64, default='')  # Assuming the hash is stored as a string with a length of 64 characters

    def save(self, *args, **kwargs):
        if not self.pk:
            file_content = self.file.read()
            self.file_hash = hashlib.sha256(file_content).hexdigest()
        super().save(*args, **kwargs)
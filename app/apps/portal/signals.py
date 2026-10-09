from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import PerfilWifi


@receiver(post_save, sender=User, dispatch_uid="portal.criar_perfil_wifi")
def criar_perfil_wifi(sender, instance, created, raw=False, using=None, **kwargs):
    if created and not raw:
        PerfilWifi.objects.using(using).get_or_create(user=instance)

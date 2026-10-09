import re

from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


def _normalize_mac(mac):
    """Normalização compartilhada sem depender da camada de serviços."""
    value = str(mac or "").strip().replace("-", ":").upper()
    return value if re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", value) else ""


class PerfilWifi(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="perfil_wifi")
    bloqueado = models.BooleanField(default=False)
    criado_em = models.DateTimeField(auto_now_add=True)
    atualizado_em = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.username


class Dispositivo(models.Model):
    usuario = models.ForeignKey(User, on_delete=models.CASCADE, related_name="dispositivos")
    mac_address = models.CharField(max_length=17, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    primeiro_acesso = models.DateTimeField(auto_now_add=True)
    ultimo_acesso = models.DateTimeField(auto_now=True)
    ativo = models.BooleanField(default=True)

    class Meta:
        ordering = ["-ultimo_acesso"]
        constraints = [models.UniqueConstraint(
            fields=["usuario", "mac_address"], condition=~models.Q(mac_address=""),
            name="portal_dispositivo_usuario_mac_unico",
        )]

    def save(self, *args, **kwargs):
        self.mac_address = _normalize_mac(self.mac_address)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.usuario.username}: {self.mac_address or self.ip_address or 'sem endereço'}"


class SessaoWifi(models.Model):
    usuario = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sessoes_wifi")
    dispositivo = models.ForeignKey(
        Dispositivo, on_delete=models.SET_NULL, null=True, blank=True, related_name="sessoes",
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    mac_address = models.CharField(max_length=17, blank=True)
    iniciada_em = models.DateTimeField(auto_now_add=True)
    encerrada_em = models.DateTimeField(null=True, blank=True)
    ativa = models.BooleanField(default=True)
    autorizada = models.BooleanField(default=False)
    origem = models.CharField(max_length=50, default="portal")

    class Meta:
        ordering = ["-iniciada_em"]
        indexes = [models.Index(fields=["usuario", "ativa"])]

    def encerrar(self):
        if self.ativa:
            self.ativa = False
            self.encerrada_em = timezone.now()
            self.save(update_fields=["ativa", "encerrada_em"])

    def __str__(self):
        return f"{self.usuario.username} — sessão {self.pk}"


class LogAcesso(models.Model):
    class Evento(models.TextChoices):
        LOGIN_SUCESSO = "LOGIN_SUCESSO", "Login realizado"
        LOGIN_FALHA = "LOGIN_FALHA", "Falha no login"
        CADASTRO = "CADASTRO", "Cadastro"
        LOGOUT = "LOGOUT", "Saída"
        BLOQUEADO = "BLOQUEADO", "Acesso bloqueado"
        AUTORIZACAO_WIFI = "AUTORIZACAO_WIFI", "Autorização Wi-Fi"
        REVOGACAO_WIFI = "REVOGACAO_WIFI", "Revogação Wi-Fi"

    usuario = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="logs_acesso",
    )
    evento = models.CharField(max_length=30, choices=Evento.choices)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    mac_address = models.CharField(max_length=17, blank=True)
    detalhes = models.JSONField(default=dict, blank=True)
    criado_em = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-criado_em"]

    def __str__(self):
        return f"{self.get_evento_display()} — {self.usuario_id or 'anônimo'}"

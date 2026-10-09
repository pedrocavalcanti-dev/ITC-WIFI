from dataclasses import dataclass
from ipaddress import ip_address as parse_ip

from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone

from .models import Dispositivo, LogAcesso, PerfilWifi, SessaoWifi, _normalize_mac


@dataclass
class AuthResult:
    success: bool
    message: str
    session: SessaoWifi | None = None


def _validated_ip(value):
    try:
        return str(parse_ip(str(value).strip()))
    except ValueError:
        return None


def get_client_ip(request):
    # Apenas metadados nesta fase. O proxy futuro deverá sobrescrever este header.
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    candidate = forwarded.split(",", 1)[0] if forwarded else None
    return _validated_ip(candidate) or _validated_ip(request.META.get("REMOTE_ADDR"))


def normalize_mac(mac):
    return _normalize_mac(mac)


@transaction.atomic
def authorize_client(user, ip_address=None, mac_address=None, request=None):
    # Reconsultar o estado persistido para não autorizar com um User desatualizado.
    user = User.objects.select_for_update().get(pk=user.pk)
    perfil, _ = PerfilWifi.objects.get_or_create(user=user)
    ip = _validated_ip(ip_address) if ip_address else get_client_ip(request) if request else None
    mac = normalize_mac(mac_address)
    if not user.is_active or perfil.bloqueado:
        LogAcesso.objects.create(
            usuario=user, evento=LogAcesso.Evento.BLOQUEADO, ip_address=ip, mac_address=mac,
        )
        return AuthResult(False, "Acesso Wi-Fi bloqueado para este usuário.")

    dispositivo = None
    if mac:
        dispositivo, _ = Dispositivo.objects.update_or_create(
            usuario=user, mac_address=mac, defaults={"ip_address": ip, "ativo": True},
        )
        # O mesmo dispositivo pode receber outro IP em uma nova conexão.
        anteriores = SessaoWifi.objects.filter(usuario=user, ativa=True, mac_address=mac)
    else:
        anteriores = SessaoWifi.objects.filter(usuario=user, ativa=True, ip_address=ip, mac_address="")
    anteriores.update(ativa=False, encerrada_em=timezone.now())
    # FUTURE: integrar autorização real com AP/captive portal aqui.
    session = SessaoWifi.objects.create(
        usuario=user, dispositivo=dispositivo, ip_address=ip, mac_address=mac,
        ativa=True, autorizada=True,
    )
    LogAcesso.objects.create(
        usuario=user, evento=LogAcesso.Evento.AUTORIZACAO_WIFI,
        ip_address=ip, mac_address=mac, detalhes={"sessao_id": session.pk},
    )
    return AuthResult(True, "Sessão Wi-Fi autorizada localmente.", session)


@transaction.atomic
def revoke_client(user, ip_address=None, mac_address=None):
    sessions = SessaoWifi.objects.filter(usuario=user, ativa=True)
    if ip_address is not None:
        ip = _validated_ip(ip_address)
        if ip is None:
            return AuthResult(False, "Endereço IP inválido.")
        sessions = sessions.filter(ip_address=ip)
    if mac_address is not None:
        mac = normalize_mac(mac_address)
        if not mac:
            return AuthResult(False, "Endereço MAC inválido.")
        sessions = sessions.filter(mac_address=mac)
    last_session = sessions.first()
    count = sessions.update(ativa=False, encerrada_em=timezone.now())
    if last_session:
        last_session.refresh_from_db()
    # FUTURE: revogar cliente no AP/captive portal aqui.
    LogAcesso.objects.create(
        usuario=user, evento=LogAcesso.Evento.REVOGACAO_WIFI,
        ip_address=_validated_ip(ip_address), mac_address=normalize_mac(mac_address),
        detalhes={"sessoes_encerradas": count},
    )
    return AuthResult(True, "Sessões Wi-Fi encerradas.", last_session)

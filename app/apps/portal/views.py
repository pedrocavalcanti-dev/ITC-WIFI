from functools import wraps

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError, transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_POST

from .forms import CadastroForm, LoginForm
from .models import LogAcesso, PerfilWifi, SessaoWifi
from .services import authorize_client, get_client_ip, revoke_client


def staff_required(view):
    @login_required
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_staff:
            raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapped


def _portal_response(request, login_form=None, register_form=None):
    context = {
        "login_form": login_form if login_form is not None else LoginForm(),
        "register_form": register_form if register_form is not None else CadastroForm(),
    }
    if request.user.is_authenticated:
        context["perfil"], _ = PerfilWifi.objects.get_or_create(user=request.user)
        context["wifi_session"] = SessaoWifi.objects.filter(
            usuario=request.user, ativa=True,
        ).select_related("dispositivo").first()
    return render(request, "portal/index.html", context)


@require_GET
def portal_view(request):
    return _portal_response(request)


@require_POST
@transaction.atomic
def login_view(request):
    if request.user.is_authenticated:
        return redirect("portal:home")
    form = LoginForm(request.POST)
    user = None
    if form.is_valid():
        user = authenticate(
            request, username=form.cleaned_data["username"], password=form.cleaned_data["password"],
        )
    if user is None:
        LogAcesso.objects.create(evento=LogAcesso.Evento.LOGIN_FALHA, ip_address=get_client_ip(request))
        form.add_error(None, "Usuário ou senha inválidos, ou conta inativa.")
        return _portal_response(request, login_form=form)

    perfil, _ = PerfilWifi.objects.get_or_create(user=user)
    if not user.is_active or perfil.bloqueado:
        LogAcesso.objects.create(
            usuario=user, evento=LogAcesso.Evento.BLOQUEADO, ip_address=get_client_ip(request),
        )
        form.add_error(None, "Acesso Wi-Fi bloqueado para este usuário.")
        return _portal_response(request, login_form=form)

    login(request, user)
    result = authorize_client(user, request=request)
    if not result.success:
        logout(request)
        form.add_error(None, result.message)
        return _portal_response(request, login_form=form)
    LogAcesso.objects.create(
        usuario=user, evento=LogAcesso.Evento.LOGIN_SUCESSO, ip_address=get_client_ip(request),
    )
    messages.success(request, "Login realizado. Sessão Wi-Fi registrada.")
    return redirect("portal:home")


@require_POST
@transaction.atomic
def register_view(request):
    if request.user.is_authenticated:
        return redirect("portal:home")
    form = CadastroForm(request.POST)
    if not form.is_valid():
        return _portal_response(request, register_form=form)
    try:
        # Savepoint para tratar cadastros simultâneos sem quebrar a transação externa.
        with transaction.atomic():
            user = form.save()
    except IntegrityError:
        form.add_error("username", "Este usuário já existe.")
        return _portal_response(request, register_form=form)
    PerfilWifi.objects.get_or_create(user=user)
    LogAcesso.objects.create(
        usuario=user, evento=LogAcesso.Evento.CADASTRO, ip_address=get_client_ip(request),
    )
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    result = authorize_client(user, request=request)
    if not result.success:
        logout(request)
        messages.error(request, result.message)
    else:
        messages.success(request, "Conta criada. Sessão Wi-Fi registrada.")
    return redirect("portal:home")


@require_POST
@login_required
@transaction.atomic
def logout_view(request):
    revoke_client(request.user)
    LogAcesso.objects.create(
        usuario=request.user, evento=LogAcesso.Evento.LOGOUT, ip_address=get_client_ip(request),
    )
    logout(request)
    messages.success(request, "Você saiu do portal.")
    return redirect("portal:home")


@require_GET
@staff_required
def dashboard_view(request):
    usuarios = User.objects.select_related("perfil_wifi").order_by("username")
    sessoes_ativas = SessaoWifi.objects.filter(ativa=True).select_related("usuario", "dispositivo")
    return render(request, "portal/painel.html", {
        "total_usuarios": usuarios.count(),
        "total_bloqueados": PerfilWifi.objects.filter(bloqueado=True).count(),
        "total_sessoes_ativas": sessoes_ativas.count(),
        "usuarios": usuarios, "sessoes_ativas": sessoes_ativas,
    })


@require_POST
@staff_required
@transaction.atomic
def block_user_view(request, user_id):
    user = get_object_or_404(User.objects.select_for_update(), pk=user_id)
    if user.pk == request.user.pk:
        messages.error(request, "Você não pode bloquear seu próprio acesso.")
        return redirect("portal:dashboard")
    perfil, _ = PerfilWifi.objects.get_or_create(user=user)
    perfil.bloqueado = True
    perfil.save(update_fields=["bloqueado", "atualizado_em"])
    revoke_client(user)
    LogAcesso.objects.create(
        usuario=user, evento=LogAcesso.Evento.BLOQUEADO, ip_address=get_client_ip(request),
        detalhes={"staff_id": request.user.pk},
    )
    messages.success(request, "Usuário bloqueado e sessões encerradas.")
    return redirect("portal:dashboard")


@require_POST
@staff_required
@transaction.atomic
def unblock_user_view(request, user_id):
    user = get_object_or_404(User.objects.select_for_update(), pk=user_id)
    perfil, _ = PerfilWifi.objects.get_or_create(user=user)
    perfil.bloqueado = False
    perfil.save(update_fields=["bloqueado", "atualizado_em"])
    messages.success(request, "Usuário desbloqueado.")
    return redirect("portal:dashboard")

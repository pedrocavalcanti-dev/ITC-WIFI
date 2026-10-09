from django.contrib import admin

from .models import Dispositivo, LogAcesso, PerfilWifi, SessaoWifi


@admin.register(PerfilWifi)
class PerfilWifiAdmin(admin.ModelAdmin):
    list_display = ("user", "bloqueado", "criado_em")
    list_filter = ("bloqueado",)
    search_fields = ("user__username",)
    list_select_related = ("user",)
    readonly_fields = ("criado_em", "atualizado_em")

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if obj.bloqueado:
            from .services import revoke_client
            revoke_client(obj.user)


@admin.register(Dispositivo)
class DispositivoAdmin(admin.ModelAdmin):
    list_display = ("usuario", "mac_address", "ip_address", "ativo", "ultimo_acesso")
    list_filter = ("ativo",)
    search_fields = ("usuario__username", "ip_address", "mac_address")
    list_select_related = ("usuario",)
    readonly_fields = ("primeiro_acesso", "ultimo_acesso")


@admin.register(SessaoWifi)
class SessaoWifiAdmin(admin.ModelAdmin):
    list_display = ("usuario", "ip_address", "mac_address", "ativa", "autorizada", "iniciada_em", "encerrada_em")
    list_filter = ("ativa", "autorizada", "origem")
    search_fields = ("usuario__username", "ip_address", "mac_address")
    list_select_related = ("usuario", "dispositivo")
    readonly_fields = ("iniciada_em", "encerrada_em")


@admin.register(LogAcesso)
class LogAcessoAdmin(admin.ModelAdmin):
    list_display = ("usuario", "evento", "ip_address", "criado_em")
    list_filter = ("evento",)
    search_fields = ("usuario__username", "ip_address", "mac_address")
    list_select_related = ("usuario",)
    readonly_fields = ("usuario", "evento", "ip_address", "mac_address", "detalhes", "criado_em")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

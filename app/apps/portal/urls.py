from django.urls import path

from . import views

app_name = "portal"

urlpatterns = [
    path("", views.portal_view, name="home"),
    path("entrar/", views.login_view, name="login"),
    path("criar-conta/", views.register_view, name="register"),
    path("sair/", views.logout_view, name="logout"),
    path("painel/", views.dashboard_view, name="dashboard"),
    path("painel/usuarios/<int:user_id>/bloquear/", views.block_user_view, name="block_user"),
    path("painel/usuarios/<int:user_id>/desbloquear/", views.unblock_user_view, name="unblock_user"),
]

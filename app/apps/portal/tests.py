from django.contrib.auth.models import User
from django.test import Client, RequestFactory, TestCase
from django.urls import reverse

from .forms import CadastroForm, LoginForm
from .models import Dispositivo, LogAcesso, PerfilWifi, SessaoWifi
from .services import authorize_client, get_client_ip, normalize_mac, revoke_client


PASSWORD = "Laboratorio!Seguro2026"


class PortalTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("aluno", password=PASSWORD)
        cls.staff = User.objects.create_user("gestor", password=PASSWORD, is_staff=True)

    def login_post(self, **extra):
        return self.client.post(reverse("portal:login"), {
            "username": self.user.username, "password": PASSWORD, **extra,
        })

    def test_homepage(self):
        response = self.client.get(reverse("portal:home"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.context["login_form"].fields), {"username", "password"})
        self.assertEqual(set(response.context["register_form"].fields), {"username", "password"})

    def test_registration_creates_user_hash_profile_and_session(self):
        response = self.client.post(reverse("portal:register"), {
            "username": "  novo.aluno  ", "password": PASSWORD,
        })
        self.assertRedirects(response, reverse("portal:home"))
        user = User.objects.get(username="novo.aluno")
        self.assertTrue(user.is_active)
        self.assertNotEqual(user.password, PASSWORD)
        self.assertTrue(user.check_password(PASSWORD))
        self.assertTrue(PerfilWifi.objects.filter(user=user, bloqueado=False).exists())
        self.assertEqual(int(self.client.session["_auth_user_id"]), user.pk)
        self.assertTrue(SessaoWifi.objects.filter(usuario=user, ativa=True, autorizada=True).exists())
        self.assertTrue(LogAcesso.objects.filter(usuario=user, evento=LogAcesso.Evento.CADASTRO).exists())

    def test_profile_signal_does_not_duplicate_on_save(self):
        self.user.save()
        self.assertEqual(PerfilWifi.objects.filter(user=self.user).count(), 1)

    def test_duplicate_username(self):
        response = self.client.post(reverse("portal:register"), {"username": " aluno ", "password": PASSWORD})
        self.assertEqual(response.status_code, 200)
        self.assertIn("username", response.context["register_form"].errors)
        self.assertEqual(User.objects.filter(username="aluno").count(), 1)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_invalid_passwords(self):
        for password in ["", "1", "12", "123"]:
            with self.subTest(password=password):
                form = CadastroForm({"username": "novo.aluno", "password": password})
                self.assertFalse(form.is_valid())
                self.assertIn("password", form.errors)

    def test_simple_passwords_are_accepted_and_hashed(self):
        for password in ["1234", "2026", "teste", "aluno", "abc1", "0000", "password"]:
            with self.subTest(password=password):
                # O username igual à senha também deve ser aceito.
                username = password if password != "aluno" else "aluno.novo"
                form = CadastroForm({"username": username, "password": password})
                self.assertTrue(form.is_valid(), form.errors)
                user = form.save()
                self.assertNotEqual(user.password, password)
                self.assertTrue(user.check_password(password))

    def test_numeric_four_character_password_registration(self):
        response = self.client.post(reverse("portal:register"), {"username": "numerico", "password": "1234"})
        self.assertRedirects(response, reverse("portal:home"))
        user = User.objects.get(username="numerico")
        self.assertTrue(user.check_password("1234"))
        self.assertNotEqual(user.password, "1234")
        self.assertEqual(int(self.client.session["_auth_user_id"]), user.pk)
        self.assertTrue(SessaoWifi.objects.filter(usuario=user, ativa=True, autorizada=True).exists())

    def test_three_character_password_registration_is_rejected(self):
        response = self.client.post(reverse("portal:register"), {"username": "curto", "password": "123"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("password", response.context["register_form"].errors)
        self.assertFalse(User.objects.filter(username="curto").exists())
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_invalid_usernames_and_required_fields(self):
        for username in ["", "   ", "nome com espaço", "<script>", "a" * 151]:
            with self.subTest(username=username):
                form = CadastroForm({"username": username, "password": PASSWORD})
                self.assertFalse(form.is_valid())
                self.assertIn("username", form.errors)
        self.assertFalse(CadastroForm({"username": "novo"}).is_valid())
        self.assertFalse(LoginForm({"username": "aluno"}).is_valid())

    def test_normalized_username_uniqueness(self):
        form = CadastroForm({"username": "ａｌｕｎｏ", "password": PASSWORD})
        self.assertFalse(form.is_valid())
        self.assertIn("username", form.errors)

    def test_valid_login_and_wifi_session(self):
        response = self.login_post(username=" aluno ", next="https://example.org/")
        self.assertRedirects(response, reverse("portal:home"))
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.user.pk)
        session = SessaoWifi.objects.get(usuario=self.user, ativa=True)
        self.assertTrue(session.autorizada)
        self.assertTrue(LogAcesso.objects.filter(evento=LogAcesso.Evento.LOGIN_SUCESSO).exists())

    def test_invalid_login(self):
        response = self.login_post(password="incorreta")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertFalse(SessaoWifi.objects.exists())
        self.assertTrue(LogAcesso.objects.filter(evento=LogAcesso.Evento.LOGIN_FALHA).exists())
        self.assertTrue(response.context["login_form"].non_field_errors())

    def test_invalid_login_form_is_logged(self):
        self.client.post(reverse("portal:login"), {})
        self.assertTrue(LogAcesso.objects.filter(evento=LogAcesso.Evento.LOGIN_FALHA).exists())

    def test_blocked_user_cannot_login(self):
        PerfilWifi.objects.filter(user=self.user).update(bloqueado=True)
        response = self.login_post()
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertFalse(SessaoWifi.objects.exists())
        self.assertTrue(LogAcesso.objects.filter(usuario=self.user, evento=LogAcesso.Evento.BLOQUEADO).exists())

    def test_inactive_user_cannot_login(self):
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        self.login_post()
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertFalse(SessaoWifi.objects.exists())

    def test_authenticated_home_has_profile_and_session(self):
        self.login_post()
        response = self.client.get(reverse("portal:home"))
        self.assertEqual(response.context["perfil"].user_id, self.user.pk)
        self.assertTrue(response.context["wifi_session"].ativa)

    def test_logout_closes_sessions_and_logs(self):
        self.login_post()
        authorize_client(self.user, ip_address="10.10.0.100")
        response = self.client.post(reverse("portal:logout"))
        self.assertRedirects(response, reverse("portal:home"))
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertFalse(SessaoWifi.objects.filter(usuario=self.user, ativa=True).exists())
        self.assertFalse(SessaoWifi.objects.filter(encerrada_em__isnull=True).exists())
        self.assertTrue(LogAcesso.objects.filter(evento=LogAcesso.Evento.LOGOUT).exists())

    def test_logout_requires_post(self):
        self.login_post()
        self.assertEqual(self.client.get(reverse("portal:logout")).status_code, 405)
        self.assertTrue(SessaoWifi.objects.filter(ativa=True).exists())

    def test_login_and_registration_require_post(self):
        for name in ["login", "register"]:
            self.assertEqual(self.client.get(reverse(f"portal:{name}")).status_code, 405)

    def test_dashboard_requires_login(self):
        response = self.client.get(reverse("portal:dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/?next=/painel/")

    def test_dashboard_rejects_regular_user(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("portal:dashboard")).status_code, 403)

    def test_dashboard_allows_staff_and_has_counts(self):
        authorize_client(self.user)
        self.client.force_login(self.staff)
        response = self.client.get(reverse("portal:dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["total_usuarios"], 2)
        self.assertEqual(response.context["total_bloqueados"], 0)
        self.assertEqual(response.context["total_sessoes_ativas"], 1)

    def test_dashboard_query_count_is_constant(self):
        self.client.force_login(self.staff)
        with self.assertNumQueries(7):
            self.client.get(reverse("portal:dashboard"))
        for index in range(10):
            user = User.objects.create_user(f"extra{index}")
            SessaoWifi.objects.create(usuario=user)
        with self.assertNumQueries(7):
            self.client.get(reverse("portal:dashboard"))

    def test_block_requires_post(self):
        self.client.force_login(self.staff)
        response = self.client.get(reverse("portal:block_user", args=[self.user.pk]))
        self.assertEqual(response.status_code, 405)
        self.assertFalse(PerfilWifi.objects.get(user=self.user).bloqueado)

    def test_unblock_requires_post(self):
        self.client.force_login(self.staff)
        response = self.client.get(reverse("portal:unblock_user", args=[self.user.pk]))
        self.assertEqual(response.status_code, 405)

    def test_staff_can_block_and_close_sessions_without_deactivating_user(self):
        authorize_client(self.user)
        self.client.force_login(self.staff)
        response = self.client.post(reverse("portal:block_user", args=[self.user.pk]))
        self.assertRedirects(response, reverse("portal:dashboard"))
        self.assertTrue(PerfilWifi.objects.get(user=self.user).bloqueado)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)
        self.assertFalse(SessaoWifi.objects.filter(usuario=self.user, ativa=True).exists())

    def test_staff_can_unblock(self):
        PerfilWifi.objects.filter(user=self.user).update(bloqueado=True)
        self.client.force_login(self.staff)
        response = self.client.post(reverse("portal:unblock_user", args=[self.user.pk]))
        self.assertRedirects(response, reverse("portal:dashboard"))
        self.assertFalse(PerfilWifi.objects.get(user=self.user).bloqueado)
        self.assertFalse(SessaoWifi.objects.exists())

    def test_block_actions_reject_regular_user_and_anonymous(self):
        for name in ["block_user", "unblock_user"]:
            url = reverse(f"portal:{name}", args=[self.user.pk])
            self.assertEqual(self.client.post(url).status_code, 302)
            self.client.force_login(self.user)
            self.assertEqual(self.client.post(url).status_code, 403)
            self.client.logout()

    def test_staff_cannot_block_self(self):
        self.client.force_login(self.staff)
        self.client.post(reverse("portal:block_user", args=[self.staff.pk]))
        self.assertFalse(PerfilWifi.objects.get(user=self.staff).bloqueado)

    def test_missing_user_returns_404(self):
        self.client.force_login(self.staff)
        for name in ["block_user", "unblock_user"]:
            self.assertEqual(self.client.post(reverse(f"portal:{name}", args=[999999])).status_code, 404)

    def test_csrf_required_for_all_mutations(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.staff)
        for name in ["login", "register", "logout", "block_user", "unblock_user"]:
            args = [self.user.pk] if name in {"block_user", "unblock_user"} else []
            self.assertEqual(csrf_client.post(reverse(f"portal:{name}", args=args)).status_code, 403)

    def test_csrf_form_can_be_submitted(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.get(reverse("portal:home"))
        response = csrf_client.post(reverse("portal:login"), {
            "username": self.user.username, "password": PASSWORD,
            "csrfmiddlewaretoken": csrf_client.cookies["csrftoken"].value,
        })
        self.assertEqual(response.status_code, 302)

    def test_passwords_never_appear_in_logs(self):
        self.login_post(password="SenhaIncorretaSecreta!")
        self.login_post()
        self.client.post(reverse("portal:logout"))
        self.client.post(reverse("portal:register"), {"username": "novo", "password": PASSWORD})
        for log in LogAcesso.objects.all():
            self.assertNotIn(PASSWORD, str(log.detalhes))
            self.assertNotIn("SenhaIncorretaSecreta!", str(log.detalhes))
            self.assertNotIn("password", log.detalhes)


class ServicesTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("aluno", password=PASSWORD)

    def test_authorize_creates_authorized_session(self):
        result = authorize_client(self.user, ip_address="10.10.0.50", mac_address="aa-bb-cc-dd-ee-ff")
        self.assertTrue(result.success)
        self.assertTrue(result.session.ativa)
        self.assertTrue(result.session.autorizada)
        self.assertEqual(result.session.mac_address, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(result.session.dispositivo.usuario_id, self.user.pk)
        self.assertTrue(LogAcesso.objects.filter(evento=LogAcesso.Evento.AUTORIZACAO_WIFI).exists())

    def test_no_mac_allows_session_without_device(self):
        result = authorize_client(self.user, ip_address="10.10.0.50")
        self.assertTrue(result.success)
        self.assertIsNone(result.session.dispositivo)

    def test_repeated_authorization_replaces_same_client_session(self):
        first = authorize_client(self.user, ip_address="10.10.0.50").session
        second = authorize_client(self.user, ip_address="10.10.0.50").session
        first.refresh_from_db()
        self.assertFalse(first.ativa)
        self.assertIsNotNone(first.encerrada_em)
        self.assertNotEqual(first.pk, second.pk)
        self.assertEqual(SessaoWifi.objects.filter(ativa=True).count(), 1)

    def test_repeated_authorization_without_identifiers(self):
        authorize_client(self.user)
        authorize_client(self.user)
        self.assertEqual(SessaoWifi.objects.filter(ativa=True).count(), 1)

    def test_mac_device_is_updated_when_ip_changes(self):
        first = authorize_client(self.user, ip_address="10.10.0.50", mac_address="aa-bb-cc-dd-ee-ff").session
        second = authorize_client(self.user, ip_address="10.10.0.51", mac_address="AA:BB:CC:DD:EE:FF").session
        first.refresh_from_db()
        self.assertFalse(first.ativa)
        self.assertEqual(first.dispositivo_id, second.dispositivo_id)
        self.assertEqual(Dispositivo.objects.count(), 1)
        self.assertEqual(second.dispositivo.ip_address, "10.10.0.51")

    def test_authorize_checks_persisted_block_and_active_status(self):
        PerfilWifi.objects.filter(user=self.user).update(bloqueado=True)
        self.assertFalse(authorize_client(self.user).success)
        PerfilWifi.objects.filter(user=self.user).update(bloqueado=False)
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertFalse(authorize_client(self.user).success)
        self.assertFalse(SessaoWifi.objects.exists())

    def test_missing_profile_is_created(self):
        PerfilWifi.objects.filter(user=self.user).delete()
        self.assertTrue(authorize_client(self.user).success)
        self.assertTrue(PerfilWifi.objects.filter(user=self.user).exists())

    def test_revoke_closes_all_user_sessions_only(self):
        other = User.objects.create_user("outro")
        authorize_client(other)
        authorize_client(self.user, ip_address="10.10.0.50")
        authorize_client(self.user, ip_address="10.10.0.51")
        result = revoke_client(self.user)
        self.assertTrue(result.success)
        self.assertFalse(result.session.ativa)
        self.assertIsNotNone(result.session.encerrada_em)
        self.assertFalse(SessaoWifi.objects.filter(usuario=self.user, ativa=True).exists())
        self.assertTrue(SessaoWifi.objects.filter(usuario=other, ativa=True).exists())
        self.assertEqual(LogAcesso.objects.get(evento=LogAcesso.Evento.REVOGACAO_WIFI).detalhes["sessoes_encerradas"], 2)

    def test_revoke_can_target_specific_client(self):
        first = authorize_client(self.user, ip_address="10.10.0.50", mac_address="AA:BB:CC:DD:EE:FF").session
        second = authorize_client(self.user, ip_address="10.10.0.51").session
        revoke_client(self.user, mac_address="aa-bb-cc-dd-ee-ff")
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertFalse(first.ativa)
        self.assertTrue(second.ativa)
        revoke_client(self.user, ip_address="10.10.0.51")
        second.refresh_from_db()
        self.assertFalse(second.ativa)

    def test_invalid_revoke_identifiers_do_not_revoke_everything(self):
        session = authorize_client(self.user).session
        self.assertFalse(revoke_client(self.user, mac_address="inválido").success)
        self.assertFalse(revoke_client(self.user, ip_address="inválido").success)
        session.refresh_from_db()
        self.assertTrue(session.ativa)

    def test_revoke_is_idempotent(self):
        authorize_client(self.user)
        revoke_client(self.user)
        session = SessaoWifi.objects.get()
        ended = session.encerrada_em
        self.assertTrue(revoke_client(self.user).success)
        session.refresh_from_db()
        self.assertEqual(session.encerrada_em, ended)

    def test_encerrar_method(self):
        session = authorize_client(self.user).session
        session.encerrar()
        session.refresh_from_db()
        self.assertFalse(session.ativa)
        self.assertIsNotNone(session.encerrada_em)
        ended = session.encerrada_em
        session.encerrar()
        self.assertEqual(session.encerrada_em, ended)

    def test_mac_normalization(self):
        for value in ["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", " aa-bb-cc-dd-ee-ff "]:
            self.assertEqual(normalize_mac(value), "AA:BB:CC:DD:EE:FF")
        for value in [None, "", "inválido", "GG:BB:CC:DD:EE:FF", "AA:BB"]:
            self.assertEqual(normalize_mac(value), "")

    def test_device_normalizes_mac_on_save(self):
        device = Dispositivo.objects.create(usuario=self.user, mac_address="aa-bb-cc-dd-ee-ff")
        device.refresh_from_db()
        self.assertEqual(device.mac_address, "AA:BB:CC:DD:EE:FF")

    def test_client_ip_forwarded_first_and_fallback(self):
        factory = RequestFactory()
        request = factory.get("/", HTTP_X_FORWARDED_FOR="10.10.0.50, 10.10.0.1", REMOTE_ADDR="127.0.0.1")
        self.assertEqual(get_client_ip(request), "10.10.0.50")
        request.META["HTTP_X_FORWARDED_FOR"] = "inválido"
        self.assertEqual(get_client_ip(request), "127.0.0.1")
        request.META.pop("HTTP_X_FORWARDED_FOR")
        self.assertEqual(get_client_ip(request), "127.0.0.1")
        request.META["REMOTE_ADDR"] = "inválido"
        self.assertIsNone(get_client_ip(request))

    def test_authorization_uses_request_ip_and_rejects_invalid_metadata(self):
        request = RequestFactory().get("/", REMOTE_ADDR="::1")
        result = authorize_client(self.user, request=request, mac_address="inválido")
        self.assertEqual(result.session.ip_address, "::1")
        self.assertEqual(result.session.mac_address, "")
        self.assertIsNone(authorize_client(self.user, ip_address="inválido").session.ip_address)

    def test_logs_survive_user_deletion(self):
        authorize_client(self.user)
        self.user.delete()
        self.assertIsNone(LogAcesso.objects.get().usuario)

import logging
import urllib.parse
from unittest.mock import patch, MagicMock

import requests
from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.portal.models import LogAcesso, PerfilWifi, SessaoWifi, Dispositivo
from apps.portal.moonshield import moonshield_client, MoonShieldUnavailable, MoonShieldRejected, MoonShieldProtocolError
from apps.portal.services import authorize_client, revoke_client

class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code
        self.ok = status_code < 400

    def json(self):
        if self.json_data is None:
            raise ValueError("No JSON object could be decoded")
        return self.json_data


class MoonShieldTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='pedro', password='password123')
        self.ip = '10.10.0.137'
        self.mac = 'AA:BB:CC:11:22:33'

    # 1. Configuração desabilitada
    @override_settings(MOONSHIELD_API_ENABLED=False)
    @patch('requests.request')
    def test_configuracao_desabilitada(self, mock_req):
        res = moonshield_client.authorize(self.user.username, self.ip)
        self.assertTrue(res['ok'])
        mock_req.assert_not_called()

    # 2, 3, 4, 5, 6, 7. authorize sucesso, payload limpo, sem senha/mac, token, timeout
    @override_settings(MOONSHIELD_API_ENABLED=True, MOONSHIELD_API_TOKEN='test_token', MOONSHIELD_API_TIMEOUT=3)
    @patch('requests.request')
    def test_authorize_sucesso_e_payload(self, mock_req):
        mock_req.return_value = MockResponse({"ok": True, "authorization_id": 99}, 200)


        
        res = moonshield_client.authorize('pedro', self.ip)
        self.assertTrue(res['ok'])
        
        mock_req.assert_called_once()
        args, kwargs = mock_req.call_args
        
        self.assertEqual(args[0], 'POST')
        self.assertEqual(kwargs['timeout'], 3)
        self.assertEqual(kwargs['headers']['Authorization'], 'Bearer test_token')
        
        payload = kwargs['json']
        self.assertIn('username', payload)
        self.assertIn('ip_address', payload)
        self.assertNotIn('password', payload)
        self.assertNotIn('senha', payload)
        self.assertNotIn('mac', payload)
        self.assertNotIn('mac_address', payload)

    # 8. Timeout remoto
    @override_settings(MOONSHIELD_API_ENABLED=True)
    @patch('requests.request', side_effect=requests.exceptions.Timeout)
    def test_timeout_remoto(self, mock_req):
        with self.assertRaises(MoonShieldUnavailable):
            moonshield_client.authorize('pedro', self.ip)

    # 9. connection refused
    @override_settings(MOONSHIELD_API_ENABLED=True)
    @patch('requests.request', side_effect=requests.exceptions.ConnectionError)
    def test_connection_refused(self, mock_req):
        with self.assertRaises(MoonShieldUnavailable):
            moonshield_client.authorize('pedro', self.ip)

    # 10. 400
    @override_settings(MOONSHIELD_API_ENABLED=True)
    @patch('requests.request')
    def test_400(self, mock_req):
        mock_req.return_value = MockResponse({"ok": False, "erro": "IP invalido"}, 400)
        with self.assertRaises(MoonShieldRejected):
            moonshield_client.authorize('pedro', self.ip)

    # 11. 401
    @override_settings(MOONSHIELD_API_ENABLED=True)
    @patch('requests.request')
    def test_401(self, mock_req):
        mock_req.return_value = MockResponse({"ok": False, "erro": "Token invalido"}, 401)
        with self.assertRaises(MoonShieldProtocolError):
            moonshield_client.authorize('pedro', self.ip)

    # 12. 403
    @override_settings(MOONSHIELD_API_ENABLED=True)
    @patch('requests.request')
    def test_403(self, mock_req):
        mock_req.return_value = MockResponse({"ok": False, "erro": "Origem nao permitida"}, 403)
        with self.assertRaises(MoonShieldProtocolError):
            moonshield_client.authorize('pedro', self.ip)

    # 13. 500
    @override_settings(MOONSHIELD_API_ENABLED=True)
    @patch('requests.request')
    def test_500(self, mock_req):
        mock_req.return_value = MockResponse({"ok": False, "erro": "Erro interno"}, 500)
        with self.assertRaises(MoonShieldUnavailable):
            moonshield_client.authorize('pedro', self.ip)

    # 14. 503
    @override_settings(MOONSHIELD_API_ENABLED=True)
    @patch('requests.request')
    def test_503(self, mock_req):
        mock_req.return_value = MockResponse({"ok": False, "erro": "Servico indisponivel"}, 503)
        with self.assertRaises(MoonShieldUnavailable):
            moonshield_client.authorize('pedro', self.ip)

    # 15. JSON invalido
    @override_settings(MOONSHIELD_API_ENABLED=True)
    @patch('requests.request')
    def test_json_invalido(self, mock_req):
        mock_req.return_value = MockResponse(None, 200)
        with self.assertRaises(MoonShieldProtocolError):
            moonshield_client.authorize('pedro', self.ip)

    # 16. resposta valida
    @override_settings(MOONSHIELD_API_ENABLED=True)
    @patch('requests.request')
    def test_resposta_valida(self, mock_req):
        mock_req.return_value = MockResponse({"ok": True, "authorization_id": 123}, 200)
        res = moonshield_client.authorize('pedro', self.ip)
        self.assertTrue(res['ok'])
        self.assertEqual(res['authorization_id'], 123)

    # 17. login valido + MoonShield OK
    @override_settings(MOONSHIELD_API_ENABLED=True)
    @patch('apps.portal.moonshield.MoonShieldClient.authorize')
    def test_login_valido_moonshield_ok(self, mock_auth):
        mock_auth.return_value = {"ok": True, "authorization_id": 123}
        res = self.client.post(reverse('portal:login'), {'username': 'pedro', 'password': 'password123'}, REMOTE_ADDR=self.ip)
        self.assertRedirects(res, reverse('portal:home'))
        self.assertTrue(SessaoWifi.objects.filter(usuario=self.user, ip_address=self.ip, ativa=True).exists())

    # 18. login valido + MoonShield indisponível
    @override_settings(MOONSHIELD_API_ENABLED=True)
    @patch('apps.portal.moonshield.MoonShieldClient.authorize', side_effect=MoonShieldUnavailable("Erro"))
    def test_login_valido_moonshield_indisponivel(self, mock_auth):
        res = self.client.post(reverse('portal:login'), {'username': 'pedro', 'password': 'password123'}, REMOTE_ADDR=self.ip)
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Não foi possível liberar o acesso")
        self.assertFalse(SessaoWifi.objects.filter(usuario=self.user, ip_address=self.ip, ativa=True).exists())

    # 19. login invalido
    @override_settings(MOONSHIELD_API_ENABLED=True)
    @patch('apps.portal.moonshield.MoonShieldClient.authorize')
    def test_login_invalido_nao_chama(self, mock_auth):
        res = self.client.post(reverse('portal:login'), {'username': 'pedro', 'password': 'err'}, REMOTE_ADDR=self.ip)
        self.assertEqual(res.status_code, 200)
        mock_auth.assert_not_called()

    # 20. logout chama revoke
    @override_settings(MOONSHIELD_API_ENABLED=True)
    @patch('apps.portal.moonshield.MoonShieldClient.revoke')
    @patch('apps.portal.moonshield.MoonShieldClient.authorize')
    def test_logout_chama_revoke(self, mock_auth, mock_revoke):
        mock_auth.return_value = {"ok": True, "authorization_id": 123}
        self.client.post(reverse('portal:login'), {'username': 'pedro', 'password': 'password123'}, REMOTE_ADDR=self.ip)
        
        self.client.post(reverse('portal:logout'))
        mock_revoke.assert_called_with(self.ip, reason='Revogação via portal')
        self.assertFalse(SessaoWifi.objects.filter(usuario=self.user, ip_address=self.ip, ativa=True).exists())

    # 21. bloqueio administrativo chama revoke
    @override_settings(MOONSHIELD_API_ENABLED=True)
    @patch('apps.portal.moonshield.MoonShieldClient.revoke')
    @patch('apps.portal.moonshield.MoonShieldClient.authorize')
    def test_bloqueio_admin_chama_revoke(self, mock_auth, mock_revoke):
        mock_auth.return_value = {"ok": True, "authorization_id": 123}
        self.client.post(reverse('portal:login'), {'username': 'pedro', 'password': 'password123'}, REMOTE_ADDR=self.ip)
        
        admin = User.objects.create_superuser('admin', 'admin@example.com', 'adminpass')
        self.client.force_login(admin)
        self.client.post(reverse('portal:block_user', args=[self.user.id]))
        mock_revoke.assert_called_with(self.ip, reason='Revogação via portal')

    # 22. dev IP override
    @override_settings(DEBUG=True, MOONSHIELD_DEV_CLIENT_IP='10.10.0.99')
    def test_dev_ip_override(self):
        ip = moonshield_client._resolve_ip('127.0.0.1')
        self.assertEqual(ip, '10.10.0.99')

    # 23. dev IP ignorado em false
    @override_settings(DEBUG=False, MOONSHIELD_DEV_CLIENT_IP='10.10.0.99')
    def test_dev_ip_ignorado(self):
        ip = moonshield_client._resolve_ip('127.0.0.1')
        self.assertEqual(ip, '127.0.0.1')

    # 24. token não em msg
    @override_settings(MOONSHIELD_API_ENABLED=True, MOONSHIELD_API_TOKEN='SECRET_TOKEN')
    @patch('requests.request', side_effect=requests.exceptions.ConnectionError("Connection err"))
    def test_token_nao_vaza(self, mock_req):
        try:
            moonshield_client.authorize('pedro', self.ip)
        except Exception as e:
            self.assertNotIn('SECRET_TOKEN', str(e))

    # 25. desabilitado preserva o comportamento
    @override_settings(MOONSHIELD_API_ENABLED=False)
    @patch('requests.request')
    def test_desabilitado_preserva(self, mock_req):
        res = self.client.post(reverse('portal:login'), {'username': 'pedro', 'password': 'password123'}, REMOTE_ADDR=self.ip)
        self.assertRedirects(res, reverse('portal:home'))
        mock_req.assert_not_called()
        self.assertTrue(SessaoWifi.objects.filter(usuario=self.user, ip_address=self.ip, ativa=True).exists())

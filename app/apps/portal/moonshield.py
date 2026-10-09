import logging
import urllib.parse
from urllib.error import URLError

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

class MoonShieldError(Exception):
    pass

class MoonShieldUnavailable(MoonShieldError):
    pass

class MoonShieldRejected(MoonShieldError):
    pass

class MoonShieldProtocolError(MoonShieldError):
    pass

class MoonShieldClient:
    @property
    def enabled(self):
        return getattr(settings, "MOONSHIELD_API_ENABLED", False)

    @property
    def base_url(self):
        return getattr(settings, "MOONSHIELD_API_URL", "").rstrip("/")

    @property
    def token(self):
        return getattr(settings, "MOONSHIELD_API_TOKEN", "")

    @property
    def timeout(self):
        return getattr(settings, "MOONSHIELD_API_TIMEOUT", 5)

    def _get_headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _resolve_ip(self, ip_address):
        """Override IP in development if configured."""
        if getattr(settings, "DEBUG", False):
            dev_ip = getattr(settings, "MOONSHIELD_DEV_CLIENT_IP", "").strip()
            if dev_ip:
                return dev_ip
        return ip_address

    def _request(self, method, endpoint, **kwargs):
        if not self.enabled:
            return None
            
        url = f"{self.base_url}{endpoint}"
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("headers", self._get_headers())
        
        try:
            response = requests.request(method, url, **kwargs)
        except requests.exceptions.Timeout:
            raise MoonShieldUnavailable("O servidor de firewall demorou muito para responder.")
        except requests.exceptions.ConnectionError:
            raise MoonShieldUnavailable("Não foi possível conectar ao servidor de firewall.")
        except requests.exceptions.RequestException as e:
            raise MoonShieldProtocolError("Erro de rede ao comunicar com o servidor de firewall.")
            
        try:
            data = response.json()
        except ValueError:
            raise MoonShieldProtocolError("Resposta inválida (não-JSON) do servidor de firewall.")
            
        if not response.ok:
            error_code = data.get("codigo") if isinstance(data, dict) else None
            error_msg = data.get("erro", "Erro desconhecido") if isinstance(data, dict) else "Erro desconhecido"
            if response.status_code in (401, 403):
                raise MoonShieldProtocolError(f"Acesso negado na API do MoonShield: {error_msg}")
            elif response.status_code == 400:
                raise MoonShieldRejected(f"Falha na autorização: {error_msg}")
            elif response.status_code >= 500:
                raise MoonShieldUnavailable(f"O servidor de firewall está indisponível: {error_msg}")
            else:
                raise MoonShieldRejected(f"Erro {response.status_code} na autorização: {error_msg}")
                
        return data

    def authorize(self, username, ip_address):
        if not self.enabled:
            return {"ok": True, "authorization_id": "mock_auth_id_123"}
            
        resolved_ip = self._resolve_ip(ip_address)
        payload = {
            "username": username,
            "ip_address": resolved_ip,
        }
        
        response_data = self._request("POST", "/wifi/api/authorize/", json=payload)
        
        if not response_data or not response_data.get("ok"):
            # Should not reach here if exceptions are raised properly, but just in case
            raise MoonShieldRejected("Autorização rejeitada pelo firewall.")
            
        return response_data

    def revoke(self, ip_address, authorization_id=None, reason=""):
        if not self.enabled:
            return {"ok": True, "revoked": True}
            
        resolved_ip = self._resolve_ip(ip_address)
        payload = {
            "ip_address": resolved_ip,
            "authorization_id": authorization_id,
            "revoked_reason": reason,
        }
        
        return self._request("POST", "/wifi/api/revoke/", json=payload)

    def status(self, ip_address):
        if not self.enabled:
            return {"ok": True, "active": True}
            
        resolved_ip = self._resolve_ip(ip_address)
        return self._request("GET", f"/wifi/api/status/?ip_address={urllib.parse.quote(resolved_ip)}")

moonshield_client = MoonShieldClient()

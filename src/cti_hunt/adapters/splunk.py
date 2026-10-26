import json
import os
import urllib.request
import urllib.parse
from urllib.error import URLError, HTTPError
from typing import Any

class SplunkError(Exception):
    pass


class LocalOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SplunkError("Từ chối redirect từ Splunk; chỉ gọi endpoint tìm kiếm localhost đã chọn")


class SplunkConnection:
    """Connects to Splunk REST API using standard urllib. ONLY allows localhost."""
    def __init__(self, host: str, port: int = 8089):
        if host not in ("localhost", "127.0.0.1"):
            raise ValueError(f"Chỉ cho phép kết nối Splunk tại localhost/127.0.0.1, từ chối host: {host}")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("Cổng Splunk không hợp lệ")
        
        self.host = host
        self.port = port
        self.base_url = f"https://{self.host}:{self.port}"
        
        # Lấy thông tin đăng nhập từ biến môi trường
        username = os.environ.get("SPLUNK_USER")
        password = os.environ.get("SPLUNK_PASS")
        if not username or not password:
            raise ValueError("Thiếu biến môi trường SPLUNK_USER hoặc SPLUNK_PASS")
        
        import base64
        creds = f"{username}:{password}".encode("utf-8")
        self.auth_header = f"Basic {base64.b64encode(creds).decode('ascii')}"
        
        # Bypass SSL verification since Splunk locally uses self-signed cert
        import ssl
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.ssl_context), LocalOnlyRedirect())

    def search(self, spl: str, earliest_time: str = "-24h", latest_time: str = "now") -> list[dict[str, Any]]:
        """Thực thi câu truy vấn SPL (đồng bộ, xuất JSON) và trả về danh sách sự kiện."""
        # Splunk requires SPL searches to start with "search "
        if not spl.strip().startswith("search") and not spl.strip().startswith("|"):
            spl = "search " + spl
            
        endpoint = f"{self.base_url}/services/search/jobs/export"
        data = urllib.parse.urlencode({
            "search": spl,
            "output_mode": "json",
            "earliest_time": earliest_time,
            "latest_time": latest_time
        }).encode("utf-8")
        
        req = urllib.request.Request(endpoint, data=data, method="POST")
        req.add_header("Authorization", self.auth_header)
        
        results = []
        try:
            with self.opener.open(req, timeout=30) as response:
                for line in response:
                    line = line.decode("utf-8").strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if not isinstance(obj, dict):
                            raise SplunkError("Splunk export có dòng không phải object")
                        for message in obj.get("messages", []):
                            if message.get("type", "").upper() in ("WARN", "WARNING", "ERROR", "FATAL"):
                                raise SplunkError("Splunk báo lỗi: " + str(message.get("text", "")))
                        if "error" in obj:
                            raise SplunkError("Splunk export trả lỗi")
                        if "result" in obj and not obj.get("preview", False):
                            if not isinstance(obj["result"], dict):
                                raise SplunkError("Splunk result không phải object")
                            results.append(obj["result"])
                    except json.JSONDecodeError:
                        raise SplunkError("Splunk export có dòng JSON không hợp lệ; không coi là kết quả rỗng")
            return results
        except HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            raise SplunkError(f"HTTP {e.code}: {e.reason}\n{error_body}")
        except URLError as e:
            raise SplunkError(f"Lỗi kết nối Splunk: {e.reason}")

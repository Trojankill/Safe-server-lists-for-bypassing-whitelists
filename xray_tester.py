#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import subprocess
import tempfile
import time
import socket
import threading
import atexit
import signal
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Optional, Dict
from urllib.parse import urlparse, parse_qs

# ------------------------------------------------------------------
# Простой логгер (без внешних зависимостей)
# ------------------------------------------------------------------
def log(msg):
    print(msg)

# ------------------------------------------------------------------
# Проверка наличия curl_cffi (опционально, для ускорения)
# ------------------------------------------------------------------
try:
    from curl_cffi.requests import Session as CurlSession
    CURL_CFFI_AVAILABLE = True
except ImportError:
    CURL_CFFI_AVAILABLE = False
    CurlSession = None

# ------------------------------------------------------------------
# Очистка процессов при выходе
# ------------------------------------------------------------------
_active_testers = []
_cleanup_lock = threading.Lock()

def _cleanup_all():
    with _cleanup_lock:
        for tester in _active_testers[:]:
            try:
                tester.cleanup()
            except Exception:
                pass

atexit.register(_cleanup_all)

def _signal_handler(signum, frame):
    _cleanup_all()
    sys.exit(1)

try:
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
except Exception:
    pass

# ------------------------------------------------------------------
# Класс XrayTester (ускоренная версия)
# ------------------------------------------------------------------
class XrayTester:
    TEST_URLS = ["https://www.google.com/generate_204"]
    BASE_PORT = 20000
    PORT_RANGE_END = 21000

    def __init__(self, xray_path: str = None):
        self.xray_path = xray_path or self._find_xray()
        self._running_processes = []
        self._config_files = {}
        self._process_lock = threading.Lock()
        self._port_counter = [self.BASE_PORT]
        self._port_lock = threading.Lock()
        with _cleanup_lock:
            _active_testers.append(self)

    def _find_xray(self) -> str:
        xray_exe = "xray.exe" if sys.platform == "win32" else "xray"
        possible = [
            os.path.join(os.path.dirname(__file__), "xray", xray_exe),
            xray_exe,
        ]
        for p in possible:
            if os.path.exists(p):
                return os.path.abspath(p)
        return "xray"

    def _get_next_port(self) -> int:
        with self._port_lock:
            port = self._port_counter[0]
            self._port_counter[0] = port + 1
            if self._port_counter[0] >= self.PORT_RANGE_END:
                self._port_counter[0] = self.BASE_PORT
            return port

    def _wait_for_port(self, port: int, timeout: float = 1.0) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                if sock.connect_ex(('127.0.0.1', port)) == 0:
                    sock.close()
                    return True
                sock.close()
            except Exception:
                pass
            time.sleep(0.05)
        return False

    def _parse_vless(self, url: str, tag: str) -> Optional[Dict]:
        try:
            # vless://uuid@host:port?params#name
            url_part = url.replace('vless://', '', 1)
            if '#' in url_part:
                url_part = url_part.split('#', 1)[0]
            if '?' in url_part:
                base, query_str = url_part.split('?', 1)
            else:
                base, query_str = url_part, ''
            if '@' not in base:
                return None
            uuid, host_port = base.rsplit('@', 1)
            if ':' not in host_port:
                return None
            host, port_str = host_port.rsplit(':', 1)
            port = int(port_str.split('/')[0])
            params = parse_qs(query_str)
            security = params.get('security', ['none'])[0]
            outbound = {
                "tag": tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{
                            "id": uuid,
                            "encryption": params.get('encryption', ['none'])[0],
                            "flow": params.get('flow', [''])[0]
                        }]
                    }]
                },
                "streamSettings": {
                    "network": params.get('type', ['tcp'])[0],
                    "security": security
                }
            }
            if security == 'tls':
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": params.get('sni', [host])[0],
                    "fingerprint": params.get('fp', ['chrome'])[0]
                }
            elif security == 'reality':
                outbound["streamSettings"]["realitySettings"] = {
                    "serverName": params.get('sni', [''])[0],
                    "fingerprint": params.get('fp', ['chrome'])[0],
                    "publicKey": params.get('pbk', [''])[0],
                    "shortId": params.get('sid', [''])[0]
                }
            return outbound
        except Exception:
            return None

    def _parse_trojan(self, url: str, tag: str) -> Optional[Dict]:
        try:
            url_part = url.replace('trojan://', '', 1)
            if '#' in url_part:
                url_part = url_part.split('#', 1)[0]
            if '?' in url_part:
                url_part = url_part.split('?', 1)[0]
            if '@' not in url_part:
                return None
            password, host_port = url_part.rsplit('@', 1)
            if ':' not in host_port:
                return None
            host, port_str = host_port.rsplit(':', 1)
            port = int(port_str)
            return {
                "tag": tag,
                "protocol": "trojan",
                "settings": {"servers": [{"address": host, "port": port, "password": password}]},
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {"serverName": host}
                }
            }
        except Exception:
            return None

    def _url_to_outbound(self, url: str, tag: str) -> Optional[Dict]:
        if url.startswith('vless://'):
            return self._parse_vless(url, tag)
        if url.startswith('trojan://'):
            return self._parse_trojan(url, tag)
        return None

    def create_config(self, url: str, socks_port: int) -> Optional[Dict]:
        out = self._url_to_outbound(url, "proxy")
        if not out:
            return None
        return {
            "log": {"loglevel": "error"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "mixed",
                "settings": {"auth": "noauth", "udp": True}
            }],
            "outbounds": [out, {"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [{"type": "field", "inboundTag": ["mixed"], "outboundTag": "proxy"}]}
        }

    def start_xray(self, config: Dict, socks_port: int) -> Tuple[bool, Optional[subprocess.Popen], str]:
        try:
            config_json = json.dumps(config, separators=(',', ':'))
            fd, conf_file = tempfile.mkstemp(suffix='.json', prefix='xray_')
            os.chmod(conf_file, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(config_json)
            proc = subprocess.Popen(
                [self.xray_path, "run", "-config", conf_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(0.3)  # сокращённое ожидание
            if proc.poll() is not None:
                os.unlink(conf_file)
                return False, None, "Xray exit"
            if not self._wait_for_port(socks_port, timeout=1.0):
                proc.terminate()
                proc.wait(timeout=2)
                os.unlink(conf_file)
                return False, None, "Port timeout"
            with self._process_lock:
                self._running_processes.append(proc)
                self._config_files[proc.pid] = conf_file
            return True, proc, ""
        except Exception as e:
            return False, None, str(e)

    def stop_xray(self, proc: subprocess.Popen):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        conf = self._config_files.pop(proc.pid, None)
        if conf and os.path.exists(conf):
            os.unlink(conf)
        with self._process_lock:
            if proc in self._running_processes:
                self._running_processes.remove(proc)

    def _http_test(self, socks_port: int, timeout: float) -> Tuple[bool, float]:
        # Приоритет: curl_cffi если есть
        if CURL_CFFI_AVAILABLE:
            try:
                proxy = f"socks5://127.0.0.1:{socks_port}"
                session = CurlSession(impersonate="chrome")
                start = time.perf_counter()
                resp = session.get(self.TEST_URLS[0], proxy=proxy, timeout=timeout)
                lat = (time.perf_counter() - start) * 1000
                if resp.status_code == 204:
                    return True, lat
            except Exception:
                pass
        # fallback на requests (если установлен) или простой сокет
        try:
            import requests
            proxies = {"http": f"socks5h://127.0.0.1:{socks_port}", "https": f"socks5h://127.0.0.1:{socks_port}"}
            start = time.perf_counter()
            r = requests.get(self.TEST_URLS[0], proxies=proxies, timeout=timeout)
            lat = (time.perf_counter() - start) * 1000
            if r.status_code == 204:
                return True, lat
        except ImportError:
            # последняя попытка: через socket напрямую (только TCP, не HTTP)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect(('127.0.0.1', socks_port))
                sock.send(b"GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\n\r\n")
                data = sock.recv(1024)
                if b"204" in data:
                    return True, 0.0
            except Exception:
                pass
        return False, 0.0

    def test_single(self, url: str, timeout: float = 5.0) -> Tuple[str, bool, float]:
        port = self._get_next_port()
        config = self.create_config(url, port)
        if not config:
            return (url, False, 0.0)
        ok, proc, err = self.start_xray(config, port)
        if not ok:
            return (url, False, 0.0)
        try:
            success, latency = self._http_test(port, timeout)
            return (url, success, latency if success else 0.0)
        finally:
            self.stop_xray(proc)

    def test_batch(self, urls: List[str], concurrency: int = 20, timeout: float = 5.0) -> List[Tuple[str, bool, float]]:
        results = []
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = {ex.submit(self.test_single, url, timeout): url for url in urls}
            for fut in futures:
                try:
                    res = fut.result(timeout=timeout+2)
                    results.append(res)
                except Exception:
                    results.append((futures[fut], False, 0.0))
        return results

    def cleanup(self):
        with self._process_lock:
            for proc in self._running_processes[:]:
                self.stop_xray(proc)
        with _cleanup_lock:
            if self in _active_testers:
                _active_testers.remove(self)

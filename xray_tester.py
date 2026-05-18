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
import re
import asyncio
import requests
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from typing import List, Tuple, Optional, Dict
from urllib.parse import urlparse, parse_qs, unquote
from urllib3.util.retry import Retry
import base64
import multiprocessing

# ------------------------------------------------------------------
# Логгер (замена утилитному)
# ------------------------------------------------------------------
def log(msg):
    print(msg)

# ------------------------------------------------------------------
# Настройки по умолчанию (замена config.settings)
# ------------------------------------------------------------------
VALIDATION_HTTP_TIMEOUT = 8.0
ASYNC_CONCURRENCY_WIN32 = 50
ASYNC_CONCURRENCY_LINUX = 150

# ------------------------------------------------------------------
# Проверка наличия curl_cffi (опционально)
# ------------------------------------------------------------------
try:
    from curl_cffi.requests import Session as CurlSession, AsyncSession
    CURL_CFFI_AVAILABLE = True
except ImportError:
    CURL_CFFI_AVAILABLE = False
    CurlSession = None
    AsyncSession = None

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ------------------------------------------------------------------
# Глобальная регистрация для очистки при выходе
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
# Класс XrayTester (основной)
# ------------------------------------------------------------------
class XrayTester:
    TEST_URLS = ["https://www.google.com/generate_204"]
    DEFAULT_TIMEOUT = 5.0
    BASE_PORT = 20000
    BATCH_PORT_END = 21999
    CHAIN_PORT_START = 22000
    CHAIN_PORT_END = 23999
    PERSISTENT_PORT_START = 24000
    BATCH_SIZE = 100
    MAX_BATCH_SIZE = 150
    MIN_BATCH_SIZE = 50

    def __init__(self, xray_path: str = None):
        self.xray_path = xray_path or self._find_xray()
        self._running_processes: List[subprocess.Popen] = []
        self._config_files: dict = {}
        self._process_lock = threading.Lock()
        self._port_counter = [self.BASE_PORT]
        self._port_lock = threading.Lock()
        self._error_stats = {}
        self._error_samples = {}
        self._error_stats_lock = threading.Lock()
        with _cleanup_lock:
            _active_testers.append(self)

    def _find_xray(self) -> str:
        xray_exe = "xray.exe" if sys.platform == "win32" else "xray"
        possible_paths = [
            os.path.join(os.path.dirname(__file__), "xray", xray_exe),
            xray_exe,
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return os.path.abspath(path)
        return "xray"

    def _get_next_port(self) -> int:
        max_attempts = 10
        for _ in range(max_attempts):
            with self._port_lock:
                port = self._port_counter[0]
                if self.CHAIN_PORT_START <= port <= self.CHAIN_PORT_END:
                    port = self.CHAIN_PORT_END + 1
                    self._port_counter[0] = port
                elif port >= self.PERSISTENT_PORT_START:
                    port = self.BASE_PORT
                    self._port_counter[0] = port
                self._port_counter[0] += 1
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('127.0.0.1', port))
                sock.close()
                return port
            except OSError:
                continue
        raise RuntimeError("No available port")

    def _wait_for_port(self, port: int, timeout: float = 1.5) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                if result == 0:
                    return True
            except Exception:
                pass
            time.sleep(0.05)
        return False

    # ---------- Парсинг URL в outbound (для VLESS, Trojan, Shadowsocks, VMess) ----------
    def _parse_vless_to_outbound(self, url: str, tag: str) -> Optional[Dict]:
        try:
            url_part = url.replace('vless://', '', 1)
            if '#' in url_part:
                url_part, _ = url_part.split('#', 1)
            if '?' in url_part:
                base_part, query_part = url_part.split('?', 1)
            else:
                base_part = url_part
                query_part = ''
            if '@' not in base_part:
                return None
            uuid, host_port = base_part.rsplit('@', 1)
            if ':' not in host_port:
                return None
            hostname, port_str = host_port.rsplit(':', 1)
            port = int(port_str.strip().rstrip('/'))
            params = parse_qs(query_part)
            security = params.get('security', ['none'])[0]
            outbound = {
                "tag": tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": hostname,
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
                    "serverName": params.get('sni', [hostname])[0],
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

    def _parse_trojan_to_outbound(self, url: str, tag: str) -> Optional[Dict]:
        try:
            url_part = url.replace('trojan://', '', 1)
            if '#' in url_part:
                url_part, _ = url_part.split('#', 1)
            if '?' in url_part:
                url_part, _ = url_part.split('?', 1)
            if '@' not in url_part:
                return None
            password, host_port = url_part.rsplit('@', 1)
            if ':' not in host_port:
                return None
            hostname, port_str = host_port.rsplit(':', 1)
            port = int(port_str.strip())
            return {
                "tag": tag,
                "protocol": "trojan",
                "settings": {"servers": [{"address": hostname, "port": port, "password": password}]},
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {"serverName": hostname}
                }
            }
        except Exception:
            return None

    # Для простоты добавим заглушки для VMess и Shadowsocks (можно опустить, если не нужны)
    def _parse_vmess_to_outbound(self, url: str, tag: str) -> Optional[Dict]:
        # VMess – можно не поддерживать, если все твои источники только VLESS/Trojan
        return None

    def _parse_shadowsocks_to_outbound(self, url: str, tag: str) -> Optional[Dict]:
        return None

    def _url_to_outbound(self, url: str, tag: str) -> Optional[Dict]:
        if url.startswith('vless://'):
            return self._parse_vless_to_outbound(url, tag)
        if url.startswith('trojan://'):
            return self._parse_trojan_to_outbound(url, tag)
        return None

    def create_single_outbound_config(self, url: str, socks_port: int) -> Optional[Dict]:
        outbound = self._url_to_outbound(url, "proxy")
        if not outbound:
            return None
        return {
            "log": {"loglevel": "error"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "mixed",
                "settings": {"auth": "noauth", "udp": True}
            }],
            "outbounds": [outbound, {"tag": "direct", "protocol": "freedom"}],
            "routing": {
                "rules": [{"type": "field", "inboundTag": ["mixed"], "outboundTag": "proxy"}]
            }
        }

    def start_xray_instance(self, config: Dict, socks_port: int, verbose: bool = False) -> Tuple[bool, Optional[subprocess.Popen], str]:
        try:
            config_json = json.dumps(config, separators=(',', ':'))
            fd, config_file = tempfile.mkstemp(suffix='.json', prefix='xray_')
            os.chmod(config_file, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(config_json)
            cmd = [self.xray_path, "run", "-config", config_file]
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)
            if process.poll() is not None:
                os.unlink(config_file)
                return False, None, "Xray exited immediately"
            if not self._wait_for_port(socks_port, timeout=3.0):
                process.terminate()
                process.wait(timeout=2)
                os.unlink(config_file)
                return False, None, "Port not listening"
            with self._process_lock:
                self._running_processes.append(process)
                self._config_files[process.pid] = config_file
            return True, process, ""
        except Exception as e:
            return False, None, str(e)

    def stop_xray_process(self, process: subprocess.Popen):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        config_file = self._config_files.pop(process.pid, None)
        if config_file and os.path.exists(config_file):
            os.unlink(config_file)
        with self._process_lock:
            if process in self._running_processes:
                self._running_processes.remove(process)

    def test_through_socks(self, socks_port: int, timeout: float, verbose: bool = False) -> Tuple[bool, float]:
        # Используем requests с socks5h
        session = requests.Session()
        session.trust_env = False
        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}", "https": f"socks5h://127.0.0.1:{socks_port}"}
        for test_url in self.TEST_URLS:
            try:
                start = time.perf_counter()
                resp = session.get(test_url, proxies=proxies, timeout=timeout, allow_redirects=True)
                latency = (time.perf_counter() - start) * 1000
                if resp.status_code == 204:
                    return True, latency
            except Exception:
                continue
        return False, 0.0

    def test_batch(self, urls: List[str], concurrency: int = 50, timeout: float = 8.0, verbose: bool = False) -> List[Tuple[str, bool, float]]:
        # Упрощённая версия: последовательный запуск с ограничением параллелизма через ThreadPoolExecutor
        results = []
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(self._test_single, url, timeout): url for url in urls}
            for future in futures:
                try:
                    res = future.result(timeout=timeout+5)
                    results.append(res)
                except Exception:
                    results.append((futures[future], False, 0.0))
        return results

    def _test_single(self, url: str, timeout: float) -> Tuple[str, bool, float]:
        socks_port = self._get_next_port()
        config = self.create_single_outbound_config(url, socks_port)
        if not config:
            return (url, False, 0.0)
        success, process, err = self.start_xray_instance(config, socks_port, verbose=False)
        if not success:
            return (url, False, 0.0)
        try:
            ok, latency = self.test_through_socks(socks_port, timeout)
            return (url, ok, latency if ok else 0.0)
        finally:
            self.stop_xray_process(process)

    def cleanup(self):
        with self._process_lock:
            for process in self._running_processes[:]:
                self.stop_xray_process(process)
        with _cleanup_lock:
            if self in _active_testers:
                _active_testers.remove(self)

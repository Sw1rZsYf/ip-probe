#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP Probe - 本地 IP 体检工具（类似 ping0.cc）

单文件、仅使用 Python 标准库。支持：
  * 检测当前公网 IPv4 / IPv6 出口
  * 查询任意 IP 的归属地、ASN、ASN 所有者、企业、经纬度
  * IP 类型、风控值、共享人数估算、原生 IP 推断、适用场景
  * 终端彩色报告 / JSON 输出 / 本地 Web 面板

数据源：ipwho.is、proxycheck.io、RIPEstat、RDAP、ipinfo.io、ip-api.com
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as _dt
import gzip
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterable, List, Optional, Tuple

APP_NAME = "ip-probe"
APP_TITLE = "IP PROBE"
VERSION = "1.0.1"
DEFAULT_TIMEOUT = 12.0
MAX_BODY = 2 * 1024 * 1024
USER_AGENT = (
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 "
    f"{APP_NAME}/{VERSION}"
)

DISCLAIMER = (
    "归属地/经纬度为城市级估算；共享人数、原生 IP、适用场景为多源推断，"
    "不是 ping0.cc 官方数据，也不构成精确风控结论。"
)

# ---------------------------------------------------------------------------
# 终端与文本工具
# ---------------------------------------------------------------------------

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class C:
    enabled = True
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_CYAN = "\033[96m"


def color(text: str, code: str) -> str:
    if not C.enabled or not code:
        return text
    return f"{code}{text}{C.RESET}"


def enable_windows_ansi() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        try:
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)
        except Exception:
            pass
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def setup_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def char_width(ch: str) -> int:
    if ch == "\t":
        return 4
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def disp_width(text: str) -> int:
    return sum(char_width(ch) for ch in strip_ansi(str(text)))


def truncate_disp(text: str, width: int) -> str:
    if width <= 0:
        return ""
    out = []
    used = 0
    for ch in str(text):
        w = char_width(ch)
        if used + w > width:
            break
        out.append(ch)
        used += w
    return "".join(out)


def pad_disp(text: str, width: int, align: str = "left") -> str:
    text = str(text)
    current = disp_width(text)
    if current > width:
        text = truncate_disp(text, width)
        current = disp_width(text)
    gap = max(0, width - current)
    if align == "right":
        return " " * gap + text
    if align == "center":
        left = gap // 2
        return " " * left + text + " " * (gap - left)
    return text + " " * gap


def _wrap_tokens(text: str) -> List[str]:
    tokens: List[str] = []
    buffer = ""
    for ch in text:
        if ch.isspace():
            if buffer:
                tokens.append(buffer)
                buffer = ""
            tokens.append(" ")
        elif char_width(ch) == 2 or ch in "，。！？；：、（）【】《》“”‘’":
            if buffer:
                tokens.append(buffer)
                buffer = ""
            tokens.append(ch)
        else:
            buffer += ch
    if buffer:
        tokens.append(buffer)
    return tokens


def wrap_disp(text: str, width: int) -> List[str]:
    if width <= 0:
        return [""]
    text = str(text).replace("\r\n", "\n").replace("\r", "\n")
    lines: List[str] = []
    for paragraph in text.split("\n"):
        if not paragraph:
            lines.append("")
            continue
        line = ""
        used = 0
        for token in _wrap_tokens(paragraph):
            if token == " ":
                if line and not line.endswith(" "):
                    line += " "
                    used += 1
                continue
            token_width = disp_width(token)
            if used + token_width <= width:
                line += token
                used += token_width
                continue
            if line.strip():
                lines.append(line.rstrip())
            line = ""
            used = 0
            if token_width <= width:
                line = token
                used = token_width
                continue
            # 超长单词/URL：按显示宽度硬切
            for ch in token:
                ch_width = char_width(ch)
                if line and used + ch_width > width:
                    lines.append(line.rstrip())
                    line = ""
                    used = 0
                line += ch
                used += ch_width
        if line.strip() or not lines:
            lines.append(line.rstrip())
    return lines or [""]


def contains_cjk(text: str) -> bool:
    return any("\u4e00" <= ch <= "\u9fff" for ch in str(text))


# ---------------------------------------------------------------------------
# 基础数据 / 常量
# ---------------------------------------------------------------------------

COUNTRY_ZH: Dict[str, str] = {
    "CN": "中国", "US": "美国", "JP": "日本", "KR": "韩国", "SG": "新加坡",
    "HK": "中国香港", "TW": "中国台湾", "MO": "中国澳门", "GB": "英国",
    "DE": "德国", "FR": "法国", "CA": "加拿大", "AU": "澳大利亚",
    "RU": "俄罗斯", "IN": "印度", "BR": "巴西", "NL": "荷兰",
    "CH": "瑞士", "SE": "瑞典", "IT": "意大利", "ES": "西班牙",
    "PT": "葡萄牙", "TR": "土耳其", "AE": "阿联酋", "SA": "沙特阿拉伯",
    "TH": "泰国", "VN": "越南", "MY": "马来西亚", "ID": "印度尼西亚",
    "PH": "菲律宾", "MX": "墨西哥", "AR": "阿根廷", "ZA": "南非",
    "NZ": "新西兰", "IE": "爱尔兰", "BE": "比利时", "AT": "奥地利",
    "DK": "丹麦", "NO": "挪威", "FI": "芬兰", "PL": "波兰",
    "CZ": "捷克", "GR": "希腊", "IL": "以色列", "EG": "埃及",
    "NG": "尼日利亚", "KE": "肯尼亚", "PK": "巴基斯坦",
    "BD": "孟加拉国", "LK": "斯里兰卡", "MM": "缅甸", "KH": "柬埔寨",
    "LA": "老挝", "MN": "蒙古", "KZ": "哈萨克斯坦", "UA": "乌克兰",
    "RO": "罗马尼亚", "HU": "匈牙利", "CL": "智利", "CO": "哥伦比亚",
    "PE": "秘鲁", "VE": "委内瑞拉", "QA": "卡塔尔", "KW": "科威特",
    "BH": "巴林", "OM": "阿曼", "JO": "约旦", "LB": "黎巴嫩",
    "CY": "塞浦路斯", "MT": "马耳他", "IS": "冰岛", "LU": "卢森堡",
    "BG": "保加利亚", "HR": "克罗地亚", "RS": "塞尔维亚", "SI": "斯洛文尼亚",
    "SK": "斯洛伐克", "LT": "立陶宛", "LV": "拉脱维亚", "EE": "爱沙尼亚",
}

TRAD_TO_SIMP = {
    "聖荷西": "圣何塞", "昆士蘭州": "昆士兰州", "紐約": "纽约",
    "洛杉磯": "洛杉矶", "舊金山": "旧金山", "華盛頓": "华盛顿",
    "倫敦": "伦敦", "東京": "东京", "首爾": "首尔", "雪梨": "悉尼",
    "墨爾本": "墨尔本", "溫哥華": "温哥华", "多倫多": "多伦多",
    "巴黎": "巴黎", "柏林": "柏林", "阿姆斯特丹": "阿姆斯特丹",
    "法蘭克福": "法兰克福", "蘇黎世": "苏黎世", "日內瓦": "日内瓦",
    "馬德里": "马德里", "羅馬": "罗马", "米蘭": "米兰",
    "杜拜": "迪拜", "孟買": "孟买", "班加羅爾": "班加罗尔",
    "胡志明市": "胡志明市", "河內": "河内", "馬尼拉": "马尼拉",
}

# 常见云厂商/Anycast ASN：即便第三方把类型标成 Business，也应视作机房/广播网络
CLOUD_ASNS = {
    13335, 15169, 16509, 14618, 8075, 14061, 16276, 24940, 63949,
    31898, 45102, 132203, 37963, 45090, 55990, 136907, 20940, 16625,
    54113, 19551, 2635, 396982, 396356, 9009,
}
CLOUD_KEYWORDS = (
    "google", "cloudflare", "amazon", "aws", "microsoft", "azure",
    "digitalocean", "linode", "vultr", "ovh", "hetzner", "oracle cloud",
    "alibaba cloud", "aliyun", "tencent cloud", "akamai", "fastly",
    "leaseweb", "choopa", "contabo", "scaleway",
)

COUNTRY_NAME_TO_CODE = {
    "china": "CN", "united states": "US", "japan": "JP", "south korea": "KR",
    "korea": "KR", "singapore": "SG", "hong kong": "HK", "taiwan": "TW",
    "united kingdom": "GB", "germany": "DE", "france": "FR", "canada": "CA",
    "australia": "AU", "russia": "RU", "india": "IN", "brazil": "BR",
    "netherlands": "NL", "switzerland": "CH", "sweden": "SE", "italy": "IT",
    "spain": "ES", "portugal": "PT", "turkey": "TR", "united arab emirates": "AE",
    "saudi arabia": "SA", "thailand": "TH", "vietnam": "VN", "malaysia": "MY",
    "indonesia": "ID", "philippines": "PH", "mexico": "MX", "argentina": "AR",
    "south africa": "ZA", "new zealand": "NZ", "ireland": "IE", "belgium": "BE",
    "austria": "AT", "denmark": "DK", "norway": "NO", "finland": "FI",
    "poland": "PL", "czechia": "CZ", "czech republic": "CZ", "greece": "GR",
    "israel": "IL", "egypt": "EG", "nigeria": "NG", "kenya": "KE",
    "pakistan": "PK", "bangladesh": "BD", "sri lanka": "LK", "myanmar": "MM",
    "cambodia": "KH", "laos": "LA", "mongolia": "MN", "kazakhstan": "KZ",
    "ukraine": "UA", "romania": "RO", "hungary": "HU", "chile": "CL",
    "colombia": "CO", "peru": "PE",
}


def flag_emoji(country_code: Optional[str]) -> str:
    code = (country_code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in code)


def simplify_zh(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    text = str(value)
    for traditional, simplified in TRAD_TO_SIMP.items():
        text = text.replace(traditional, simplified)
    return text


def country_display(code: Optional[str], name: Optional[str]) -> str:
    if name and contains_cjk(name):
        return simplify_zh(str(name).strip()) or ""
    code = (code or "").upper()
    if code in COUNTRY_ZH:
        return COUNTRY_ZH[code]
    if name:
        return simplify_zh(str(name).strip()) or ""
    return code or "未知"


def normalize_city(city: Optional[str], country_code: Optional[str]) -> Optional[str]:
    if not city:
        return None
    city = simplify_zh(str(city).strip()) or ""
    if (country_code or "").upper() == "CN" and contains_cjk(city):
        if not city.endswith(("市", "区", "县", "旗", "盟", "州", "地区")):
            city += "市"
    return city or None


def fmt_utc_offset(seconds: Any) -> Optional[str]:
    try:
        value = int(seconds)
    except (TypeError, ValueError):
        return None
    sign = "+" if value >= 0 else "-"
    value = abs(value)
    hours, minutes = divmod(value // 60, 60)
    return f"UTC{sign}{hours:02d}:{minutes:02d}"


def first(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            value = value.strip()
            if value:
                return value
        else:
            return value
    return None


def first_num(*values: Any) -> Optional[float]:
    for value in values:
        if value is None or value == "":
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return None


def parse_asn(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    match = re.search(r"(?i)\bAS\s*(\d+)\b", str(value))
    if match:
        return int(match.group(1))
    if str(value).strip().isdigit():
        return int(value)
    return None


def strip_asn_prefix(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    text = re.sub(r"(?i)^AS\s*\d+\s*[-:]?\s*", "", text).strip()
    return text or None


def strip_as_handle(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if " - " in text:
        left, right = text.split(" - ", 1)
        if left.upper().startswith(("AS", "CHINA", "GOOGLE", "CLOUDFLARE")):
            return right.strip() or text
    return text


def clean_error(value: Any) -> str:
    text = str(value or "").replace("\n", " ").replace("\r", " ").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:180]


def now_iso() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def parse_ip(value: str) -> ipaddress._BaseAddress:
    text = (value or "").strip()
    if not text:
        raise ProbeError("没有提供 IP 地址")
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if "%" in text:
        text = text.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ProbeError(f"不是合法的 IP 地址：{value}") from exc
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


class ProbeError(Exception):
    pass


# ---------------------------------------------------------------------------
# HTTP 层
# ---------------------------------------------------------------------------

SSL_CONTEXT = ssl.create_default_context()


def http_get_text(url: str, timeout: float) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.7",
        "Accept-Encoding": "identity",
        "Cache-Control": "no-cache",
    }
    request = urllib.request.Request(url, headers=headers, method="GET")
    kwargs: Dict[str, Any] = {"timeout": max(1.0, timeout)}
    if url.lower().startswith("https://"):
        kwargs["context"] = SSL_CONTEXT
    try:
        with urllib.request.urlopen(request, **kwargs) as response:
            raw = response.read(MAX_BODY)
            encoding = (response.headers.get("Content-Encoding") or "").lower()
            if "gzip" in encoding:
                try:
                    raw = gzip.decompress(raw)
                except Exception:
                    pass
            charset = response.headers.get_content_charset() or "utf-8"
            try:
                text = raw.decode(charset, "replace")
            except LookupError:
                text = raw.decode("utf-8", "replace")
            return text, None, getattr(response, "status", None)
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(300).decode("utf-8", "replace")
        except Exception:
            body = ""
        message = f"HTTP {exc.code}"
        if exc.code == 429:
            message = "HTTP 429（请求过多/限流）"
        if body:
            message += ": " + clean_error(body)
        return None, message, exc.code
    except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", None)
        message = clean_error(reason if reason is not None else exc)
        return None, message or exc.__class__.__name__, None


def fetch_json_source(name: str, url: str, timeout: float) -> Dict[str, Any]:
    started = time.perf_counter()
    text, error, status = http_get_text(url, timeout)
    elapsed = int((time.perf_counter() - started) * 1000)
    if error:
        return {
            "name": name, "ok": False, "data": None, "error": error,
            "elapsed_ms": elapsed, "status": status, "url": url,
        }
    try:
        data = json.loads(text or "")
    except (TypeError, ValueError):
        return {
            "name": name, "ok": False, "data": None,
            "error": "返回内容不是 JSON", "elapsed_ms": elapsed,
            "status": status, "url": url,
        }
    if not isinstance(data, dict):
        return {
            "name": name, "ok": False, "data": None,
            "error": "返回 JSON 结构异常", "elapsed_ms": elapsed,
            "status": status, "url": url,
        }
    return {
        "name": name, "ok": True, "data": data, "error": None,
        "elapsed_ms": elapsed, "status": status, "url": url,
    }


def source_ok(result: Optional[Dict[str, Any]]) -> bool:
    return bool(result and result.get("ok") and isinstance(result.get("data"), dict))


def data_of(result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if source_ok(result):
        return result["data"]  # type: ignore[return-value]
    return {}


# ---------------------------------------------------------------------------
# 具体数据源
# ---------------------------------------------------------------------------

ECHO_URLS = {
    4: [
        "https://ipv4.icanhazip.com",
        "https://v4.ident.me",
        "https://ipv4.ifconfig.co",
        "https://api.ipify.org?format=json",
    ],
    6: [
        "https://ipv6.icanhazip.com",
        "https://v6.ident.me",
        "https://ipv6.ifconfig.co",
        "https://api6.ipify.org?format=json",
    ],
}


def parse_ip_echo(text: str) -> Optional[str]:
    text = (text or "").strip()
    if not text:
        return None
    if text.startswith("{"):
        try:
            payload = json.loads(text)
            if isinstance(payload, dict):
                for key in ("ip", "address", "query"):
                    value = payload.get(key)
                    if value:
                        return str(value).strip()
        except ValueError:
            pass
    first_line = text.splitlines()[0].strip()
    return first_line.split()[0].strip(" ,;\"'<>") if first_line else None


def detect_one(family: int, timeout: float) -> Dict[str, Any]:
    errors: List[str] = []
    started = time.perf_counter()
    for url in ECHO_URLS[family]:
        text, error, _status = http_get_text(url, min(max(timeout, 2.0), 6.0))
        if error or not text:
            host = urllib.parse.urlparse(url).hostname or url
            errors.append(f"{host}: {clean_error(error or '空响应')}")
            continue
        candidate = parse_ip_echo(text)
        if not candidate:
            errors.append(f"{url}: 无法解析 IP")
            continue
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            errors.append(f"{url}: 返回非 IP")
            continue
        if ip.version != family:
            errors.append(f"{url}: 返回了 IPv{ip.version}")
            continue
        if not ip.is_global:
            errors.append(f"{url}: 返回非公网地址")
            continue
        return {
            "ip": str(ip),
            "family": family,
            "source": url,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
        }
    return {
        "ip": None,
        "family": family,
        "source": None,
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
        "error": "；".join(errors[-2:]) or "无可用回显服务",
    }


def detect_public_ips(families: Iterable[int], timeout: float) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    families = list(families)
    found: List[Dict[str, Any]] = []
    missing: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(families) or 1) as executor:
        futures = {executor.submit(detect_one, family, timeout): family for family in families}
        for future in concurrent.futures.as_completed(futures):
            family = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # pragma: no cover - 防御性
                result = {"ip": None, "family": family, "error": clean_error(exc)}
            if result.get("ip"):
                found.append(result)
            else:
                missing.append({
                    "family": family,
                    "message": f"未检测到 IPv{family} 出口（可能未启用 IPv{family} 或网络不支持）",
                    "error": result.get("error"),
                })
    found.sort(key=lambda item: item["family"])
    missing.sort(key=lambda item: item["family"])
    return found, missing


def fetch_ipwho(ip: str, timeout: float) -> Dict[str, Any]:
    url = f"https://ipwho.is/{urllib.parse.quote(ip, safe=':')}?lang=zh-CN"
    result = fetch_json_source("ipwho.is", url, timeout)
    if source_ok(result):
        data = result["data"]  # type: ignore[index]
        if data.get("success") is False:
            result["ok"] = False
            result["error"] = clean_error(data.get("message") or "查询失败")
    return result


def fetch_proxycheck(ip: str, timeout: float) -> Dict[str, Any]:
    params = {"vpn": "1", "asn": "1", "risk": "1"}
    key = os.environ.get("PROXYCHECK_API_KEY", "").strip()
    if key:
        params["key"] = key
    url = f"https://proxycheck.io/v2/{urllib.parse.quote(ip, safe=':')}?{urllib.parse.urlencode(params)}"
    result = fetch_json_source("proxycheck.io", url, timeout)
    if not source_ok(result):
        return result
    data = result["data"]  # type: ignore[index]
    status = str(data.get("status") or "").lower()
    payload = data.get(ip)
    if not isinstance(payload, dict):
        for key, value in data.items():
            if key != "status" and isinstance(value, dict):
                payload = value
                break
    if status not in ("ok", "warning") or not isinstance(payload, dict):
        result["ok"] = False
        result["error"] = clean_error(data.get("message") or f"状态：{status or 'unknown'}")
        return result
    result["data"] = payload
    return result


def fetch_rdap(ip: str, timeout: float) -> Dict[str, Any]:
    url = f"https://rdap.org/ip/{urllib.parse.quote(ip, safe=':')}"
    result = fetch_json_source("RDAP", url, timeout)
    if not source_ok(result):
        return result
    data = result["data"]  # type: ignore[index]
    registry = None
    for notice in data.get("notices") or []:
        if not isinstance(notice, dict):
            continue
        title = str(notice.get("title") or "").lower()
        if "source" in title:
            for description in notice.get("description") or []:
                text = str(description)
                if text.upper() in ("APNIC", "ARIN", "RIPE", "LACNIC", "AFRINIC"):
                    registry = text.upper()
                    break
    if not registry:
        for notice in data.get("notices") or []:
            if not isinstance(notice, dict):
                continue
            descriptions = notice.get("description") or []
            if not isinstance(descriptions, list):
                descriptions = [descriptions]
            for description in descriptions:
                text = str(description).upper()
                for candidate in ("APNIC", "ARIN", "RIPE", "LACNIC", "AFRINIC"):
                    if candidate in text:
                        registry = candidate
                        break
                if registry:
                    break
            if registry:
                break
    data["_registry"] = registry
    return result


def fetch_ripe(ip: str, timeout: float) -> Dict[str, Any]:
    url = (
        "https://stat.ripe.net/data/prefix-overview/data.json?resource="
        + urllib.parse.quote(ip, safe=":")
    )
    result = fetch_json_source("RIPEstat", url, timeout)
    if not source_ok(result):
        return result
    data = result["data"]  # type: ignore[index]
    if str(data.get("status") or "").lower() != "ok":
        result["ok"] = False
        result["error"] = clean_error(data.get("message") or "RIPEstat 查询失败")
        return result
    registry = None
    block = (data.get("data") or {}).get("block") or {}
    match = re.search(r"(?i)(APNIC|ARIN|RIPE|LACNIC|AFRINIC)", str(block.get("desc") or ""))
    if match:
        registry = match.group(1).upper()
    data["_registry"] = registry
    return result


def fetch_ipinfo(ip: str, timeout: float) -> Dict[str, Any]:
    token = os.environ.get("IPINFO_TOKEN", "").strip()
    url = f"https://ipinfo.io/{urllib.parse.quote(ip, safe=':')}/json"
    if token:
        url += "?" + urllib.parse.urlencode({"token": token})
    return fetch_json_source("ipinfo.io", url, timeout)


def fetch_ipapi_is(ip: str, timeout: float) -> Dict[str, Any]:
    url = f"https://ipapi.is/json/?q={urllib.parse.quote(ip, safe=':')}"
    return fetch_json_source("ipapi.is", url, timeout)


def fetch_ipapi_com(ip: str, timeout: float) -> Dict[str, Any]:
    fields = ",".join([
        "status", "message", "continent", "country", "countryCode", "regionName",
        "city", "district", "zip", "lat", "lon", "timezone", "offset", "isp",
        "org", "as", "asname", "reverse", "mobile", "proxy", "hosting", "query",
    ])
    url = f"http://ip-api.com/json/{urllib.parse.quote(ip, safe=':')}?fields={fields}&lang=zh-CN"
    result = fetch_json_source("ip-api.com", url, timeout)
    if source_ok(result):
        data = result["data"]  # type: ignore[index]
        if data.get("status") != "success":
            result["ok"] = False
            result["error"] = clean_error(data.get("message") or "查询失败")
    return result


def reverse_dns(ip: str, timeout: float = 3.0) -> Optional[str]:
    holder: Dict[str, Optional[str]] = {}

    def worker() -> None:
        try:
            hostname, _aliases, _addresses = socket.gethostbyaddr(ip)
            holder["ptr"] = hostname.rstrip(".")
        except Exception:
            holder["ptr"] = None

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(max(0.5, timeout))
    return holder.get("ptr")


# ---------------------------------------------------------------------------
# 画像构建
# ---------------------------------------------------------------------------

def classify_company(name: Optional[str], hosting: bool) -> str:
    text = (name or "").lower()
    if any(word in text for word in ("amazon", "aws", "google", "microsoft", "azure", "cloudflare", "digitalocean", "oracle", "alibaba cloud", "tencent cloud", "vultr", "linode", "ovh", "hetzner")):
        return "云服务商/科技公司"
    if hosting:
        return "机房/云服务"
    if any(word in text for word in ("mobile", "telecom", "unicom", "communications", "broadband", "internet service", "isp", "telefonica", "vodafone", "orange", "verizon", "at&t", "comcast")):
        return "ISP/运营商"
    if any(word in text for word in ("hosting", "server", "data center", "data centre", "datacenter", "idc", "vps")):
        return "机房/云服务"
    if any(word in text for word in ("university", "college", "education", "school")):
        return "教育机构"
    if any(word in text for word in ("government", "ministry", "municipal")):
        return "政府机构"
    if any(word in text for word in ("bank", "finance", "insurance")):
        return "金融/企业"
    return "企业"


TYPE_LABELS = {
    "residential": ("家庭宽带", "residential"),
    "wireless": ("移动网络", "mobile"),
    "mobile": ("移动网络", "mobile"),
    "cellular": ("移动网络", "mobile"),
    "business": ("企业网络", "business"),
    "hosting": ("数据中心/机房", "hosting"),
    "server": ("服务器/机房", "hosting"),
    "datacenter": ("数据中心/机房", "hosting"),
    "vpn": ("VPN 出口", "vpn"),
    "tor": ("Tor 出口", "tor"),
    "public proxy": ("公共代理", "proxy"),
    "open proxy": ("开放代理", "proxy"),
    "compromised server": ("被入侵主机", "compromised"),
    "compromised": ("被入侵主机", "compromised"),
}


def classify_network_type(raw_type: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    text = (raw_type or "").strip().lower()
    if not text:
        return None, None
    if text in TYPE_LABELS:
        return TYPE_LABELS[text]
    for key, value in TYPE_LABELS.items():
        if key in text:
            return value
    return raw_type, "unknown"


def risk_level(score: Optional[int]) -> Tuple[str, str]:
    if score is None:
        return "未知", "unknown"
    if score <= 20:
        return "极低", "clean"
    if score <= 40:
        return "低", "low"
    if score <= 60:
        return "中", "medium"
    if score <= 80:
        return "高", "high"
    return "极高", "critical"


def infer_native(
    country_code: Optional[str],
    rdap_country: Optional[str],
    type_code: str,
    flags: Dict[str, bool],
) -> Dict[str, Any]:
    geo_cc = (country_code or "").upper() or None
    reg_cc = (rdap_country or "").upper() or None
    same_country = bool(geo_cc and reg_cc and geo_cc == reg_cc)

    if flags.get("tor"):
        return {"label": "Tor 出口", "confidence": "高", "reason": "检测为 Tor 节点，非原生住宅出口", "is_native": False, "country_match": same_country}
    if flags.get("vpn"):
        return {"label": "VPN 出口", "confidence": "中", "reason": "检测为 VPN，非原生住宅出口", "is_native": False, "country_match": same_country}
    if flags.get("proxy"):
        return {"label": "代理出口", "confidence": "中", "reason": "检测为代理，非原生住宅出口", "is_native": False, "country_match": same_country}
    if flags.get("hosting") or type_code in ("hosting", "compromised"):
        return {"label": "广播/机房 IP", "confidence": "中", "reason": "IP 类型为机房/数据中心，通常不是原生住宅 IP", "is_native": False, "country_match": same_country}
    if geo_cc and reg_cc and geo_cc != reg_cc:
        return {
            "label": "广播 IP",
            "confidence": "高",
            "reason": f"注册地 {reg_cc} 与归属地 {geo_cc} 不一致",
            "is_native": False,
            "country_match": False,
        }
    if same_country:
        return {
            "label": "原生 IP",
            "confidence": "中",
            "reason": "注册地与归属地一致，且未发现机房/代理特征",
            "is_native": True,
            "country_match": True,
        }
    if type_code in ("mobile", "residential", "business"):
        return {
            "label": "可能原生 IP",
            "confidence": "低",
            "reason": "ISP 类型且未发现广播证据，但缺少注册地数据",
            "is_native": None,
            "country_match": None,
        }
    return {
        "label": "未知",
        "confidence": "低",
        "reason": "缺少注册地或网络类型数据",
        "is_native": None,
        "country_match": None,
    }


def estimate_shared(
    ip: ipaddress._BaseAddress,
    type_code: str,
    flags: Dict[str, bool],
    devices_address: Optional[int],
    devices_subnet: Optional[int],
) -> Dict[str, Any]:
    if devices_address is not None and devices_address >= 1 and (
        type_code not in ("hosting", "proxy", "vpn", "tor") or devices_address > 3
    ):
        high = max(10, devices_address * 10)
        low = max(1, devices_address)
        if devices_address == 1:
            level = "极少"
            value = "1-10"
        elif devices_address <= 3:
            level = "少"
            value = f"{low}-{high}"
        elif devices_address <= 10:
            level = "中"
            value = f"{low}-{high}"
        else:
            level = "多"
            value = f"{low}+"
        return {
            "range": value,
            "level": level,
            "estimated": True,
            "basis": f"proxycheck.io 观测到该地址有 {devices_address} 台设备",
            "devices_address": devices_address,
            "devices_subnet": devices_subnet,
        }

    if type_code == "hosting":
        return {
            "range": "50-500+", "level": "很多", "estimated": True,
            "basis": "机房 IP 通常被多个用户/业务共享（估算）",
            "devices_address": None, "devices_subnet": devices_subnet,
        }
    if type_code in ("vpn", "proxy", "tor"):
        return {
            "range": "10-100", "level": "较多", "estimated": True,
            "basis": "代理/VPN/Tor 出口通常被多人共享（估算）",
            "devices_address": None, "devices_subnet": devices_subnet,
        }
    if ip.version == 6:
        return {
            "range": "1-10", "level": "极少", "estimated": True,
            "basis": "IPv6 地址通常独享（估算）",
            "devices_address": None, "devices_subnet": devices_subnet,
        }
    if type_code == "mobile":
        return {
            "range": "10-100", "level": "较多", "estimated": True,
            "basis": "移动网络常经运营商 NAT 共享（估算）",
            "devices_address": None, "devices_subnet": devices_subnet,
        }
    if type_code == "business":
        return {
            "range": "5-50", "level": "中", "estimated": True,
            "basis": "企业网络可能由多人共享（估算）",
            "devices_address": None, "devices_subnet": devices_subnet,
        }
    if type_code == "residential":
        return {
            "range": "1-10", "level": "极少", "estimated": True,
            "basis": "家庭宽带通常独享（估算）",
            "devices_address": None, "devices_subnet": devices_subnet,
        }
    return {
        "range": "未知", "level": "未知", "estimated": True,
        "basis": "缺少可用的共享数据",
        "devices_address": None, "devices_subnet": devices_subnet,
    }


def scenario_label(score: float) -> str:
    if score >= 4.5:
        return "强烈推荐"
    if score >= 3.5:
        return "推荐"
    if score >= 2.5:
        return "可用"
    if score >= 1.5:
        return "谨慎"
    return "不推荐"


def stars_for(score: float) -> str:
    filled = max(0, min(5, int(round(score))))
    return "★" * filled + "☆" * (5 - filled)


def build_scenarios(
    country_code: Optional[str],
    type_code: str,
    risk: Optional[int],
    native_is: Optional[bool],
    shared_level: str,
    flags: Dict[str, bool],
) -> List[Dict[str, Any]]:
    base = 3.8
    if type_code in ("residential", "mobile"):
        base += 0.8
    elif type_code == "business":
        base -= 0.2
    elif type_code in ("hosting", "proxy", "vpn", "tor", "compromised"):
        base -= 2.6
    if risk is not None:
        if risk >= 80:
            base -= 3.0
        elif risk >= 60:
            base -= 2.0
        elif risk >= 40:
            base -= 1.0
        elif risk <= 10:
            base += 0.5
    if native_is is True:
        base += 0.5
    elif native_is is False:
        base -= 1.0
    if shared_level in ("多", "很多"):
        base -= 0.5

    cc = (country_code or "").upper()
    definitions = [
        ("TikTok", -5.0 if cc == "CN" else 0.4, "中国大陆 IP 通常无法直接使用 TikTok"),
        ("跨境电商", -1.2 if cc == "CN" else 0.2, "更看重原生 IP 与低风控"),
        ("社媒运营", -1.0 if cc == "CN" else 0.1, "更看重稳定与共享人数"),
        ("AI 应用", -0.5, "风控与地区限制影响可用性"),
    ]
    output: List[Dict[str, Any]] = []
    for name, adjust, reason in definitions:
        score = max(0.0, min(5.0, base + adjust))
        label = scenario_label(score)
        if flags.get("tor") or flags.get("proxy"):
            reason = "代理/ Tor 出口容易被平台风控"
        elif type_code == "hosting":
            reason = "机房 IP 容易被流媒体和电商平台限制"
        elif native_is is True and (risk is None or risk <= 40):
            reason = "原生 IP 且风险较低，相对适合"
        output.append({
            "name": name,
            "score": round(score, 1),
            "stars": stars_for(score),
            "label": label,
            "reason": reason,
        })
    return output


def make_private_profile(ip: ipaddress._BaseAddress) -> Dict[str, Any]:
    profile: Dict[str, Any] = {
        "ip": str(ip),
        "version": ip.version,
        "family": f"IPv{ip.version}",
        "is_public": False,
        "detected_via": None,
        "elapsed_ms": 0,
        "location": {
            "continent": None,
            "country": "非公网地址",
            "country_code": None,
            "flag": "🏠",
            "region": None,
            "city": None,
            "district": None,
            "postal": None,
            "latitude": None,
            "longitude": None,
            "timezone": None,
            "utc_offset": None,
            "accuracy": "非公网",
        },
        "asn": {
            "number": None, "id": None, "owner": None, "isp": None,
            "domain": None, "prefix": None, "country": None,
            "registry": None, "rir_holder": None,
        },
        "company": {"name": None, "domain": None, "category": "非公网"},
        "network": {
            "type": "私有/保留地址", "type_code": "private", "type_raw": None,
            "is_proxy": False, "is_vpn": False, "is_tor": False,
            "is_hosting": False, "is_mobile": False, "is_residential": False,
            "is_business": False,
        },
        "native": {
            "label": "非公网 IP", "confidence": "高",
            "reason": "该地址属于私有/保留网段", "is_native": None,
            "country_match": None,
        },
        "risk": {
            "score": None, "level": "未知", "purity": None,
            "source": None, "note": "非公网地址不查询风控",
        },
        "shared": {
            "range": "未知", "level": "未知", "estimated": True,
            "basis": "非公网地址", "devices_address": None, "devices_subnet": None,
        },
        "scenarios": [
            {"name": name, "score": 0.0, "stars": "☆☆☆☆☆", "label": "不推荐", "reason": "非公网 IP"}
            for name in ("TikTok", "跨境电商", "社媒运营", "AI 应用")
        ],
        "reverse_dns": None,
        "sources": [],
        "warnings": ["该地址属于私有/保留网段，未发送到第三方服务查询。"],
        "ok": True,
    }
    return profile


def build_profile(
    ip: ipaddress._BaseAddress,
    ipwho: Optional[Dict[str, Any]],
    proxycheck: Optional[Dict[str, Any]],
    rdap: Optional[Dict[str, Any]],
    ripe: Optional[Dict[str, Any]],
    ipinfo: Optional[Dict[str, Any]],
    ipapiis: Optional[Dict[str, Any]],
    ipapi: Optional[Dict[str, Any]],
    ptr: Optional[str],
    want_risk: bool,
    fast: bool,
    deep: bool,
    detected_via: Optional[str],
    elapsed_ms: int,
) -> Dict[str, Any]:
    w = data_of(ipwho)
    pc = data_of(proxycheck)
    rd = data_of(rdap)
    ri = data_of(ripe)
    ii = data_of(ipinfo)
    ai = data_of(ipapiis)
    ia = data_of(ipapi)

    w_conn = w.get("connection") or {}
    w_tz = w.get("timezone") or {}
    ii_privacy = ii.get("privacy") or {}
    ii_asn = ii.get("asn") or {}
    ii_company = ii.get("company") or {}
    pc_devices = pc.get("devices") or {}

    # ---- 位置 ----
    country_code = first(
        w.get("country_code"), ii.get("country"), ia.get("countryCode"),
        pc.get("isocode"), rd.get("country"),
    )
    if not country_code and ai.get("country"):
        country_code = COUNTRY_NAME_TO_CODE.get(str(ai["country"]).lower())
    country_code = str(country_code).upper() if country_code else None

    country_name = first(
        w.get("country"),
        COUNTRY_ZH.get(country_code or ""),
        ia.get("country"),
        ai.get("country"),
        pc.get("country"),
    )
    region = simplify_zh(first(w.get("region"), ii.get("region"), ia.get("regionName"), ai.get("region"), pc.get("region")))
    city = first(w.get("city"), ii.get("city"), ia.get("city"), ai.get("city"), pc.get("city"))
    city = normalize_city(city, country_code)
    district = simplify_zh(first(ia.get("district")))
    postal = first(w.get("postal"), ii.get("postal"), ia.get("zip"), pc.get("postcode"))

    lat = first_num(w.get("latitude"), ai.get("lat"), ai.get("latitude"), pc.get("latitude"))
    lon = first_num(w.get("longitude"), ai.get("lon"), ai.get("longitude"), pc.get("longitude"))
    if lat is None or lon is None:
        location_text = first(ii.get("loc"))
        if location_text and "," in str(location_text):
            parts = str(location_text).split(",", 1)
            lat = lat if lat is not None else first_num(parts[0])
            lon = lon if lon is not None else first_num(parts[1])

    timezone = first(w_tz.get("id"), ii.get("timezone"), ia.get("timezone"), ai.get("timezone"), pc.get("timezone"))
    utc_offset = first(w_tz.get("utc"), fmt_utc_offset(ia.get("offset")))
    if utc_offset and re.match(r"^[+-]\d{2}:\d{2}$", str(utc_offset)):
        utc_offset = "UTC" + str(utc_offset)
    continent = first(w.get("continent"), pc.get("continent"))

    accuracy = "未知"
    if city:
        accuracy = "城市级"
    elif region:
        accuracy = "省级"
    elif country_code or country_name:
        accuracy = "国家级"

    location = {
        "continent": continent,
        "country": country_display(country_code, country_name),
        "country_code": country_code,
        "flag": flag_emoji(country_code),
        "region": region,
        "city": city,
        "district": district,
        "postal": postal,
        "latitude": round(lat, 6) if lat is not None else None,
        "longitude": round(lon, 6) if lon is not None else None,
        "timezone": timezone,
        "utc_offset": utc_offset,
        "accuracy": accuracy,
    }

    # ---- ASN / 企业 ----
    asn_number = first_num(
        w_conn.get("asn"), parse_asn(ii_asn.get("asn")), parse_asn(ai.get("asn")),
        parse_asn(ia.get("as")), parse_asn(pc.get("asn")),
    )
    asn_number_int = int(asn_number) if asn_number is not None else None

    ripe_data = ri.get("data") if isinstance(ri.get("data"), dict) else {}
    rir_holder = first(ripe_data.get("holder"))
    if not rir_holder:
        for item in ripe_data.get("asns") or []:
            if isinstance(item, dict) and item.get("holder"):
                rir_holder = str(item["holder"])
                break

    asn_owner = first(
        pc.get("provider"),
        strip_as_handle(rir_holder),
        w_conn.get("org"),
        ii_asn.get("name"),
        strip_asn_prefix(ai.get("asn")),
        ia.get("asname"),
    )
    isp = first(
        w_conn.get("isp"),
        ia.get("isp"),
        pc.get("organisation"),
        pc.get("provider"),
        ii_company.get("name"),
        asn_owner,
    )
    if isp and (not asn_owner or "apnic research" in str(asn_owner).lower()):
        asn_owner = isp
    domain = first(
        w_conn.get("domain"),
        ii_asn.get("domain"),
        ii_company.get("domain"),
    )
    prefix = first(
        pc.get("range"),
        ripe_data.get("resource"),
        ii_asn.get("route"),
    )
    registry = first(rd.get("_registry"), ri.get("_registry"))
    if not registry:
        block = ripe_data.get("block") or {}
        desc = str(block.get("desc") or "")
        match = re.search(r"(?i)(APNIC|ARIN|RIPE|LACNIC|AFRINIC)", desc)
        if match:
            registry = match.group(1).upper()
    asn_country = first(rd.get("country"))

    asn = {
        "number": asn_number_int,
        "id": f"AS{asn_number_int}" if asn_number_int is not None else None,
        "owner": asn_owner,
        "isp": isp,
        "domain": domain,
        "prefix": prefix,
        "country": str(asn_country).upper() if asn_country else None,
        "country_name": country_display(str(asn_country).upper() if asn_country else None, None) if asn_country else None,
        "registry": registry,
        "rir_holder": rir_holder,
    }

    company_name = first(isp, asn_owner)
    company = {
        "name": company_name,
        "domain": domain,
        "category": classify_company(company_name, False),
    }

    # ---- 网络类型 / 标记 ----
    raw_type = first(pc.get("type"))
    type_label, type_code = classify_network_type(raw_type)
    flags = {
        "proxy": False, "vpn": False, "tor": False,
        "hosting": False, "mobile": False, "residential": False,
        "business": False, "compromised": False,
    }

    if raw_type:
        raw_lower = str(raw_type).lower()
        if "tor" in raw_lower:
            flags["tor"] = True
        if "vpn" in raw_lower:
            flags["vpn"] = True
        if "proxy" in raw_lower:
            flags["proxy"] = True
        if "hosting" in raw_lower or "server" in raw_lower or "datacenter" in raw_lower or "data center" in raw_lower:
            flags["hosting"] = True
        if "wireless" in raw_lower or "mobile" in raw_lower or "cellular" in raw_lower:
            flags["mobile"] = True
        if "residential" in raw_lower:
            flags["residential"] = True
        if "business" in raw_lower:
            flags["business"] = True
        if "compromised" in raw_lower:
            flags["compromised"] = True
    if str(pc.get("proxy") or "").lower() == "yes":
        flags["proxy"] = True

    if ia:
        flags["proxy"] = flags["proxy"] or bool(ia.get("proxy"))
        flags["hosting"] = flags["hosting"] or bool(ia.get("hosting"))
        flags["mobile"] = flags["mobile"] or bool(ia.get("mobile"))
    if ii_privacy:
        flags["proxy"] = flags["proxy"] or bool(ii_privacy.get("proxy"))
        flags["vpn"] = flags["vpn"] or bool(ii_privacy.get("vpn"))
        flags["tor"] = flags["tor"] or bool(ii_privacy.get("tor"))
        flags["hosting"] = flags["hosting"] or bool(ii_privacy.get("hosting"))

    if type_code is None:
        if flags["tor"]:
            type_label, type_code = "Tor 出口", "tor"
        elif flags["vpn"]:
            type_label, type_code = "VPN 出口", "vpn"
        elif flags["proxy"]:
            type_label, type_code = "代理", "proxy"
        elif flags["hosting"]:
            type_label, type_code = "数据中心/机房", "hosting"
        elif flags["mobile"]:
            type_label, type_code = "移动网络", "mobile"
        elif flags["residential"]:
            type_label, type_code = "家庭宽带", "residential"
        elif flags["business"]:
            type_label, type_code = "企业网络", "business"
        else:
            type_label, type_code = "未知", "unknown"
    else:
        # 用 flags 修正更具体的类型
        if flags["tor"]:
            type_label, type_code = "Tor 出口", "tor"
        elif flags["vpn"] and type_code not in ("vpn", "tor"):
            type_label, type_code = "VPN 出口", "vpn"
        elif flags["hosting"] and type_code not in ("hosting", "compromised"):
            type_label, type_code = "数据中心/机房", "hosting"

    # 云厂商 / Anycast 网络：第三方可能标记为 Business，但实际应按机房网络处理
    owner_text = " ".join(str(part or "").lower() for part in (asn_owner, company_name, domain))
    cloud_like = (
        (asn_number_int in CLOUD_ASNS)
        or any(keyword in owner_text for keyword in CLOUD_KEYWORDS)
    )
    if cloud_like and not flags["mobile"] and not flags["residential"]:
        flags["hosting"] = True
        if type_code in ("business", "unknown", None):
            type_label, type_code = "数据中心/机房", "hosting"

    company["category"] = classify_company(company_name, flags["hosting"])
    network = {
        "type": type_label or "未知",
        "type_code": type_code or "unknown",
        "type_raw": raw_type,
        "is_proxy": bool(flags["proxy"]),
        "is_vpn": bool(flags["vpn"]),
        "is_tor": bool(flags["tor"]),
        "is_hosting": bool(flags["hosting"]),
        "is_mobile": bool(flags["mobile"]),
        "is_residential": bool(flags["residential"]),
        "is_business": bool(flags["business"]),
    }

    # ---- 风险 ----
    risk_score: Optional[int] = None
    if source_ok(proxycheck):
        try:
            risk_score = max(0, min(100, int(pc.get("risk"))))
        except (TypeError, ValueError):
            risk_score = None
    risk_label, _risk_key = risk_level(risk_score)
    if risk_score is not None:
        risk_note = "来自 proxycheck.io"
    elif not want_risk:
        risk_note = "已通过 --no-risk 跳过风控查询"
    elif not source_ok(proxycheck):
        risk_note = "风控源不可用"
    else:
        risk_note = "风控源未返回分数"
    risk = {
        "score": risk_score,
        "level": risk_label,
        "purity": (100 - risk_score) if risk_score is not None else None,
        "source": "proxycheck.io" if risk_score is not None else None,
        "note": risk_note,
    }

    native = infer_native(country_code, asn["country"], type_code or "unknown", flags)

    try:
        devices_address = int(pc_devices.get("address")) if pc_devices.get("address") is not None else None
    except (TypeError, ValueError):
        devices_address = None
    try:
        devices_subnet = int(pc_devices.get("subnet")) if pc_devices.get("subnet") is not None else None
    except (TypeError, ValueError):
        devices_subnet = None
    shared = estimate_shared(ip, type_code or "unknown", flags, devices_address, devices_subnet)

    scenarios = build_scenarios(
        country_code, type_code or "unknown", risk_score,
        native.get("is_native"), shared.get("level", "未知"), flags,
    )

    # ---- 来源汇总 ----
    sources: List[Dict[str, Any]] = []
    for result in (ipwho, proxycheck, rdap, ripe, ipinfo, ipapiis, ipapi):
        if result is None:
            continue
        sources.append({
            "name": result.get("name"),
            "ok": bool(result.get("ok")),
            "elapsed_ms": result.get("elapsed_ms"),
            "error": clean_error(result.get("error")) if result.get("error") else None,
        })
    if ptr:
        sources.append({"name": "PTR", "ok": True, "elapsed_ms": None, "error": None})

    warnings: List[str] = []
    if want_risk and not source_ok(proxycheck):
        warnings.append("风控值未获取，IP 类型可能由备用数据源推断。")
    if not city and not region:
        warnings.append("仅获取到国家级位置，城市/经纬度可能缺失。")
    if not any(source_ok(item) for item in (ipwho, proxycheck, rdap, ripe, ipinfo, ipapiis, ipapi)):
        warnings.append("所有数据源均查询失败。")

    profile_ok = any(source_ok(item) for item in (ipwho, proxycheck, rdap, ripe, ipinfo, ipapiis, ipapi))
    if not profile_ok:
        warnings.append("网络请求失败，请检查网络或代理设置。")

    return {
        "ip": str(ip),
        "version": ip.version,
        "family": f"IPv{ip.version}",
        "is_public": True,
        "detected_via": detected_via,
        "elapsed_ms": elapsed_ms,
        "location": location,
        "asn": asn,
        "company": company,
        "network": network,
        "native": native,
        "risk": risk,
        "shared": shared,
        "scenarios": scenarios,
        "reverse_dns": ptr,
        "sources": sources,
        "warnings": warnings,
        "ok": profile_ok,
    }


def query_ip(
    ip_value: str,
    timeout: float = DEFAULT_TIMEOUT,
    want_risk: bool = True,
    fast: bool = False,
    deep: bool = False,
    detected_via: Optional[str] = None,
) -> Dict[str, Any]:
    ip = parse_ip(ip_value)
    started = time.perf_counter()
    if not ip.is_global:
        return make_private_profile(ip)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures: Dict[str, concurrent.futures.Future] = {
            "ipwho": executor.submit(fetch_ipwho, str(ip), timeout),
        }
        if want_risk:
            futures["proxycheck"] = executor.submit(fetch_proxycheck, str(ip), timeout)
        if not fast:
            futures["rdap"] = executor.submit(fetch_rdap, str(ip), min(timeout, 7.0))
        if deep:
            futures["ripe"] = executor.submit(fetch_ripe, str(ip), timeout)
        if os.environ.get("IPINFO_TOKEN", "").strip():
            futures["ipinfo"] = executor.submit(fetch_ipinfo, str(ip), timeout)

        results: Dict[str, Optional[Dict[str, Any]]] = {}
        for key, future in futures.items():
            try:
                results[key] = future.result()
            except Exception as exc:  # pragma: no cover - 防御性
                results[key] = {
                    "name": key, "ok": False, "data": None,
                    "error": clean_error(exc), "elapsed_ms": None,
                }

    ipwho = results.get("ipwho")
    proxycheck = results.get("proxycheck")
    rdap = results.get("rdap")
    ripe = results.get("ripe")
    ipinfo = results.get("ipinfo")
    ipapiis: Optional[Dict[str, Any]] = None
    ipapi: Optional[Dict[str, Any]] = None

    need_geo = not source_ok(ipwho)
    need_flags = not source_ok(proxycheck)

    if need_geo or need_flags:
        fallback_futures: Dict[str, concurrent.futures.Future] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            if need_geo:
                fallback_futures["ipapiis"] = executor.submit(fetch_ipapi_is, str(ip), timeout)
                if not source_ok(ipinfo):
                    fallback_futures["ipinfo"] = executor.submit(fetch_ipinfo, str(ip), timeout)
            if need_flags or need_geo:
                fallback_futures["ipapi"] = executor.submit(fetch_ipapi_com, str(ip), timeout)
            for key, future in fallback_futures.items():
                try:
                    result = future.result()
                except Exception as exc:  # pragma: no cover
                    result = {
                        "name": key, "ok": False, "data": None,
                        "error": clean_error(exc), "elapsed_ms": None,
                    }
                if key == "ipapiis":
                    ipapiis = result
                elif key == "ipinfo":
                    ipinfo = result
                elif key == "ipapi":
                    ipapi = result

    if not source_ok(ipwho) and not source_ok(ipinfo) and not source_ok(ipapiis) and not source_ok(ipapi):
        # 仍返回 IP 本身，方便排查网络问题
        profile = build_profile(
            ip, ipwho, proxycheck, rdap, ripe, ipinfo, ipapiis, ipapi,
            None, want_risk, fast, deep, detected_via,
            int((time.perf_counter() - started) * 1000),
        )
        profile["ok"] = False
        return profile

    ptr: Optional[str] = None
    if source_ok(proxycheck):
        ptr = first(data_of(proxycheck).get("hostname"))
    if not ptr and source_ok(ipapi):
        ptr = first(data_of(ipapi).get("reverse"))
    if not ptr and deep:
        ptr = reverse_dns(str(ip), timeout=3.0)

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return build_profile(
        ip, ipwho, proxycheck, rdap, ripe, ipinfo, ipapiis, ipapi,
        ptr, want_risk, fast, deep, detected_via, elapsed_ms,
    )


# ---------------------------------------------------------------------------
# 报告汇总
# ---------------------------------------------------------------------------

def build_report(
    target: Optional[str] = None,
    family: str = "auto",
    want_risk: bool = True,
    fast: bool = False,
    deep: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    started = time.perf_counter()
    warnings: List[str] = []
    profiles: List[Dict[str, Any]] = []
    missing: List[Dict[str, Any]] = []
    mode = "target" if target else "current"

    if target:
        ip = parse_ip(target)
        profile = query_ip(
            str(ip), timeout=timeout, want_risk=want_risk,
            fast=fast, deep=deep, detected_via=None,
        )
        profiles.append(profile)
    else:
        families = [4, 6] if family == "auto" else [int(family)]
        detections, missing = detect_public_ips(families, timeout)
        if not detections:
            return {
                "ok": False,
                "app": APP_NAME,
                "version": VERSION,
                "generated_at": now_iso(),
                "elapsed_ms": int((time.perf_counter() - started) * 1000),
                "mode": mode,
                "query": None,
                "primary": None,
                "addresses": [],
                "missing": missing,
                "warnings": ["未检测到任何公网出口 IP。"],
                "disclaimer": DISCLAIMER,
                "error": "未检测到公网 IP，请检查网络连接。",
            }
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(detections))) as executor:
            futures = {
                executor.submit(
                    query_ip,
                    detection["ip"],
                    timeout,
                    want_risk,
                    fast,
                    deep,
                    detection.get("source"),
                ): detection
                for detection in detections
            }
            for future in concurrent.futures.as_completed(futures):
                detection = futures[future]
                try:
                    profiles.append(future.result())
                except Exception as exc:
                    missing.append({
                        "family": detection.get("family"),
                        "message": f"IPv{detection.get('family')} 查询失败",
                        "error": clean_error(exc),
                    })
        profiles.sort(key=lambda item: item.get("version", 0))

    if not profiles:
        return {
            "ok": False,
            "app": APP_NAME,
            "version": VERSION,
            "generated_at": now_iso(),
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "mode": mode,
            "query": target,
            "primary": None,
            "addresses": [],
            "missing": missing,
            "warnings": warnings,
            "disclaimer": DISCLAIMER,
            "error": "查询失败，未获取到数据。",
        }

    primary = next((profile for profile in profiles if profile.get("version") == 4), profiles[0])
    ok = any(profile.get("ok") for profile in profiles)

    if missing:
        warnings.append("部分网络出口未检测到，结果可能不完整。")
    warnings.append("共享人数、原生 IP 与适用场景为估算/推断，不是精确值。")
    if not want_risk:
        warnings.append("已禁用风控查询（--no-risk），风险分显示为未知。")

    return {
        "ok": ok,
        "app": APP_NAME,
        "version": VERSION,
        "generated_at": now_iso(),
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
        "mode": mode,
        "query": target,
        "primary": primary,
        "addresses": profiles,
        "missing": missing,
        "warnings": warnings,
        "disclaimer": DISCLAIMER,
    }


# ---------------------------------------------------------------------------
# 终端渲染
# ---------------------------------------------------------------------------

def terminal_width() -> int:
    try:
        columns = shutil.get_terminal_size((100, 30)).columns
    except Exception:
        columns = 100
    return max(64, min(108, columns - 2))


def risk_ansi(score: Optional[int]) -> str:
    if score is None:
        return C.DIM
    if score <= 20:
        return C.BRIGHT_GREEN
    if score <= 40:
        return C.GREEN
    if score <= 60:
        return C.YELLOW
    if score <= 80:
        return C.BRIGHT_YELLOW
    return C.BRIGHT_RED


def type_ansi(type_code: str) -> str:
    return {
        "residential": C.BRIGHT_GREEN,
        "mobile": C.BRIGHT_CYAN,
        "business": C.CYAN,
        "hosting": C.MAGENTA,
        "proxy": C.BRIGHT_RED,
        "vpn": C.BRIGHT_RED,
        "tor": C.BRIGHT_RED,
        "compromised": C.BRIGHT_RED,
    }.get(type_code, C.DIM)


def kv_lines(label: str, value: Any, label_width: int, content_width: int) -> List[str]:
    value_text = "—" if value is None or value == "" else str(value)
    value_width = max(8, content_width - label_width - 1)
    parts = wrap_disp(value_text, value_width)
    output: List[str] = []
    for index, part in enumerate(parts):
        if index == 0:
            output.append(color(pad_disp(label, label_width), C.DIM) + " " + part)
        else:
            output.append(" " * label_width + " " + part)
    return output


def box_lines(title: str, content: List[str], width: int) -> List[str]:
    content_width = max(20, width - 4)
    if title:
        top_title = f" {title} "
        top = (
            color("╭─", C.DIM + C.CYAN)
            + color(top_title, C.BOLD + C.CYAN)
            + color("─" * max(0, width - 3 - disp_width(top_title)), C.DIM + C.CYAN)
            + color("╮", C.DIM + C.CYAN)
        )
    else:
        top = color("╭" + "─" * (width - 2) + "╮", C.DIM + C.CYAN)
    bottom = color("╰" + "─" * (width - 2) + "╯", C.DIM + C.CYAN)
    output = [top]
    for line in content:
        output.append(color("│", C.DIM + C.CYAN) + " " + pad_disp(line, content_width) + " " + color("│", C.DIM + C.CYAN))
    output.append(bottom)
    return output


def render_profile(profile: Dict[str, Any], target_mode: bool, width: int) -> List[str]:
    content_width = width - 4
    label_width = 11
    loc = profile.get("location") or {}
    asn = profile.get("asn") or {}
    company = profile.get("company") or {}
    network = profile.get("network") or {}
    native = profile.get("native") or {}
    risk = profile.get("risk") or {}
    shared = profile.get("shared") or {}

    content: List[str] = []
    ip_text = color(str(profile.get("ip") or "—"), C.BOLD + C.BRIGHT_CYAN)
    type_text = color(str(network.get("type") or "未知"), type_ansi(str(network.get("type_code") or "unknown")))
    content.append(ip_text + "  " + type_text + color("  ·  " + str(native.get("label") or "未知"), C.DIM))

    loc_parts = [str(part) for part in (loc.get("country"), loc.get("region"), loc.get("city")) if part]
    loc_text = " · ".join(loc_parts) if loc_parts else "位置未知"
    if loc.get("postal"):
        loc_text += " · " + str(loc["postal"])
    content.extend(wrap_disp(loc_text, content_width))

    coords = "未知"
    if loc.get("latitude") is not None and loc.get("longitude") is not None:
        coords = f"{loc['latitude']}, {loc['longitude']}"
    tz_bits = [str(part) for part in (loc.get("timezone"), loc.get("utc_offset")) if part]
    coord_text = coords + (" · " + " · ".join(tz_bits) if tz_bits else "")
    content.extend(wrap_disp(coord_text, content_width))
    content.append("")

    owner = str(asn.get("owner") or "未知")
    isp = str(asn.get("isp") or company.get("name") or "未知")
    domain = str(asn.get("domain") or company.get("domain") or "")
    company_line = isp + (f"  ·  {domain}" if domain else "")
    asn_id = asn.get("id")
    asn_line = f"{asn_id}  {owner}" if asn_id else owner
    content.extend(kv_lines("ASN", asn_line, label_width, content_width))
    content.extend(kv_lines("ASN 所有者", owner, label_width, content_width))
    content.extend(kv_lines("企业 / ISP", company_line, label_width, content_width))
    if company.get("category"):
        content.extend(kv_lines("企业类型", company.get("category"), label_width, content_width))

    type_line = str(network.get("type") or "未知")
    if network.get("type_raw"):
        type_line += f"（{network['type_raw']}）"
    content.extend(kv_lines("网络类型", type_line, label_width, content_width))
    content.extend(kv_lines(
        "原生 IP",
        f"{native.get('label') or '未知'}  ·  置信度 {native.get('confidence') or '—'}",
        label_width, content_width,
    ))

    score = risk.get("score")
    if score is None:
        risk_text = f"未知  ·  {risk.get('note') or ''}".strip()
        content.extend(kv_lines("风控值", risk_text, label_width, content_width))
    else:
        filled = max(0, min(10, int(round(int(score) / 10))))
        bar = "█" * filled + "░" * (10 - filled)
        risk_text = f"{score}/100  {risk.get('level')}  {bar}"
        content.append(
            color(pad_disp("风控值", label_width), C.DIM) + " " +
            color(risk_text, risk_ansi(score))
        )

    shared_range = shared.get("range") or "未知"
    if shared_range == "未知":
        shared_line = "未知（未获取到共享数据）"
    else:
        shared_line = f"{shared_range} 人  ·  {shared.get('level') or '未知'}（估算）"
    content.extend(kv_lines("共享人数", shared_line, label_width, content_width))
    basis = shared.get("basis")
    if basis:
        content.extend(kv_lines("估算依据", basis, label_width, content_width))

    prefix = asn.get("prefix")
    if prefix:
        content.extend(kv_lines("网络段", prefix, label_width, content_width))
    reg_bits = [str(part) for part in (asn.get("country_name") or asn.get("country"), asn.get("registry")) if part]
    if reg_bits:
        content.extend(kv_lines("注册信息", " · ".join(reg_bits), label_width, content_width))
    if asn.get("rir_holder") and asn.get("rir_holder") != owner:
        content.extend(kv_lines("RIR 持有者", asn.get("rir_holder"), label_width, content_width))
    content.extend(kv_lines("反向解析", profile.get("reverse_dns") or "无", label_width, content_width))

    flag_bits = []
    for label, key in (("代理", "is_proxy"), ("VPN", "is_vpn"), ("Tor", "is_tor"), ("机房", "is_hosting"), ("移动", "is_mobile"), ("家宽", "is_residential")):
        flag_bits.append(f"{label} {'是' if network.get(key) else '否'}")
    content.extend(kv_lines("网络标记", " · ".join(flag_bits), label_width, content_width))

    if profile.get("scenarios"):
        scenario_text = "   ".join(
            f"{item.get('name')} {item.get('stars')}" for item in profile["scenarios"]
        )
        content.extend(kv_lines("适用场景", scenario_text, label_width, content_width))

    if profile.get("sources"):
        source_bits = []
        for source in profile["sources"]:
            mark = "✓" if source.get("ok") else "✗"
            elapsed = source.get("elapsed_ms")
            timing = f" {elapsed}ms" if elapsed is not None else ""
            source_bits.append(f"{source.get('name')} {mark}{timing}")
        content.extend(kv_lines("数据源", " · ".join(source_bits), label_width, content_width))

    for warning in profile.get("warnings") or []:
        content.extend(wrap_disp("! " + str(warning), content_width))

    title = f"{profile.get('family', 'IP')} {'查询结果' if target_mode else '出口'}"
    return box_lines(title, content, width)


def render_report(report: Dict[str, Any]) -> None:
    print()
    print("  " + color(APP_TITLE, C.BOLD + C.BRIGHT_CYAN) + color("  ·  本地 IP 体检", C.DIM))
    generated = str(report.get("generated_at") or "").replace("T", " ")
    elapsed = report.get("elapsed_ms")
    meta = generated
    if elapsed is not None:
        meta += f"  ·  耗时 {elapsed / 1000:.1f}s"
    print("  " + color(meta, C.DIM))
    print()

    if not report.get("ok") and not report.get("addresses"):
        print("  " + color("✗ 查询失败", C.BOLD + C.BRIGHT_RED))
        print("  " + str(report.get("error") or "未知错误"))
        for warning in report.get("warnings") or []:
            print("  " + color("! " + str(warning), C.YELLOW))
        print()
        return

    width = terminal_width()
    for profile in report.get("addresses") or []:
        for line in render_profile(profile, report.get("mode") == "target", width):
            print("  " + line)
        print()

    for item in report.get("missing") or []:
        print("  " + color("! " + str(item.get("message") or "出口缺失"), C.YELLOW))
        if item.get("error"):
            print("    " + color(str(item["error"]), C.DIM))
    if report.get("missing"):
        print()

    print("  " + color("说明", C.BOLD) + color("  " + DISCLAIMER, C.DIM))
    print("  " + color("数据源  ", C.DIM) + color("ipwho.is · proxycheck.io · RIPEstat · RDAP · ipinfo.io · ip-api.com", C.DIM))
    print()


# ---------------------------------------------------------------------------
# Web 面板
# ---------------------------------------------------------------------------

HTML_PAGE = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IP PROBE · 本地 IP 体检</title>
<style>
:root {
  --bg: #07111f;
  --bg2: #0b1728;
  --panel: rgba(14, 27, 45, .78);
  --panel-2: rgba(10, 22, 38, .9);
  --line: rgba(148, 187, 233, .14);
  --text: #e6f1ff;
  --muted: #8296ad;
  --cyan: #4de2ff;
  --green: #52f2b0;
  --yellow: #ffd166;
  --red: #ff6b7a;
  --purple: #b18cff;
  --blue: #6aa8ff;
}
* { box-sizing: border-box; }
html, body { min-height: 100%; }
body {
  margin: 0;
  color: var(--text);
  background:
    radial-gradient(900px 500px at 12% -10%, rgba(77,226,255,.14), transparent 60%),
    radial-gradient(700px 500px at 92% 0%, rgba(177,140,255,.12), transparent 55%),
    linear-gradient(160deg, var(--bg), var(--bg2) 55%, #06101d);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
  min-height: 100vh;
}
body::before {
  content: "";
  position: fixed; inset: 0; pointer-events: none; opacity: .35;
  background-image:
    linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px);
  background-size: 44px 44px;
  mask-image: linear-gradient(to bottom, #000, transparent 82%);
}
a { color: var(--cyan); text-decoration: none; }
a:hover { text-decoration: underline; }
.wrap { width: min(1180px, calc(100% - 36px)); margin: 0 auto; position: relative; }
.topbar {
  display: flex; align-items: center; justify-content: space-between; gap: 18px;
  padding: 24px 0 10px;
}
.brand { display: flex; align-items: center; gap: 13px; }
.logo {
  width: 44px; height: 44px; border-radius: 13px; display: grid; place-items: center;
  font-weight: 800; letter-spacing: .5px; color: #04111d;
  background: linear-gradient(135deg, var(--cyan), var(--green));
  box-shadow: 0 0 28px rgba(77,226,255,.28);
}
.brand h1 { margin: 0; font-size: 18px; letter-spacing: 3px; }
.brand p { margin: 3px 0 0; color: var(--muted); font-size: 12px; }
.status { display: flex; align-items: center; gap: 8px; color: var(--muted); font-size: 12px; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); box-shadow: 0 0 12px var(--green); }
.auto { display: inline-flex; align-items: center; gap: 6px; margin-left: 8px; cursor: pointer; user-select: none; }
.auto input { accent-color: var(--cyan); }
.hero {
  display: grid; grid-template-columns: 1.15fr 1fr; gap: 26px; align-items: end;
  padding: 30px 0 22px;
}
.eyebrow { color: var(--cyan); font-size: 11px; letter-spacing: 2.6px; text-transform: uppercase; margin-bottom: 10px; }
.hero h2 { margin: 0; font-size: clamp(28px, 4vw, 48px); line-height: 1.08; letter-spacing: -.5px; }
.hero p { color: var(--muted); margin: 14px 0 0; max-width: 620px; line-height: 1.7; font-size: 14px; }
.search {
  display: flex; gap: 10px; padding: 8px; border-radius: 16px;
  background: var(--panel); border: 1px solid var(--line);
  box-shadow: 0 18px 50px rgba(0,0,0,.28); backdrop-filter: blur(14px);
}
.search input {
  flex: 1; min-width: 0; border: 0; outline: 0; background: transparent; color: var(--text);
  padding: 13px 14px; font-size: 14px;
}
.search input::placeholder { color: #677b92; }
.search button, .ghost {
  border: 0; border-radius: 11px; padding: 12px 20px; cursor: pointer;
  color: #04111d; font-weight: 800; font-size: 14px;
  background: linear-gradient(135deg, var(--cyan), var(--green));
  box-shadow: 0 8px 22px rgba(77,226,255,.18);
}
.search button:disabled { opacity: .55; cursor: wait; }
.ghost {
  color: var(--text); background: rgba(255,255,255,.07);
  border: 1px solid var(--line); box-shadow: none; font-weight: 600;
  padding: 7px 11px; font-size: 12px;
}
.hero-note { margin-top: 12px; color: #6f849c; font-size: 12px; }
.hidden { display: none !important; }
.error {
  margin: 10px 0 0; padding: 14px 16px; border-radius: 12px;
  background: rgba(255,107,122,.1); border: 1px solid rgba(255,107,122,.3); color: #ffc4ca;
}
.loading {
  margin: 28px 0; padding: 30px; border-radius: 18px; text-align: center;
  background: var(--panel); border: 1px solid var(--line); color: var(--muted);
}
.spinner {
  width: 28px; height: 28px; margin: 0 auto 12px; border-radius: 50%;
  border: 3px solid rgba(77,226,255,.16); border-top-color: var(--cyan);
  animation: spin .8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.result-head {
  display: flex; align-items: center; justify-content: space-between; gap: 22px;
  padding: 24px; border-radius: 20px;
  background: linear-gradient(135deg, rgba(16,32,53,.9), rgba(9,20,35,.78));
  border: 1px solid var(--line); box-shadow: 0 20px 60px rgba(0,0,0,.25);
}
.label { color: var(--muted); font-size: 11px; letter-spacing: 2px; text-transform: uppercase; }
.ip-row { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; margin: 8px 0 7px; }
.ip-row h3 { margin: 0; font-size: clamp(24px, 4.6vw, 48px); letter-spacing: -1px; line-height: 1.08; overflow-wrap: anywhere; }
.pill {
  display: inline-flex; align-items: center; gap: 5px; padding: 5px 9px; border-radius: 999px;
  border: 1px solid var(--line); background: rgba(255,255,255,.045);
  color: var(--muted); font-size: 11px; white-space: nowrap;
}
.pill.ok { color: var(--green); border-color: rgba(82,242,176,.25); background: rgba(82,242,176,.08); }
.pill.warn { color: var(--yellow); border-color: rgba(255,209,102,.28); background: rgba(255,209,102,.08); }
.pill.bad { color: var(--red); border-color: rgba(255,107,122,.28); background: rgba(255,107,122,.08); }
.sub { color: var(--muted); font-size: 13px; }
.head-actions { display: flex; align-items: center; gap: 20px; }
.ring {
  --p: 0; --risk-color: #5d7188;
  width: 104px; height: 104px; border-radius: 50%; position: relative; flex: 0 0 auto;
  display: grid; place-items: center;
  background: conic-gradient(var(--risk-color) calc(var(--p) * 1%), rgba(255,255,255,.075) 0);
  box-shadow: 0 0 34px color-mix(in srgb, var(--risk-color) 24%, transparent);
}
.ring::before { content: ""; position: absolute; inset: 8px; border-radius: 50%; background: #0a1626; border: 1px solid rgba(255,255,255,.06); }
.ring > div { position: relative; text-align: center; }
.ring strong { display: block; font-size: 28px; line-height: 1; }
.ring span { display: block; margin-top: 5px; color: var(--muted); font-size: 10px; letter-spacing: 1.6px; }
.head-meta { display: flex; flex-direction: column; gap: 7px; align-items: flex-start; }
.tabs { display: flex; gap: 8px; margin: 18px 0 12px; }
.tab {
  padding: 8px 12px; border-radius: 10px; border: 1px solid var(--line);
  background: rgba(255,255,255,.035); color: var(--muted); cursor: pointer; font-size: 12px;
}
.tab.active { color: #04111d; background: linear-gradient(135deg, var(--cyan), var(--green)); border-color: transparent; font-weight: 800; }
.grid { display: grid; gap: 14px; }
.stats { grid-template-columns: repeat(4, minmax(0, 1fr)); margin-top: 14px; }
.stat, .panel {
  background: var(--panel); border: 1px solid var(--line); border-radius: 16px;
  box-shadow: 0 14px 40px rgba(0,0,0,.18); backdrop-filter: blur(12px);
}
.stat { padding: 16px; min-height: 112px; }
.stat .k { color: var(--muted); font-size: 11px; letter-spacing: 1.4px; text-transform: uppercase; margin-bottom: 10px; }
.stat .v { font-size: 15px; line-height: 1.45; overflow-wrap: anywhere; }
.stat .s { margin-top: 6px; color: #6f849c; font-size: 11px; line-height: 1.4; overflow-wrap: anywhere; }
.stat .v.big { font-size: 22px; font-weight: 800; letter-spacing: -.4px; }
.two { grid-template-columns: 1.08fr .92fr; margin-top: 14px; }
.panel { padding: 18px; min-width: 0; }
.panel h3 { margin: 0 0 14px; font-size: 14px; letter-spacing: .4px; }
.panel h3 .hint { color: var(--muted); font-weight: 400; font-size: 11px; margin-left: 5px; }
.flag-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 9px; }
.flag-item {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  padding: 10px 11px; border-radius: 10px; background: rgba(255,255,255,.035);
  border: 1px solid rgba(255,255,255,.045); color: var(--muted); font-size: 12px;
}
.flag-item strong { color: var(--text); font-weight: 700; }
.flag-item.on { border-color: rgba(255,107,122,.22); background: rgba(255,107,122,.07); }
.flag-item.on strong { color: var(--red); }
.meter { height: 7px; border-radius: 99px; background: rgba(255,255,255,.07); overflow: hidden; margin-top: 15px; }
.meter > i { display: block; height: 100%; width: 0; border-radius: inherit; transition: width .5s ease; }
.risk-note { margin-top: 8px; color: var(--muted); font-size: 11px; }
.scenario { display: grid; grid-template-columns: 82px 1fr 64px; gap: 10px; align-items: center; padding: 8px 0; border-bottom: 1px dashed rgba(255,255,255,.06); }
.scenario:last-child { border-bottom: 0; }
.scenario .name { font-size: 12px; color: var(--muted); }
.scenario .stars { color: var(--yellow); letter-spacing: 2px; font-size: 13px; white-space: nowrap; }
.scenario .lab { text-align: right; font-size: 11px; color: var(--muted); }
.scenario .bar { grid-column: 2 / 3; height: 4px; margin-top: -5px; border-radius: 99px; background: rgba(255,255,255,.07); overflow: hidden; }
.scenario .bar i { display: block; height: 100%; border-radius: inherit; background: linear-gradient(90deg, var(--cyan), var(--green)); }
.map-box { position: relative; border-radius: 12px; overflow: hidden; border: 1px solid var(--line); background: #0a1626; min-height: 250px; }
.map-box iframe { width: 100%; height: 250px; border: 0; display: block; filter: saturate(.85) contrast(1.03); }
.map-fallback { padding: 26px 16px; color: var(--muted); text-align: center; font-size: 12px; }
.map-link { margin-top: 10px; font-size: 12px; }
.sources { display: flex; flex-direction: column; gap: 8px; }
.source { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 9px 10px; border-radius: 9px; background: rgba(255,255,255,.03); font-size: 12px; }
.source .name { color: var(--muted); }
.source .right { display: flex; align-items: center; gap: 8px; }
.source .ms { color: #6f849c; font-size: 11px; }
.ok-dot { color: var(--green); }
.bad-dot { color: var(--red); }
.warnings { margin-top: 12px; display: flex; flex-direction: column; gap: 6px; }
.warning { padding: 8px 10px; border-radius: 8px; background: rgba(255,209,102,.07); border: 1px solid rgba(255,209,102,.16); color: #e9cf8f; font-size: 11px; line-height: 1.5; }
.disclaimer { margin: 20px 0 34px; color: #62768d; font-size: 11px; line-height: 1.7; text-align: center; }
.footer-links { display: flex; justify-content: center; gap: 14px; margin-top: 8px; }
.toast {
  position: fixed; left: 50%; bottom: 26px; transform: translateX(-50%) translateY(20px);
  background: #10243c; border: 1px solid var(--line); color: var(--text);
  padding: 10px 16px; border-radius: 10px; font-size: 12px; opacity: 0; pointer-events: none;
  transition: .25s ease; z-index: 9;
}
.toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
@media (max-width: 900px) {
  .hero { grid-template-columns: 1fr; padding-top: 18px; }
  .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .two { grid-template-columns: 1fr; }
  .result-head { flex-direction: column; align-items: flex-start; }
  .head-actions { width: 100%; justify-content: space-between; }
  .ring { width: 88px; height: 88px; }
}
@media (max-width: 520px) {
  .wrap { width: min(100% - 22px, 1180px); }
  .status { display: none; }
  .stats { grid-template-columns: 1fr; }
  .flag-grid { grid-template-columns: repeat(2, 1fr); }
  .search { flex-direction: column; }
  .search button { width: 100%; }
  .ip-row h3 { font-size: 24px; }
}
</style>
</head>
<body>
<div class="wrap">
  <header class="topbar">
    <div class="brand">
      <div class="logo">IP</div>
      <div>
        <h1>IP PROBE</h1>
        <p>本地 IP 体检 · 类似 ping0.cc</p>
      </div>
    </div>
    <div class="status">
      <span class="dot"></span>
      <span id="clock">--:--:--</span>
      <label class="auto"><input type="checkbox" id="auto-refresh"> 自动刷新 30s</label>
    </div>
  </header>

  <section class="hero">
    <div>
      <div class="eyebrow">CURRENT EGRESS / TARGET LOOKUP</div>
      <h2>看清你的 IP 底细</h2>
      <p>公网出口、归属地、ASN、企业、经纬度、IP 类型、风控值、共享人数估算。双栈 IPv4 / IPv6 自动识别。</p>
    </div>
    <div>
      <form id="query-form" class="search">
        <input id="ip-input" autocomplete="off" spellcheck="false" placeholder="留空检测当前 IP，或输入 8.8.8.8 / 2001:4860:4860::8888">
        <button type="submit" id="query-btn">查询</button>
      </form>
      <div class="hero-note">提示：留空 = 当前公网出口；输入任意公网 IPv4 / IPv6 = 目标查询。</div>
    </div>
  </section>

  <div id="error" class="error hidden"></div>
  <div id="loading" class="loading hidden">
    <div class="spinner"></div>
    <div>正在查询多个数据源，通常需要 2–8 秒…</div>
  </div>

  <section id="result" class="hidden">
    <div class="result-head">
      <div class="ip-block">
        <div class="label">IP 地址</div>
        <div class="ip-row">
          <h3 id="ip-value">--</h3>
          <button id="copy-btn" class="ghost" type="button">复制</button>
          <span id="ip-version" class="pill">IPv4</span>
        </div>
        <div id="ip-sub" class="sub">--</div>
      </div>
      <div class="head-actions">
        <div id="risk-ring" class="ring"><div><strong id="risk-score">--</strong><span>风险值</span></div></div>
        <div class="head-meta">
          <span id="native-badge" class="pill">--</span>
          <span id="type-badge" class="pill">--</span>
          <span id="risk-level-badge" class="pill">--</span>
        </div>
      </div>
    </div>

    <div id="family-tabs" class="tabs hidden"></div>

    <div class="grid stats">
      <div class="stat"><div class="k">位置</div><div id="stat-location" class="v">--</div><div id="stat-location-sub" class="s">--</div></div>
      <div class="stat"><div class="k">ASN</div><div id="stat-asn" class="v big">--</div><div id="stat-asn-sub" class="s">--</div></div>
      <div class="stat"><div class="k">ASN 所有者</div><div id="stat-asn-owner" class="v">--</div><div id="stat-asn-owner-sub" class="s">--</div></div>
      <div class="stat"><div class="k">企业 / ISP</div><div id="stat-company" class="v">--</div><div id="stat-company-sub" class="s">--</div></div>
      <div class="stat"><div class="k">经纬度</div><div id="stat-coords" class="v">--</div><div id="stat-coords-sub" class="s">--</div></div>
      <div class="stat"><div class="k">时区</div><div id="stat-timezone" class="v">--</div><div id="stat-timezone-sub" class="s">--</div></div>
      <div class="stat"><div class="k">网络段</div><div id="stat-prefix" class="v">--</div><div id="stat-prefix-sub" class="s">--</div></div>
      <div class="stat"><div class="k">注册信息</div><div id="stat-registry" class="v">--</div><div id="stat-registry-sub" class="s">--</div></div>
      <div class="stat"><div class="k">共享人数</div><div id="stat-shared" class="v big">--</div><div id="stat-shared-sub" class="s">--</div></div>
      <div class="stat"><div class="k">反向解析</div><div id="stat-ptr" class="v">--</div><div id="stat-ptr-sub" class="s">--</div></div>
      <div class="stat"><div class="k">原生 IP（推断）</div><div id="stat-native" class="v">--</div><div id="stat-native-sub" class="s">--</div></div>
      <div class="stat"><div class="k">查询耗时</div><div id="stat-elapsed" class="v big">--</div><div id="stat-elapsed-sub" class="s">--</div></div>
    </div>

    <div class="grid two">
      <section class="panel">
        <h3>网络指纹 <span class="hint">代理 / VPN / 机房检测</span></h3>
        <div id="flags" class="flag-grid"></div>
        <div class="meter"><i id="risk-meter"></i></div>
        <div id="risk-note" class="risk-note">--</div>
      </section>
      <section class="panel">
        <h3>适用场景 <span class="hint">启发式，仅供参考</span></h3>
        <div id="scenarios"></div>
      </section>
    </div>

    <div class="grid two">
      <section class="panel">
        <h3>地图定位 <span class="hint">城市级</span></h3>
        <div id="map" class="map-box"></div>
        <div id="map-link" class="map-link"></div>
      </section>
      <section class="panel">
        <h3>数据源</h3>
        <div id="sources" class="sources"></div>
        <div id="warnings" class="warnings"></div>
      </section>
    </div>

    <footer class="disclaimer">
      <div id="disclaimer-text">--</div>
      <div class="footer-links">
        <a href="https://ipwho.is" target="_blank" rel="noreferrer">ipwho.is</a>
        <a href="https://proxycheck.io" target="_blank" rel="noreferrer">proxycheck.io</a>
        <a href="https://stat.ripe.net" target="_blank" rel="noreferrer">RIPEstat</a>
        <a href="https://rdap.org" target="_blank" rel="noreferrer">RDAP</a>
      </div>
    </footer>
  </section>
</div>
<div id="toast" class="toast"></div>

<script>
(() => {
  const $ = (id) => document.getElementById(id);
  const state = { report: null, index: 0, loading: false, autoTimer: null, countdown: 30 };
  const RISK_COLORS = { clean: "#52f2b0", low: "#8ee36b", medium: "#ffd166", high: "#ff9f5a", critical: "#ff6b7a", unknown: "#5d7188" };
  const TYPE_CLASS = { residential: "ok", mobile: "ok", business: "", hosting: "warn", proxy: "bad", vpn: "bad", tor: "bad", compromised: "bad", private: "warn", unknown: "" };

  function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
  }
  function text(id, value) { const el = $(id); if (el) el.textContent = value ?? "—"; }
  function html(id, value) { const el = $(id); if (el) el.innerHTML = value; }
  function fmtMs(ms) { if (ms === null || ms === undefined) return "—"; return `${(ms / 1000).toFixed(1)}s`; }
  function flagEmoji(code) {
    code = String(code || "").toUpperCase();
    if (!/^[A-Z]{2}$/.test(code)) return "🏳️";
    return String.fromCodePoint(...[...code].map((ch) => 0x1F1E6 + ch.charCodeAt(0) - 65));
  }
  function toast(message) {
    const el = $("toast");
    el.textContent = message;
    el.classList.add("show");
    clearTimeout(el._timer);
    el._timer = setTimeout(() => el.classList.remove("show"), 1800);
  }
  function setPill(id, label, cls) {
    const el = $(id);
    el.textContent = label || "—";
    el.className = "pill" + (cls ? " " + cls : "");
  }

  async function loadReport(params = {}) {
    if (state.loading) return;
    state.loading = true;
    $("query-btn").disabled = true;
    $("error").classList.add("hidden");
    $("result").classList.add("hidden");
    $("loading").classList.remove("hidden");
    try {
      const query = new URLSearchParams(params);
      const response = await fetch(`/api/ip?${query.toString()}`, { cache: "no-store" });
      const report = await response.json();
      if (!response.ok) throw new Error(report.error || `HTTP ${response.status}`);
      state.report = report;
      state.index = 0;
      if (report.primary && report.addresses && report.addresses.length > 1) {
        const primaryIndex = report.addresses.findIndex((item) => item.ip === report.primary.ip);
        if (primaryIndex >= 0) state.index = primaryIndex;
      }
      renderReport(report);
      $("result").classList.remove("hidden");
    } catch (error) {
      $("error").textContent = `查询失败：${error.message || error}`;
      $("error").classList.remove("hidden");
    } finally {
      state.loading = false;
      $("query-btn").disabled = false;
      $("loading").classList.add("hidden");
    }
  }

  function renderReport(report) {
    if (!report.ok && (!report.addresses || !report.addresses.length)) {
      throw new Error(report.error || "查询失败");
    }
    const profiles = report.addresses || [];
    if (!profiles.length) throw new Error("没有返回结果");
    if (state.index >= profiles.length) state.index = 0;
    renderProfile(profiles[state.index], report);
    $("disclaimer-text").textContent = report.disclaimer || "";
    renderFamilyTabs(profiles);
  }

  function renderFamilyTabs(profiles) {
    const tabs = $("family-tabs");
    if (!profiles || profiles.length <= 1) {
      tabs.classList.add("hidden");
      tabs.innerHTML = "";
      return;
    }
    tabs.classList.remove("hidden");
    tabs.innerHTML = profiles.map((profile, index) => (
      `<button type="button" class="tab ${index === state.index ? "active" : ""}" data-index="${index}">${esc(profile.family)} · ${esc(profile.ip)}</button>`
    )).join("");
    tabs.querySelectorAll(".tab").forEach((button) => {
      button.addEventListener("click", () => {
        state.index = Number(button.dataset.index);
        renderReport(state.report);
      });
    });
  }

  function renderProfile(profile, report) {
    const loc = profile.location || {};
    const asn = profile.asn || {};
    const company = profile.company || {};
    const network = profile.network || {};
    const native = profile.native || {};
    const risk = profile.risk || {};
    const shared = profile.shared || {};

    document.title = `${profile.ip} · IP PROBE`;
    text("ip-value", profile.ip);
    setPill("ip-version", profile.family || `IPv${profile.version}`, "");
    const locBits = [loc.country, loc.region, loc.city].filter(Boolean);
    text("ip-sub", [locBits.join(" · "), profile.is_public ? "公网地址" : "非公网地址"].filter(Boolean).join("  ·  "));

    const riskScore = risk.score;
    const riskKey = riskScore === null || riskScore === undefined ? "unknown" : (riskScore <= 20 ? "clean" : riskScore <= 40 ? "low" : riskScore <= 60 ? "medium" : riskScore <= 80 ? "high" : "critical");
    const riskColor = RISK_COLORS[riskKey] || RISK_COLORS.unknown;
    $("risk-ring").style.setProperty("--p", riskScore ?? 0);
    $("risk-ring").style.setProperty("--risk-color", riskColor);
    text("risk-score", riskScore === null || riskScore === undefined ? "--" : riskScore);
    setPill("risk-level-badge", riskScore === null || riskScore === undefined ? "风险未知" : `风险 ${risk.level}`, riskKey === "clean" || riskKey === "low" ? "ok" : riskKey === "medium" ? "warn" : riskKey === "unknown" ? "" : "bad");

    const nativeLabel = native.label || "未知";
    setPill("native-badge", nativeLabel, native.is_native === true ? "ok" : native.is_native === false ? "warn" : "");
    setPill("type-badge", network.type || "未知", TYPE_CLASS[network.type_code] || "");

    text("stat-location", [loc.flag, loc.country].filter(Boolean).join(" ") || "未知");
    text("stat-location-sub", [loc.region, loc.city, loc.postal].filter(Boolean).join(" · ") || `精度：${loc.accuracy || "未知"}`);
    text("stat-asn", asn.id || "未知");
    text("stat-asn-sub", asn.registry ? `注册局 ${asn.registry}` : (asn.prefix || "—"));
    text("stat-asn-owner", asn.owner || "未知");
    text("stat-asn-owner-sub", asn.rir_holder && asn.rir_holder !== asn.owner ? asn.rir_holder : (asn.domain || "—"));
    text("stat-company", company.name || "未知");
    text("stat-company-sub", [company.category, company.domain].filter(Boolean).join(" · ") || "—");
    const coords = loc.latitude !== null && loc.latitude !== undefined && loc.longitude !== null && loc.longitude !== undefined
      ? `${Number(loc.latitude).toFixed(4)}, ${Number(loc.longitude).toFixed(4)}` : "未知";
    text("stat-coords", coords);
    text("stat-coords-sub", `定位精度：${loc.accuracy || "未知"}`);
    text("stat-timezone", loc.timezone || "未知");
    text("stat-timezone-sub", loc.utc_offset || "—");
    text("stat-prefix", asn.prefix || "未知");
    text("stat-prefix-sub", asn.country ? `注册国家/地区：${asn.country_name || asn.country}` : "—");
    text("stat-registry", [asn.country_name || asn.country, asn.registry].filter(Boolean).join(" · ") || "未知");
    text("stat-registry-sub", native.reason || "—");
    text("stat-shared", `${shared.range || "未知"}`);
    text("stat-shared-sub", `${shared.level || "未知"} · 估算`);
    text("stat-ptr", profile.reverse_dns || "无");
    text("stat-ptr-sub", profile.reverse_dns ? "反向 DNS" : "未获取到 PTR");
    text("stat-native", native.label || "未知");
    text("stat-native-sub", `置信度：${native.confidence || "—"}`);
    text("stat-elapsed", fmtMs(profile.elapsed_ms));
    text("stat-elapsed-sub", report.mode === "current" ? "当前出口检测" : "目标 IP 查询");

    const flags = [
      ["代理", network.is_proxy], ["VPN", network.is_vpn], ["Tor", network.is_tor],
      ["机房", network.is_hosting], ["移动网络", network.is_mobile], ["家庭宽带", network.is_residential],
    ];
    html("flags", flags.map(([label, value]) => (
      `<div class="flag-item ${value ? "on" : ""}"><span>${esc(label)}</span><strong>${value ? "是" : "否"}</strong></div>`
    )).join(""));

    const pct = riskScore === null || riskScore === undefined ? 0 : Math.max(0, Math.min(100, riskScore));
    $("risk-meter").style.width = `${pct}%`;
    $("risk-meter").style.background = `linear-gradient(90deg, ${riskColor}, ${riskColor})`;
    text("risk-note", risk.note || "无风控说明");

    html("scenarios", (profile.scenarios || []).map((item) => (
      `<div class="scenario">
        <div class="name">${esc(item.name)}</div>
        <div class="stars">${esc(item.stars)}</div>
        <div class="lab">${esc(item.label)}</div>
        <div class="bar"><i style="width:${Math.max(0, Math.min(100, (item.score || 0) * 20))}%"></i></div>
      </div>`
    )).join("") || "<div class='map-fallback'>暂无场景数据</div>");

    renderMap(loc);
    renderSources(profile, report);
  }

  function renderMap(loc) {
    const lat = loc.latitude;
    const lon = loc.longitude;
    if (lat === null || lat === undefined || lon === null || lon === undefined) {
      html("map", `<div class="map-fallback">没有可用的经纬度</div>`);
      $("map-link").innerHTML = "";
      return;
    }
    const delta = 0.06;
    const bbox = [lon - delta, lat - delta, lon + delta, lat + delta].map((n) => Number(n).toFixed(4)).join("%2C");
    const src = `https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&layer=mapnik&marker=${lat}%2C${lon}`;
    html("map", `<iframe src="${src}" loading="lazy" referrerpolicy="no-referrer" title="OpenStreetMap"></iframe>`);
    $("map-link").innerHTML = `<a href="https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=12/${lat}/${lon}" target="_blank" rel="noreferrer">在 OpenStreetMap 中打开 ↗</a>`;
  }

  function renderSources(profile, report) {
    html("sources", (profile.sources || []).map((source) => (
      `<div class="source">
        <span class="name">${esc(source.name)}</span>
        <span class="right"><span class="${source.ok ? "ok-dot" : "bad-dot"}">${source.ok ? "●" : "●"}</span><span>${source.ok ? "可用" : "失败"}</span><span class="ms">${source.elapsed_ms ?? "—"}ms</span></span>
      </div>`
    )).join("") || "<div class='map-fallback'>暂无来源信息</div>");
    const warnings = [...(report.warnings || []), ...(profile.warnings || [])];
    html("warnings", [...new Set(warnings)].map((warning) => `<div class="warning">! ${esc(warning)}</div>`).join(""));
  }

  function currentQuery() {
    const value = $("ip-input").value.trim();
    const params = { family: "auto", risk: "1" };
    if (value) params.ip = value;
    return params;
  }

  function updateClock() {
    $("clock").textContent = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  }

  $("query-form").addEventListener("submit", (event) => {
    event.preventDefault();
    state.autoTimer && clearInterval(state.autoTimer);
    state.autoTimer = null;
    $("auto-refresh").checked = false;
    loadReport(currentQuery());
  });

  $("copy-btn").addEventListener("click", async () => {
    const ip = $("ip-value").textContent;
    try {
      await navigator.clipboard.writeText(ip);
      toast("IP 已复制");
    } catch {
      const range = document.createRange();
      range.selectNodeContents($("ip-value"));
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      toast("已选中，请按 Ctrl+C");
    }
  });

  $("auto-refresh").addEventListener("change", (event) => {
    if (state.autoTimer) { clearInterval(state.autoTimer); state.autoTimer = null; }
    if (!event.target.checked) return;
    state.countdown = 30;
    state.autoTimer = setInterval(() => {
      state.countdown -= 1;
      if ($("ip-input").value.trim()) {
        $("auto-refresh").checked = false;
        clearInterval(state.autoTimer);
        state.autoTimer = null;
        return;
      }
      if (state.countdown <= 0) {
        state.countdown = 30;
        loadReport({ family: "auto", risk: "1" });
      }
    }, 1000);
  });

  updateClock();
  setInterval(updateClock, 1000);
  loadReport({ family: "auto", risk: "1" });
})();
</script>
</body>
</html>
"""


def _report_cache_key(
    target: Optional[str], family: str, want_risk: bool, fast: bool, deep: bool,
) -> Tuple[str, str, bool, bool, bool]:
    return (target or "__current__", family, want_risk, fast, deep)


_REPORT_CACHE: Dict[Tuple[str, str, bool, bool, bool], Tuple[float, Dict[str, Any]]] = {}
_REPORT_CACHE_LOCK = threading.Lock()
_REPORT_CACHE_TTL = 300.0


def cached_build_report(
    target: Optional[str], family: str, want_risk: bool, fast: bool, deep: bool,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    key = _report_cache_key(target, family, want_risk, fast, deep)
    now = time.time()
    with _REPORT_CACHE_LOCK:
        cached = _REPORT_CACHE.get(key)
        if cached and cached[0] > now:
            return cached[1]
    report = build_report(
        target=target, family=family, want_risk=want_risk,
        fast=fast, deep=deep, timeout=timeout,
    )
    if report.get("ok"):
        with _REPORT_CACHE_LOCK:
            _REPORT_CACHE[key] = (now + _REPORT_CACHE_TTL, report)
    return report


def run_server(host: str, port: int, open_browser: bool, debug: bool) -> int:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"{APP_NAME}/{VERSION}"

        def log_message(self, fmt: str, *args: Any) -> None:
            if debug:
                sys.stderr.write(f"[web] {self.address_string()} - {fmt % args}\n")

        def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path in ("/", "/index.html"):
                self._send_html(HTML_PAGE)
                return
            if parsed.path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return
            if parsed.path == "/api/health":
                self._send_json(200, {"ok": True, "app": APP_NAME, "version": VERSION})
                return
            if parsed.path == "/api/ip":
                query = urllib.parse.parse_qs(parsed.query)
                target = (query.get("ip", [""])[0] or "").strip() or None
                family = (query.get("family", ["auto"])[0] or "auto").strip()
                if family not in ("auto", "4", "6"):
                    family = "auto"
                want_risk = (query.get("risk", ["1"])[0] or "1") != "0"
                fast = (query.get("fast", ["0"])[0] or "0") == "1"
                deep = (query.get("deep", ["0"])[0] or "0") == "1"
                try:
                    report = cached_build_report(
                        target=target, family=family, want_risk=want_risk,
                        fast=fast, deep=deep, timeout=DEFAULT_TIMEOUT,
                    )
                    self._send_json(200 if report.get("ok") else 502, report)
                except ProbeError as exc:
                    self._send_json(400, {"ok": False, "error": str(exc)})
                except Exception as exc:  # pragma: no cover - 防御性
                    if debug:
                        import traceback
                        traceback.print_exc()
                    self._send_json(500, {"ok": False, "error": f"服务器内部错误：{clean_error(exc)}"})
                return
            self._send_json(404, {"ok": False, "error": "Not found"})

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    try:
        httpd = Server((host, port), Handler)
    except OSError as exc:
        print(f"无法监听 {host}:{port}：{exc}", file=sys.stderr)
        return 1

    display_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{display_host}:{port}/"
    print()
    print("  " + color(APP_TITLE, C.BOLD + C.BRIGHT_CYAN) + color("  ·  本地 Web 面板", C.DIM))
    print("  " + color(url, C.BRIGHT_CYAN))
    print("  " + color("按 Ctrl+C 停止服务", C.DIM))
    print()

    if open_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  已停止。")
    finally:
        httpd.server_close()
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ip_probe.py",
        description="本地 IP 体检工具：公网 IP、归属地、ASN、企业、IP 类型、风控值、共享人数估算。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  python ip_probe.py                          # 检测当前公网 IPv4/IPv6\n"
            "  python ip_probe.py --ip 8.8.8.8             # 查询指定 IP\n"
            "  python ip_probe.py --ip 8.8.8.8 --deep      # 额外查询 RIPEstat 与 PTR\n"
            "  python ip_probe.py --json                   # JSON 输出\n"
            "  python ip_probe.py --serve --open           # 启动本地 Web 面板\n"
        ),
    )
    parser.add_argument("target", nargs="?", help="要查询的 IP；省略则检测当前公网出口")
    parser.add_argument("--ip", dest="ip_option", help="要查询的 IP（与位置参数二选一）")
    parser.add_argument("--family", choices=("auto", "4", "6"), default="auto", help="当前出口检测的 IP 协议族（默认 auto）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--no-color", action="store_true", help="禁用终端颜色")
    parser.add_argument("--no-risk", action="store_true", help="不查询 proxycheck.io 风控值")
    parser.add_argument("--fast", action="store_true", help="快速模式：跳过 RDAP 注册地查询")
    parser.add_argument("--deep", action="store_true", help="深度模式：额外查询 RIPEstat 与反向 DNS")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="单次 HTTP 超时秒数（默认 12）")
    parser.add_argument("--serve", action="store_true", help="启动本地 Web 面板")
    parser.add_argument("--host", default="127.0.0.1", help="Web 监听地址（默认 127.0.0.1）")
    parser.add_argument("--port", type=int, default=8848, help="Web 监听端口（默认 8848）")
    parser.add_argument("--open", action="store_true", help="启动 Web 面板后打开浏览器")
    parser.add_argument("--quiet", action="store_true", help="不输出进度提示")
    parser.add_argument("--debug", action="store_true", help="显示调试信息")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    setup_stdio()
    enable_windows_ansi()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.fast and args.deep:
        parser.error("--fast 与 --deep 不能同时使用")
    if args.timeout <= 0:
        parser.error("--timeout 必须大于 0")
    if args.ip_option and args.target:
        parser.error("位置参数和 --ip 只能使用一个")
    target = args.ip_option or args.target

    C.enabled = (not args.no_color) and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    if args.serve:
        return run_server(args.host, args.port, args.open, args.debug)

    try:
        if not args.quiet and not args.json:
            print(color("  正在检测，请稍候…", C.DIM), file=sys.stderr)
        report = build_report(
            target=target,
            family=args.family,
            want_risk=not args.no_risk,
            fast=args.fast,
            deep=args.deep,
            timeout=args.timeout,
        )
    except ProbeError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2))
        else:
            print(color("  ✗ " + str(exc), C.BOLD + C.BRIGHT_RED), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n  已取消。", file=sys.stderr)
        return 130

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        render_report(report)
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

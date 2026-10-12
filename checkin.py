#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import os
import random
import re
import shutil
import ssl
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

# ────────────────────────── 常量 ──────────────────────────

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
QUOTA_PER_UNIT = 500000  # New API: quota / 500000 = 美元
MAX_RETRIES = 3          # 仅网络层/限流错误重试（业务失败不重试，避免重复 POST）
RETRY_BACKOFF = 2.0
RETRY_BACKOFF_MAX = 30.0   # 单次退避上限（秒）
RETRY_JITTER = 1.5         # 退避随机抖动上限（秒），避免多账号整齐重撞限流窗口
MAX_RETRY_AFTER = 120.0    # 尊重服务端 Retry-After，但不超过该值
RETRYABLE_STATUS = {429, 502, 503, 504}  # 限流 / 瞬时服务端错误，退避后可重试

# 签到状态分类词表（源自 newapi-checkin providers/base.py 的实测沉淀）
ALREADY_DONE_PATTERNS = ["已签到", "今日已", "已领取", "明天再来", "already"]
NOT_OPEN_PATTERNS = [
    "签到功能未启用", "签到功能已关闭", "签到功能暂未开放", "签到未开放",
    "签到已关闭", "未开启签到", "活动未开始", "活动已结束", "活动未开放",
]
LOGIN_PATTERNS = ["登录", "unauthorized", "not logged in", "未登录", "无权", "权限不足"]
VERIFICATION_PATTERNS = [
    "turnstile", "captcha", "验证码", "人机验证", "请完成验证",
]

# 「HTTP 拿到的是防护页而不是业务响应」的特征。
# challenge = 可解挑战（需真浏览器执行 JS）；block = 出口 IP 被安全规则终局拒绝，
# 换浏览器也没用，只能换代理节点 —— 两者必须分开报告。
CF_CHALLENGE_PATTERNS = [
    "just a moment", "checking your browser", "cf-challenge", "cf_chl_opt",
]
CF_BLOCK_PATTERNS = [
    "sorry, you have been blocked", "attention required! | cloudflare",
    "you are unable to access", "error 1020", "access denied | cloudflare",
    "cf-error-details",
]
ALIYUN_WAF_PATTERNS = ["aliyun_waf", "acw_sc__", "slidecaptcha", "var arg1="]

# 签到接口被 Turnstile 拒绝的回执特征（源自 newapi-checkin 实测）
TURNSTILE_MISSING_PATTERNS = [
    "turnstile token 为空", "turnstile token is empty", "turnstile 校验失败",
]


# ────────────────────────── 数据结构 ──────────────────────────

@dataclass
class ApiError(Exception):
    message: str
    status: int | None = None
    payload: object = None
    transient: bool = False
    kind: str = ""  # waf_challenge / waf_block / html

    def __str__(self) -> str:
        return self.message


@dataclass
class SiteConfig:
    name: str
    base_url: str
    user_id: str = ""
    access_token: str = ""
    cookie: str = ""
    enabled: bool = True
    referer_path: str = "/profile"
    verify_ssl: bool = True
    proxy: str = ""
    turnstile: str = "auto"  # auto=被拒时自动浏览器求解 / off=不求解
    browser: str = "auto"    # auto=真实Chrome优先,Camoufox兜底 / chrome / camoufox
    quota_per_unit: int = QUOTA_PER_UNIT
    raw: dict = field(default_factory=dict)


@dataclass
class Outcome:
    name: str
    base_url: str
    status: str            # success / already_done / need_login / need_verification / not_open / network_error / error / need_config
    message: str
    quota_awarded_usd: float | None = None
    current_quota_usd: float | None = None
    username: str = ""


# ────────────────────────── 工具 ──────────────────────────

def mask(text: str, keep: int = 6) -> str:
    """脱敏：长凭据只保留头尾少量字符。"""
    text = str(text or "")
    if len(text) <= keep * 2:
        return "***" if text else ""
    return text[:keep] + "***" + text[-keep:]


def fmt_usd(value) -> str:
    return f"${float(value):.4f}".rstrip("0").rstrip(".") if value is not None else "N/A"


def contains_any(haystack: str, needles) -> bool:
    h = (haystack or "").lower()
    return any(str(n).lower() in h for n in needles)


def waf_page_kind(text: str) -> str:
    """判断 HTML 响应属于哪类防护页：challenge(可解) / block(IP被封) / ''。"""
    if not text:
        return ""
    if contains_any(text, CF_BLOCK_PATTERNS):
        return "waf_block"
    if contains_any(text, CF_CHALLENGE_PATTERNS) or contains_any(text, ALIYUN_WAF_PATTERNS):
        return "waf_challenge"
    return ""


def describe_html(text: str) -> str:
    """把 HTML 响应压成一句诊断（页面标题 + 长度），不倾倒整页。"""
    kind = waf_page_kind(text)
    title = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
    title_text = (title.group(1).strip()[:60] if title else "")
    ray = re.search(r"Ray ID:\s*(?:<[^>]+>\s*)*([0-9a-f]{8,32})", text or "", re.I)
    if kind == "waf_block":
        extra = f"，Ray ID={ray.group(1)}" if ray else ""
        return f"Cloudflare 已拒绝当前出口 IP{extra}（IP 被站点安全规则封禁，需更换代理节点）"
    if kind == "waf_challenge":
        return f"站点返回人机验证挑战页（{title_text or 'Cloudflare/WAF'}），纯 HTTP 无法通过，需浏览器执行 JS"
    if title_text:
        return f"接口返回 HTML 而非 JSON（title={title_text}，共 {len(text)} 字符）"
    return f"接口返回 HTML 而非 JSON（共 {len(text)} 字符）"


def log(msg: str) -> None:
    print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def _retry_after_seconds(headers) -> float | None:
    """解析 Retry-After（秒数或 HTTP 日期），并夹在 [0, MAX_RETRY_AFTER] 内。"""
    if not headers:
        return None
    raw = (headers.get("Retry-After") or "").strip()
    if not raw:
        return None
    if raw.isdigit():
        return min(float(raw), MAX_RETRY_AFTER)
    try:
        when = dt.datetime.strptime(raw, "%a, %d %b %Y %H:%M:%S %Z")
    except ValueError:
        return None
    return min(max((when - dt.datetime.utcnow()).total_seconds(), 0.0), MAX_RETRY_AFTER)


def _backoff_delay(attempt: int, retry_after: float | None = None) -> float:
    """指数退避 + 抖动；服务端给了 Retry-After 就优先听它的。"""
    if retry_after is not None:
        return retry_after
    delay = RETRY_BACKOFF * (2 ** attempt) + random.uniform(0.0, RETRY_JITTER)
    return min(delay, RETRY_BACKOFF_MAX)


def _proxy_rotation_enabled() -> bool:
    """CHECKIN_PROXY_ROTATE（默认开）：是否复用代理池给签到 HTTP 轮换出口。"""
    raw = (os.getenv("CHECKIN_PROXY_ROTATE", "1") or "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _build_http_opener(proxy: str, verify_ssl: bool) -> urllib.request.OpenerDirector:
    """按出口代理与证书校验策略构造 urllib opener（出口轮换时可重建）。"""
    handlers: list = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    if not verify_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


# ────────────────────────── HTTP 客户端 ──────────────────────────

class NewApiClient:
    """单个 New API 站点的最小 HTTP 客户端（stdlib urllib）。"""

    def __init__(self, site: SiteConfig):
        self.site = site
        self.base_url = site.base_url.rstrip("/")
        self.referer = self.base_url + (site.referer_path if site.referer_path.startswith("/") else "/" + site.referer_path)
        self.proxy = site.proxy or os.getenv("CHECKIN_PROXY", "")
        self._verify_ssl = site.verify_ssl
        # 无静态代理时，复用 Clash 订阅池（PROXY_POOL_URL / CHECKIN_PROXY_POOL）给签到
        # HTTP 做出口轮换：命中 429 / 出口 IP 被封（waf_block）/ 网络超时时切下一个节点，
        # 而不是在同一个出口 IP 上硬撞。静态代理（site.proxy / CHECKIN_PROXY）优先。
        self._egress: EgressPool | None = None
        if not self.proxy and _proxy_rotation_enabled():
            pool_url = (os.getenv("CHECKIN_PROXY_POOL", "") or "").strip()
            if pool_url:
                self._egress = EgressPool(pool_url, lambda m: log(f"  [{site.name}] {m}"))
        self._opener = _build_http_opener(self.proxy, self._verify_ssl)

    # -- 底层请求 --
    def request(self, method: str, path: str, body: dict | None = None) -> object:
        url = self.base_url + path
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Origin": self.base_url,
            "Referer": self.referer,
            "Cache-Control": "no-store",
        }
        if self.site.user_id:
            headers["New-Api-User"] = str(self.site.user_id)
        if self.site.access_token:
            headers["Authorization"] = f"Bearer {self.site.access_token}"
        if self.site.cookie:
            headers["Cookie"] = self.site.cookie
        data = None
        if body is not None or method.upper() == "POST":
            data = json.dumps(body or {}).encode("utf-8")
            headers["Content-Type"] = "application/json;charset=UTF-8"

        # 池化出口：首个请求前先取一个节点（无静态代理时惰性拉起；失败会置位停用）。
        if not self.proxy and self._egress is not None:
            self._rotate_egress()

        attempts = MAX_RETRIES + 1
        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                return self._open(method, url, headers, data)
            except urllib.error.HTTPError as exc:
                # 4xx/5xx 是服务端应答：读出响应体用于分类
                raw = exc.read().decode("utf-8", "replace")
                err = self._as_api_error(exc.code, raw)
                # 限流(429/5xx) 或出口 IP 被安全规则封禁(waf_block) → 换出口再试
                if (exc.code in RETRYABLE_STATUS or err.kind == "waf_block") and attempt + 1 < attempts:
                    sleep_s = _backoff_delay(attempt, _retry_after_seconds(exc.headers))
                    rotated = self._rotate_egress()
                    reason = "出口 IP 被封" if err.kind == "waf_block" else f"服务端限流 HTTP {exc.code}"
                    egress = "已轮换出口" if rotated else "无可用轮换出口"
                    log(f"  [{self.site.name}] {reason}，{egress}，{sleep_s:.1f}s 后重试 ({attempt + 1}/{MAX_RETRIES})")
                    time.sleep(sleep_s)
                    last_exc = ApiError(err.message, status=exc.code, payload=err.payload,
                                        kind=err.kind, transient=True)
                    continue
                raise err from exc
            except ApiError as exc:
                # JSON 层识别出的出口 IP 封禁同样值得换节点；挑战页(waf_challenge)需要浏览器，不在此处理
                if exc.kind == "waf_block" and attempt + 1 < attempts and self._rotate_egress():
                    sleep_s = _backoff_delay(attempt)
                    log(f"  [{self.site.name}] 出口 IP 被封，已轮换出口，{sleep_s:.1f}s 后重试 ({attempt + 1}/{MAX_RETRIES})")
                    time.sleep(sleep_s)
                    last_exc = exc
                    continue
                raise
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_exc = exc
                if attempt + 1 >= attempts:
                    break
                # 超时 / 连接被断通常是出口被限流：换出口 + 指数退避 + 抖动，避免固定出口硬撞
                sleep_s = _backoff_delay(attempt)
                rotated = self._rotate_egress()
                egress = "已轮换出口" if rotated else "保持当前出口"
                log(f"  [{self.site.name}] 网络错误，{egress}，{sleep_s:.1f}s 后重试 ({attempt + 1}/{MAX_RETRIES}): {exc}")
                time.sleep(sleep_s)
        if isinstance(last_exc, ApiError):
            raise last_exc
        raise ApiError(f"网络错误: {last_exc}", transient=True)

    def _open(self, method: str, url: str, headers: dict, data: bytes | None) -> object:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with self._opener.open(req, timeout=30) as resp:
            text = resp.read().decode("utf-8", "replace")
        return self._parse_json(text)

    def _parse_json(self, text: str) -> object:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            kind = waf_page_kind(text)
            raise ApiError(describe_html(text), payload=text[:300], kind=kind)

    def _as_api_error(self, status: int, raw: str) -> ApiError:
        # 5xx 属于服务端瞬时故障（实测 tabitoken.com 整站 500），归类为可重试
        transient = status >= 500
        try:
            payload = json.loads(raw)
            if isinstance(payload, dict):
                msg = payload.get("message") or payload.get("error") or f"HTTP {status}"
                return ApiError(str(msg), status=status, payload=payload, transient=transient)
        except json.JSONDecodeError:
            pass
        kind = waf_page_kind(raw)
        msg = describe_html(raw) if (kind or (raw or "").lstrip().startswith("<")) else f"HTTP {status}: {raw[:160]}"
        return ApiError(msg, status=status, payload=raw[:300], kind=kind, transient=transient)

    # -- 业务接口 --
    def fetch_user(self) -> dict:
        """GET /api/user/self → {quota, username}"""
        payload = self._require_success(self.request("GET", "/api/user/self"))
        data = payload.get("data") or {}
        return {
            "quota": data.get("quota"),
            "username": str(data.get("username") or data.get("display_name") or ""),
            "id": data.get("id"),
        }

    def fetch_status(self) -> dict:
        """GET /api/user/checkin?month= → {checked_in_today, enabled}"""
        month = dt.datetime.now().strftime("%Y-%m")
        payload = self._require_success(
            self.request("GET", f"/api/user/checkin?{urllib.parse.urlencode({'month': month})}")
        )
        data = payload.get("data") or {}
        stats = data.get("stats") or {}
        return {
            "enabled": bool(data.get("enabled", True)),
            "checked_in_today": stats.get("checked_in_today") if "checked_in_today" in stats else None,
            "raw": data,
        }

    def fetch_site_options(self) -> dict:
        """GET /api/status → 站点公开配置（turnstile_check / turnstile_site_key 等）。"""
        try:
            payload = self.request("GET", "/api/status")
        except ApiError:
            return {}
        data = payload.get("data") if isinstance(payload, dict) else None
        return data if isinstance(data, dict) else {}

    def do_checkin(self, turnstile: str = "") -> dict:
        """POST /api/user/checkin → {quota_awarded, ...}

        turnstile 非空时按 query 参数提交（newapi legacy 变体，
        与 newapi-checkin 的 _legacy_checkin 同源）。
        """
        path = "/api/user/checkin"
        if turnstile:
            path += "?" + urllib.parse.urlencode({"turnstile": turnstile})
        payload = self._require_success(self.request("POST", path, body={}))
        data = payload.get("data") or {}
        return {
            "quota_awarded": data.get("quota_awarded"),
            "checkin_date": data.get("checkin_date"),
            "raw": payload,
        }

    @staticmethod
    def _require_success(payload: object) -> dict:
        if not isinstance(payload, dict):
            raise ApiError("接口返回非 JSON 对象", payload=payload)
        if payload.get("success") is False:
            raise ApiError(str(payload.get("message") or "接口返回失败"), payload=payload)
        return payload

    # -- 出口轮换 --
    def _rotate_egress(self) -> bool:
        """把签到 HTTP 出口切到代理池的下一个节点；真正切换成功返回 True。"""
        if self._egress is None:
            return False
        new_proxy = self._egress.next_proxy()
        if not new_proxy:
            return False
        if new_proxy != self.proxy:
            self.proxy = new_proxy
            self._opener = _build_http_opener(self.proxy, self._verify_ssl)
            log(f"  [{self.site.name}] 签到出口轮换 → {new_proxy}")
        return True

    def release_egress(self) -> None:
        """停掉轮换节点（保留池，可再次惰性拉起），给浏览器探测腾出端口/内存。"""
        if self._egress is not None:
            self._egress.stop_all()

    def close(self) -> None:
        """站点处理结束时释放本客户端起的所有出口进程。"""
        if self._egress is not None:
            self._egress.stop_all()
            self._egress = None


# ────────────────────────── Turnstile 浏览器求解 ──────────────────────────
# 「浏览器只拿令牌、签到仍走 HTTP」的混合模型，移植自 newapi-checkin
# scripts/newapi_turnstile.py + browser/bypass.py 的实测沉淀。

def env_headless() -> bool:
    """CHECKIN_HEADLESS 控制浏览器模式；默认 CI 无头、本地有头。"""
    raw = os.getenv("CHECKIN_HEADLESS", "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return bool(os.getenv("GITHUB_ACTIONS") or os.getenv("CI"))


def normalize_proxy(proxy: str) -> dict | None:
    """把代理 URL 规整为 Camoufox/Playwright 的 dict 格式（内部执行 **proxy）。"""
    raw = (proxy or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    parts = urllib.parse.urlsplit(raw)
    if not parts.hostname:
        return {"server": proxy.strip()}
    scheme = parts.scheme or "http"
    server = f"{scheme}://{parts.hostname}:{parts.port}" if parts.port else f"{scheme}://{parts.hostname}"
    result: dict = {"server": server}
    if parts.username:
        result["username"] = urllib.parse.unquote(parts.username)
    if parts.password:
        result["password"] = urllib.parse.unquote(parts.password)
    return result


# Turnstile widget 注入脚本（在页面主世界执行）。令牌写进 host 元素的
# data-token 属性，供隔离上下文（page.evaluate）经 DOM 读取。
_WIDGET_BOOTSTRAP_JS = r"""
(() => {
  const SITEKEY = '__SITEKEY__';
  const host = document.createElement('div');
  host.id = 'ck-ts-host';
  host.setAttribute('data-state', 'init');
  host.style.cssText = 'position:fixed;left:24px;top:24px;width:320px;'
    + 'z-index:2147483647;background:#fff;padding:4px';
  const slot = document.createElement('div');
  slot.id = 'ck-ts-slot';
  host.appendChild(slot);
  document.body.appendChild(host);

  let widgetId = null;

  const render = () => {
    try {
      widgetId = window.turnstile.render(slot, {
        sitekey: SITEKEY,
        callback: (token) => {
          host.setAttribute('data-token', token);
          host.setAttribute('data-state', 'done');
        },
        'error-callback': (code) => {
          host.setAttribute('data-state', 'error');
          host.setAttribute('data-error', String(code || 'unknown'));
        },
        'timeout-callback': () => {
          host.setAttribute('data-state', 'timeout');
        },
      });
      host.setAttribute('data-state', 'rendered');
    } catch (e) {
      host.setAttribute('data-state', 'error');
      host.setAttribute('data-error', String((e && e.message) || e));
    }
  };

  // 隔离上下文拿不到 window.turnstile，无法直接 reset；用 data-cmd 做命令通道。
  // Cloudflare 把 600xxx 归为可重试错误，重试前必须 reset，否则 widget 停在错误态。
  new MutationObserver(() => {
    if (host.getAttribute('data-cmd') !== 'reset') return;
    host.removeAttribute('data-cmd');
    try {
      host.removeAttribute('data-error');
      host.removeAttribute('data-token');
      host.setAttribute('data-state', 'rendered');
      if (widgetId !== null) { window.turnstile.reset(widgetId); }
      else { render(); }
    } catch (e) {
      host.setAttribute('data-state', 'error');
      host.setAttribute('data-error', 'reset failed: ' + String((e && e.message) || e));
    }
  }).observe(host, { attributes: true, attributeFilter: ['data-cmd'] });

  if (window.turnstile && window.turnstile.render) { render(); return; }
  const s = document.createElement('script');
  s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
  s.async = true;
  s.onload = () => {
    let n = 0;
    const w = setInterval(() => {
      if (window.turnstile && window.turnstile.render) { clearInterval(w); render(); }
      else if (++n > 100) { clearInterval(w); host.setAttribute('data-state', 'no-global'); }
    }, 100);
  };
  s.onerror = () => {
    host.setAttribute('data-state', 'error');
    host.setAttribute('data-error', 'api.js load failed');
  };
  document.head.appendChild(s);
})();
"""

# 读取 widget 状态（隔离上下文安全执行，只访问 DOM）。
# 令牌两个来源都要读：注入 callback 写的 data-token，以及 Turnstile 自己
# 填充的 input[name=cf-turnstile-response]（防「点过但 callback 没触发」漏判）。
_STATE_JS = """() => {
  const host = document.getElementById('ck-ts-host');
  const slot = document.getElementById('ck-ts-slot');
  const r = slot ? slot.getBoundingClientRect() : null;
  let token = (host && host.getAttribute('data-token')) || '';
  if (!token) {
    for (const f of document.querySelectorAll(
      'input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"]'
    )) {
      const v = typeof f.value === 'string' ? f.value : String(f.textContent || '');
      if (v.trim()) { token = v.trim(); break; }
    }
  }
  return {
    state: (host && host.getAttribute('data-state')) || 'missing',
    error: (host && host.getAttribute('data-error')) || '',
    token: token,
    slot: r ? { x: r.x, y: r.y, w: r.width, h: r.height } : null,
  };
}"""

# 触发 widget reset 的命令通道（主世界 MutationObserver 消费）
_RESET_JS = """() => {
  const host = document.getElementById('ck-ts-host');
  if (host) host.setAttribute('data-cmd', 'reset');
}"""

_MIN_WIDGET_HEIGHT = 50    # widget 挂载后约 65-74px，未挂载为 0
_POLL_INTERVAL_MS = 200    # 轮询间隔：秒级会推迟「已就绪」的发现
_TOKEN_WAIT_MS = 12_000    # 点击后等令牌上限（实测签发在 1-5s 内）
_MOUNT_WAIT_MS = 20_000    # api.js 下载 + render 上限（CF 波动时实测超 12s）
_ERROR_GRACE_MS = 1_500    # 600xxx 偶尔先报错再自动恢复签发，留短暂宽限
_MAX_ATTEMPTS = 2          # 失败 reset 再试一次；连续失败通常是 IP/指纹被风控
_RETRY_COOLDOWN_MS = 2_000
_HOST_PATH = "/__checkin_turnstile__"  # SPA 不接管的最小承载页路径


async def _click_checkbox(page, slot: dict, log_fn) -> None:
    """用真实鼠标事件点击 Turnstile 复选框（Cloudflare 校验 isTrusted）。

    Turnstile 用 closed shadow root，容器矩形是唯一可用几何：
    复选框在容器左侧约 30px、垂直居中。steps=2 是 A/B 实测能签发的最小值。
    """
    cx = slot["x"] + 30
    cy = slot["y"] + slot["h"] / 2
    log_fn(f"widget 已就绪，真实鼠标点击复选框 @({cx:.0f},{cy:.0f})")
    approach_x = max(cx + 60, 8.0)
    approach_y = max(cy + 40, 8.0)
    await page.mouse.move(approach_x, approach_y, steps=2)
    await page.mouse.move(cx, cy, steps=2)
    await page.mouse.click(cx, cy)


async def _poll_token(page, deadline: float, log_fn, stage: str) -> tuple[str, str]:
    """轮询令牌直到出现、widget 进入终态、或到达 deadline。返回 (token, reason)。

    轮询期间周期性回显 widget 状态：CI 无显示设备，日志是唯一可观测面，
    静默等待无法区分「正在验证」与「已被风控拒绝」。
    """
    error_deadline: float | None = None
    last_logged_state = ""
    while True:
        info = await page.evaluate(_STATE_JS)
        token: str = info.get("token") or ""
        if token:
            return token, ""
        state = info.get("state") or "missing"
        err = info.get("error") or ""
        now = time.monotonic()

        # 状态变化即回显（600010/timeout 等风控信号第一时间可见）
        current = f"{state}" + (f"/{err}" if err else "")
        if current != last_logged_state:
            log_fn(f"widget 状态: {current}")
            last_logged_state = current

        if state == "missing":
            return "", "widget 容器丢失（页面可能已跳转）"
        if state == "no-global":
            return "", "Turnstile api.js 未就绪"
        if state in {"error", "timeout"}:
            if error_deadline is None:
                error_deadline = now + _ERROR_GRACE_MS / 1000
            elif now >= error_deadline:
                return "", f"widget 错误 {err or state}"
        elif error_deadline is not None:
            error_deadline = None  # 已自行恢复，撤销宽限计时
        if now >= deadline:
            return "", f"{stage}超时（最后状态 {current}）"
        await page.wait_for_timeout(_POLL_INTERVAL_MS)


async def _one_attempt(page, log_fn) -> tuple[str, str]:
    """单次全自动求解：等挂载 → 自动签发 → 必要时真实点击 → 轮询令牌。"""
    mount_deadline = time.monotonic() + _MOUNT_WAIT_MS / 1000
    slot: dict = {}
    while True:
        info = await page.evaluate(_STATE_JS)
        token: str = info.get("token") or ""
        if token:
            log_fn(f"令牌已自动签发（{len(token)} 字符，无需点击）")
            return token, ""
        state = info.get("state") or "missing"
        if state == "missing":
            return "", "widget 容器丢失（页面可能已跳转）"
        if state == "no-global":
            return "", "Turnstile api.js 未就绪"
        slot = info.get("slot") or {}
        if slot.get("h", 0) >= _MIN_WIDGET_HEIGHT:
            break
        if time.monotonic() >= mount_deadline:
            err = info.get("error") or ""
            detail = f"state={state}" + (f" err={err}" if err else "")
            return "", f"widget 挂载超时（{detail}，容器高度 {slot.get('h', 0)}）"
        await page.wait_for_timeout(_POLL_INTERVAL_MS)

    await _click_checkbox(page, slot, log_fn)
    token, reason = await _poll_token(page, time.monotonic() + _TOKEN_WAIT_MS / 1000, log_fn, "等待令牌")
    if token:
        log_fn(f"Turnstile 令牌已签发（{len(token)} 字符）")
    return token, reason


async def _open_widget_host(page, base_url: str, log_fn) -> None:
    """在站点 origin 下打开最小承载页（Turnstile 只校验 (sitekey, hostname)）。

    用路由拦截返回空白 HTML，省掉 SPA bundle 下载与前端执行；拦截失败回落真实导航。
    """
    import contextlib

    target = base_url.rstrip("/") + _HOST_PATH
    try:
        await page.route(
            target,
            lambda route: route.fulfill(
                status=200,
                content_type="text/html; charset=utf-8",
                body="<!doctype html><html><head><title>checkin</title></head><body></body></html>",
            ),
        )
        await page.goto(target, wait_until="domcontentloaded", timeout=20000)
        host = await page.evaluate("() => location.hostname")
        if host and str(host) in base_url:
            log_fn(f"已在 {host} 下打开最小承载页（跳过 SPA 加载）")
            return
        log_fn("承载页 hostname 校验未通过，回落真实导航")
    except Exception as exc:
        log_fn(f"最小承载页不可用（{type(exc).__name__}: {exc}），回落真实导航")
        with contextlib.suppress(Exception):
            await page.unroute(target)

    await page.goto(base_url, wait_until="domcontentloaded", timeout=45000)


_CHECKIN_POST_JS = """
async ({ token, accessToken, userId }) => {
  const resp = await fetch('/api/user/checkin?turnstile=' + encodeURIComponent(token), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(accessToken ? { 'Authorization': 'Bearer ' + accessToken } : {}),
      ...(userId ? { 'New-Api-User': String(userId) } : {}),
    },
    credentials: 'include',
    cache: 'no-store',
  });
  const text = await resp.text();
  return { status: resp.status, body: text };
}
"""


_SWALLOW_ERRORS_INIT_JS = """(() => {
    const swallow = event => {
        try { event.preventDefault(); } catch (_) {}
        try { event.stopImmediatePropagation(); } catch (_) {}
    };
    try { window.addEventListener('error', swallow, true); } catch (_) {}
    try { window.addEventListener('unhandledrejection', swallow, true); } catch (_) {}
    try { window.onerror = () => true; } catch (_) {}
    try { window.onunhandledrejection = event => { try { event.preventDefault(); } catch (_) {} return true; }; } catch (_) {}
})();"""


# screenX/screenY 主世界补丁（移植自 shield-bypass ext/script.js，MIT）。
# CF 的 Turnstile 会丢弃「跨域 iframe 内 screenX < ~120」的点击事件：
# CDP 派发的事件在 iframe 内 screenX 恰好退化为 clientX 或 widget 偏移，
# 真实鼠标相对显示器通常在数百像素。此补丁拦截 getter，把可疑小值改写为
# origin(240~960 随机) + clientX。必须在页面导航前注入（add_init_script
# 会作用于主文档与所有后续 frame，含 challenges.cloudflare.com 的 iframe）。
_SCREENX_PATCH_JS = r"""
(() => {
  if (globalThis.__cfTurnstileClickPatch) return;
  globalThis.__cfTurnstileClickPatch = 1;
  const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
  const framed = (() => {
    try { return window.top !== window; } catch (_) { return true; }
  })();
  const originX =
    !framed && typeof window.screenX === "number" && window.screenX > 50
      ? window.screenX
      : rand(240, 960);
  const originY =
    !framed && typeof window.screenY === "number" && window.screenY > 40
      ? window.screenY
      : rand(80, 420);
  function inIframe() {
    try { return window.top !== window; } catch (_) { return true; }
  }
  function clientOf(evt, axis) {
    if (axis === "X") return Number(evt.clientX || evt.x || 0) || 0;
    return Number(evt.clientY || evt.y || 0) || 0;
  }
  function needsPatch(native, client) {
    if (!Number.isFinite(native)) return true;
    if (native < 120 && Math.abs(native - client) < 2) return true;
    if (inIframe() && native < 120) return true;
    return false;
  }
  function patchProto(proto) {
    if (!proto) return;
    for (const name of ["screenX", "screenY"]) {
      const desc = Object.getOwnPropertyDescriptor(proto, name);
      const origGet = desc && desc.get;
      const axis = name.endsWith("X") ? "X" : "Y";
      const origin = axis === "X" ? originX : originY;
      try {
        Object.defineProperty(proto, name, {
          configurable: true,
          enumerable: !!(desc && desc.enumerable),
          get() {
            let native = 0;
            try { native = origGet ? origGet.call(this) : 0; } catch (_) {}
            const client = clientOf(this, axis);
            if (needsPatch(native, client)) return origin + client;
            return native;
          },
        });
      } catch (_) {}
    }
  }
  patchProto(MouseEvent.prototype);
  if (typeof PointerEvent !== "undefined") patchProto(PointerEvent.prototype);
})();
"""

# Turnstile iframe 元素级点击参数（shield-bypass cf_turnstile 同源实测值）
_TS_IFRAME_SEL = "iframe[src*='challenges.cloudflare.com'], iframe[src*='turnstile'], iframe[id*='cf-chl-widget']"
_TS_CLICK_X = 26.0
_TS_CLICK_Y = 32.0


async def _submit_checkin_in_page(page, auth: dict, token: str, log_fn) -> dict:
    """令牌到手后，在页面内提交签到（与令牌签发同一浏览器环境）。"""
    log_fn("在页面内提交签到...")
    try:
        post_result = await page.evaluate(
            _CHECKIN_POST_JS,
            {"token": token, "accessToken": auth.get("access_token", ""),
             "userId": auth.get("user_id", "")},
        )
    except Exception as post_exc:
        # fetch 异常时令牌消费状态未知，本轮放弃，下次运行重试
        raise ApiError(
            f"页面内签到请求失败（{type(post_exc).__name__}: {post_exc}）；下次运行自动重试",
            transient=True,
        ) from post_exc

    status = post_result.get("status")
    body_text = str(post_result.get("body") or "")
    try:
        payload = json.loads(body_text)
    except json.JSONDecodeError:
        raise ApiError(
            f"页面内签到返回非 JSON（HTTP {status}）：{describe_html(body_text)}",
            status=status, transient=(status or 0) >= 500,
        )
    if isinstance(payload, dict) and payload.get("success") is False:
        raise ApiError(str(payload.get("message") or "页面内签到被拒绝"), status=status, payload=payload)
    if status != 200 or not isinstance(payload, dict):
        raise ApiError(f"页面内签到返回异常（HTTP {status}）", status=status, payload=payload)
    data = payload.get("data") or {}
    log_fn("页面内签到成功")
    return {
        "quota_awarded": data.get("quota_awarded"),
        "checkin_date": data.get("checkin_date"),
        "raw": payload,
    }


async def _solve_and_submit(page, base_url: str, sitekey: str, log_fn, auth: dict) -> dict:
    """打开 widget 承载页 → 注入 → 求解令牌 → 页面内提交签到（Camoufox 路径）。"""
    await _open_widget_host(page, base_url, log_fn)
    log_fn("注入 Turnstile widget（主世界）...")
    await page.add_script_tag(content=_WIDGET_BOOTSTRAP_JS.replace("__SITEKEY__", sitekey))

    token = ""
    reason = ""
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        token, reason = await _one_attempt(page, log_fn)
        if token:
            break
        if attempt >= _MAX_ATTEMPTS:
            break
        log_fn(f"第 {attempt} 次失败（{reason}），reset widget 后重试")
        await page.evaluate(_RESET_JS)
        await page.wait_for_timeout(_RETRY_COOLDOWN_MS)

    if not token:
        log_fn(f"未能拿到令牌（最后原因：{reason}）")
        raise ApiError(
            f"Turnstile 令牌求解失败（{reason or '未知原因'}）；"
            "下次运行自动重试，可尝试更换浏览器模式或配置住宅代理",
            transient=True,
        )

    return await _submit_checkin_in_page(page, auth, token, log_fn)


async def _click_turnstile_iframe(page, log_fn) -> bool:
    """元素级可信点击 Turnstile iframe 的复选框区域（shield-bypass 同款策略）。

    通过 frame_locator 探测真实 checkbox 可见性后再点，避免盲点；点击失败
    时回退 locator 点击。返回是否发生点击。
    """
    try:
        n = await page.locator(_TS_IFRAME_SEL).count()
    except Exception:
        return False
    for i in range(n):
        host = page.locator(_TS_IFRAME_SEL).nth(i)
        try:
            handle = await host.element_handle(timeout=300)
        except Exception:
            handle = None
        if not handle:
            continue
        try:
            box = await handle.bounding_box()
        except Exception:
            box = None
        # 尺寸过滤：Turnstile widget ≥ 180x45；不设 y 下限（我们自注入的
        # widget 常在页面顶部，shield-bypass 的 y>=80 过滤对本流程不适用）
        if not box or box.get("width", 0) < 180 or box.get("height", 0) < 45:
            continue
        fl = page.frame_locator(_TS_IFRAME_SEL).nth(i)
        try:
            if await fl.get_by_text("Verifying...", exact=True).first.is_visible(timeout=150):
                continue
        except Exception:
            pass
        try:
            await handle.click(
                position={"x": _TS_CLICK_X, "y": _TS_CLICK_Y},
                timeout=2000, delay=60, force=True,
            )
            log_fn(f"元素级可信点击 iframe[{i}] @({_TS_CLICK_X:.0f},{_TS_CLICK_Y:.0f})")
            return True
        except Exception as exc:
            log_fn(f"iframe[{i}] 点击失败（{type(exc).__name__}），尝试 locator 点击")
            try:
                await fl.get_by_role("checkbox").first.click(timeout=1500, force=True)
                log_fn(f"locator 点击 iframe[{i}] checkbox")
                return True
            except Exception:
                continue
    return False


class _ClaimedAbort(Exception):
    """代理池模式：其他节点已胜出，当前探测应立即收工。"""


async def _solve_and_submit_chrome(page, base_url: str, sitekey: str, log_fn, auth: dict,
                                   on_token=None, abort_check=None) -> dict:
    """真实 Chrome 路径：直接导航真实页面 → 注入 → 元素级点击 → 轮询提交。

    不做路由拦截（Fetch 域拦截本身是可检测面），直接加载站点 SPA。
    on_token: 可选异步回调 on_token(page, token)；代理池模式用它接管提交
    （探测与提交分离，保证只有首个出令牌的节点执行签到 POST）。
    abort_check: 可选同步回调，返回 True 时立即放弃探测（其他节点已胜出）。
    """
    await page.goto(base_url, wait_until="domcontentloaded", timeout=45000)

    # 整页 CF 挑战（Just a moment）先等它自行通过，再注入 widget
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if abort_check is not None and abort_check():
            raise _ClaimedAbort()
        try:
            title = (await page.title() or "").lower()
        except Exception:
            title = ""
        if "just a moment" not in title and "attention required" not in title:
            break
        await asyncio.sleep(0.5)

    log_fn("注入 Turnstile widget（主世界）...")
    await page.add_script_tag(content=_WIDGET_BOOTSTRAP_JS.replace("__SITEKEY__", sitekey))

    token = ""
    last_state = ""
    clicks_done = 0
    last_click_at = 0.0
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if abort_check is not None and abort_check():
            raise _ClaimedAbort()
        try:
            info = await page.evaluate(_STATE_JS)
        except Exception as exc:
            log_fn(f"状态读取异常（{type(exc).__name__}），重试")
            await asyncio.sleep(0.5)
            continue
        token = info.get("token") or ""
        if token:
            log_fn(f"令牌已签发（{len(token)} 字符）")
            break
        state = info.get("state") or "missing"
        err = info.get("error") or ""
        current = state + (f"/{err}" if err else "")
        if current != last_state and current != "init":
            log_fn(f"widget 状态: {current}")
            last_state = current
        # 交互模式：widget 就绪后元素级点击；10s 无令牌允许再点一次（最多 3 次）
        now = time.monotonic()
        if state == "rendered" and clicks_done < 3 and now - last_click_at > 10:
            if await _click_turnstile_iframe(page, log_fn):
                clicks_done += 1
                last_click_at = now
        await asyncio.sleep(0.15)

    if not token:
        focus = ""
        try:
            focus = await page.evaluate("() => String(document.hasFocus())")
        except Exception:
            pass
        log_fn(f"未能拿到令牌（45s，点击 {clicks_done} 次，页面聚焦={focus}）")
        raise ApiError(
            f"Turnstile 令牌求解失败（最后状态 {last_state or 'unknown'}，点击 {clicks_done} 次）；"
            "可能为出口 IP 信誉惩罚，下次运行自动重试",
            transient=True,
        )

    if on_token is not None:
        return await on_token(page, token)
    return await _submit_checkin_in_page(page, auth, token, log_fn)


async def _solve_turnstile(base_url: str, sitekey: str, proxy: str, headless: bool,
                           log_fn, auth: dict) -> dict:
    """Camoufox 路径：反检测 Firefox 求解 + 页面内提交。"""
    from camoufox.async_api import AsyncCamoufox

    log_fn(f"启动 Camoufox（headless={headless}）...")
    launch_options: dict = {
        "headless": headless,
        # humanize 必须启用：关闭后即使 isTrusted 点击正确，CF 也会静默不签发
        "humanize": 0.6,
        "geoip": True,
        "locale": "en-US",
        "timeout": 30000,
        # 强制 macos 指纹，避免 CI 下 navigator.platform 与 UA 不一致被风控识破
        "os": "macos",
    }
    proxy_dict = normalize_proxy(proxy)
    if proxy_dict:
        launch_options["proxy"] = proxy_dict

    browser = await AsyncCamoufox(**launch_options).start()
    context = browser.contexts[0] if browser.contexts else await browser.new_context(no_viewport=True)
    try:
        # 屏蔽页面未捕获错误的上报：Playwright Firefox 驱动在部分 pageError 缺
        # location.url 时会在 Node 侧崩溃（newapi-checkin browser/bypass.py 实测）
        await context.add_init_script(_SWALLOW_ERRORS_INIT_JS)
        page = await context.new_page()
        return await _solve_and_submit(page, base_url, sitekey, log_fn, auth)
    finally:
        try:
            await browser.close()
        except Exception:
            pass


# ────────────── 真实 Chrome + Patchright 路径 ──────────────
# 实测沉淀（本机 jshook/裸 CDP 对照实验）：
#   干净 IP 免点击自动签发；脏 IP 降级为交互模式，但 CDP 派发的点击在
#   Turnstile 跨域 iframe 内 screenX 退化为小值（<120）被 Cloudflare 丢弃
#   （shield-bypass ext/script.js 揭示的判定规则）。对策 = Patchright 反检测
#   底座 + screenX 主世界补丁 + 元素级可信点击。

CHROME_CANDIDATES = [
    # Windows
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    # Linux（GitHub Actions ubuntu runner 预装 google-chrome-stable）
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
    "/opt/google/chrome/chrome",
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
]


def find_chrome() -> str | None:
    """定位本机 Chrome/Chromium 可执行文件。"""
    for path in CHROME_CANDIDATES:
        if os.path.isfile(path):
            return path
    for name in ("google-chrome-stable", "google-chrome", "chromium-browser", "chromium", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    return None


async def _solve_turnstile_chrome(base_url: str, sitekey: str, proxy: str, headless: bool,
                                  log_fn, auth: dict, on_token=None, abort_check=None) -> dict:
    """真实 Chrome 路径：Patchright（反检测 Playwright fork）持久化上下文。

    - Patchright 在 C++ 层剔除自动化标志、evaluate 走 isolated world，
      规避 Runtime.enable / webdriver 等 CDP 检测面；
    - screenX/screenY 补丁经 add_init_script 在主世界预注入，
      导航前生效且覆盖后续所有 frame（含 challenges.cloudflare.com）；
    - 系统真实 Chrome（ubuntu runner 预装 google-chrome-stable）。
    """
    from patchright.async_api import async_playwright

    chrome = find_chrome()
    if not chrome:
        raise RuntimeError("未找到 Chrome/Chromium 可执行文件")
    import tempfile

    profile_dir = tempfile.mkdtemp(prefix="ck-chrome-")
    args = ["--disable-blink-features=AutomationControlled"]
    if sys.platform.startswith("linux"):
        args += ["--no-sandbox", "--disable-dev-shm-usage", "--ozone-platform=x11"]
    launch_kwargs: dict = {
        "headless": headless,
        "executable_path": chrome,
        "no_viewport": True,
        "args": args,
        "timeout": 30000,
        # 剔除 Playwright 默认附加的自动化开关
        "ignore_default_args": ["--enable-automation", "--disable-extensions"],
    }
    proxy_dict = normalize_proxy(proxy)
    if proxy_dict:
        launch_kwargs["proxy"] = proxy_dict

    log_fn(f"启动真实 Chrome/Patchright（{'headless' if headless else 'headed'}）...")
    pw = await async_playwright().start()
    context = None
    try:
        context = await pw.chromium.launch_persistent_context(profile_dir, **launch_kwargs)
        page = context.pages[0] if context.pages else await context.new_page()
        await page.add_init_script(_SCREENX_PATCH_JS)
        return await _solve_and_submit_chrome(page, base_url, sitekey, log_fn, auth,
                                              on_token=on_token, abort_check=abort_check)
    finally:
        if context is not None:
            try:
                await asyncio.wait_for(asyncio.shield(context.close()), timeout=8)
            except Exception:
                pass
        try:
            await pw.stop()
        except Exception:
            pass
        shutil.rmtree(profile_dir, ignore_errors=True)


async def _solve_turnstile_any(browser_pref: str, base_url: str, sitekey: str, proxy: str,
                               headless: bool, log_fn, auth: dict) -> dict:
    """按偏好依次尝试浏览器路径；auto = 真实 Chrome 优先，Camoufox 兜底。"""
    order = {"chrome": ["chrome"], "camoufox": ["camoufox"]}.get(
        browser_pref, ["chrome", "camoufox"]
    )
    last_exc: Exception | None = None
    for kind in order:
        solver = _solve_turnstile_chrome if kind == "chrome" else _solve_turnstile
        try:
            return await solver(base_url, sitekey, proxy, headless, log_fn, auth)
        except (RuntimeError, FileNotFoundError, ImportError) as exc:
            # 仅当「环境不可用」（没装/没找到）才回落；业务失败直接上抛
            last_exc = exc
            log_fn(f"{kind} 路径不可用，尝试下一种浏览器")
        except ApiError:
            raise
    raise last_exc or RuntimeError("没有可用的浏览器路径")


def _run_async_loop(loop: asyncio.AbstractEventLoop, coro) -> object:
    """在指定事件循环运行协程，并可靠清理残留 task 与传输（防管道关闭噪声）。"""
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
            for t in pending:
                t.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        if sys.platform == "win32":
            try:
                loop.run_until_complete(asyncio.sleep(0.3))
            except Exception:
                pass
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        try:
            loop.close()
        except Exception:
            pass


def solve_turnstile_token(base_url: str, sitekey: str, proxy: str, headless: bool,
                          log_fn, auth: dict, browser_pref: str = "auto") -> dict:
    """同步入口：求解 Turnstile 令牌并在页面内完成签到。

    返回 do_checkin 同构 dict（quota_awarded / checkin_date / raw）。
    browser_pref: auto（真实 Chrome 优先，Camoufox 兜底）/ chrome / camoufox。
    """
    if sys.platform == "win32":
        try:
            # Playwright 驱动是子进程传输，Windows 下必须 Proactor 循环（3.8+ 默认，显式兜底）
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except Exception:
            pass
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return _run_async_loop(
        loop,
        _solve_turnstile_any(browser_pref, base_url, sitekey, proxy, headless, log_fn, auth),
    )


def retry_checkin_with_turnstile(client: NewApiClient, site: SiteConfig, exc: ApiError, tag: str) -> dict:
    """签到被 Turnstile 拒绝时自动求解令牌并重试。

    浏览器求解 + 页面内 POST 一体完成（环境一致性最优）；确认不适用
    （配置关闭/回执不匹配）时原样抛出 exc。
    """
    if site.turnstile == "off" or not contains_any(exc.message, TURNSTILE_MISSING_PATTERNS):
        raise exc
    log(f"{tag} 站点要求 Turnstile 人机验证，尝试浏览器自动求解")

    options = client.fetch_site_options()
    sitekey = str(options.get("turnstile_site_key") or "").strip()
    if not options.get("turnstile_check") or not sitekey:
        log(f"{tag} 站点未公开 Turnstile 配置（turnstile_check={options.get('turnstile_check')}），无法自动求解")
        raise exc

    headless = env_headless()
    browser_pref = site.browser or "auto"
    log_fn = lambda m: log(f"{tag} {m}")  # noqa: E731
    auth = {"access_token": site.access_token, "user_id": site.user_id}

    pool_url = os.getenv("CHECKIN_PROXY_POOL", "").strip()
    if pool_url:
        log(f"{tag} 启用代理池模式（CHECKIN_PROXY_POOL 已配置）")
        # 先释放 HTTP 出口轮换节点，避免与浏览器探测自起的 mihomo 争端口/内存
        client.release_egress()
        try:
            return solve_turnstile_via_pool(client.base_url, sitekey, pool_url, headless, log_fn, auth)
        except ApiError:
            raise
        except Exception as pool_exc:
            raise ApiError(
                f"代理池流程异常（{type(pool_exc).__name__}: {pool_exc}）；下次运行自动重试",
                transient=True,
            ) from pool_exc

    try:
        return solve_turnstile_token(client.base_url, sitekey, client.proxy, headless, log_fn, auth, browser_pref)
    except RuntimeError as install_exc:
        raise ApiError(str(install_exc), transient=True) from install_exc
    except FileNotFoundError as install_exc:
        raise ApiError(str(install_exc), transient=True) from install_exc
    except ApiError:
        raise
    except Exception as solve_exc:
        raise ApiError(
            f"Turnstile 浏览器求解异常（{type(solve_exc).__name__}: {solve_exc}）；"
            "下次运行自动重试，可尝试为该站点配置代理",
            transient=True,
        ) from solve_exc


# ────────────────────────── 代理池模式 ──────────────────────────
# 架构（适配 Clash 订阅池，如 proxypool2.zshabai.cc）：
#   1. 下载池 yaml → 起一个「预筛 mihomo」加载全部节点，
#      用 group delay API 一次性测活并按延迟排序；
#   2. K 个并发 worker，各自起独立 mihomo（固定 mixed-port，规则钉死到
#      单个节点）+ 独立 Patchright Chrome 探测：出令牌 = 节点可用；
#   3. 首个出令牌的 worker 独占提交签到（claim 机制），成功/已签 → 全局停止。
# 设计约束：令牌绑定签发出口 IP，因此 solve 与 submit 必须在同一 worker
# 同一 mihomo 内完成；探测阶段不发签到请求，只有胜者节点提交一次。

_POOL_SKIP_RE = re.compile(
    r"官网|首页|剩余|到期|过期|套餐|流量|重置|发布|订阅|屏蔽|防失联|reject|discard|direct", re.I
)


def _free_tcp_port() -> int:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _unique_group_name(taken: set) -> str:
    """生成不与池内任何节点/组重名的兜底组名（实测池子里有叫 PASS 的组）。"""
    import secrets

    while True:
        name = "CKPASS" + secrets.token_hex(3)
        if name not in taken:
            return name


def _download_pool_yaml(url: str, timeout: float = 30.0) -> str:
    req = urllib.request.Request(
        url, headers={"User-Agent": "clash-verge/1.7.7", "Accept": "*/*"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def _mihomo_ctl_get(ctl_base: str, path: str, timeout: float = 8.0):
    with urllib.request.urlopen(f"{ctl_base}{path}", timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


class _Mihomo:
    """单实例 mihomo 进程包装：生成配置、启动、等就绪、停止。"""

    def __init__(self, binary: str, name: str):
        self.binary = binary
        self.name = name
        self.proc: subprocess.Popen | None = None
        self.dir = ""
        self.ctl_port = _free_tcp_port()
        self.mixed_port = _free_tcp_port()
        self.ctl = f"http://127.0.0.1:{self.ctl_port}"

    def start(self, config: dict, log_fn) -> None:
        import tempfile

        import yaml

        self.dir = tempfile.mkdtemp(prefix=f"mihomo-{self.name}-")
        cfg_path = os.path.join(self.dir, "config.yaml")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(config, fh, allow_unicode=True, sort_keys=False)
        log_path = os.path.join(self.dir, "mihomo.log")
        log_f = open(log_path, "ab")
        self.proc = subprocess.Popen(
            [self.binary, "-f", cfg_path, "-d", self.dir],
            stdout=log_f, stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"mihomo[{self.name}] 启动即退出 rc={self.proc.returncode}："
                    f"{self._log_tail(log_path)}"
                )
            try:
                _mihomo_ctl_get(self.ctl, "/version", timeout=1.5)
                return
            except Exception:
                time.sleep(0.3)
        raise TimeoutError(
            f"mihomo[{self.name}] 控制端口 10s 未就绪：{self._log_tail(log_path)}"
        )

    @staticmethod
    def _log_tail(log_path: str, limit: int = 500) -> str:
        try:
            with open(log_path, "rb") as fh:
                data = fh.read()[-limit:]
            return data.decode("utf-8", "replace").strip().replace("\n", " | ")
        except Exception:
            return "(无日志)"

    def stop(self) -> None:
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None
        if self.dir:
            shutil.rmtree(self.dir, ignore_errors=True)


def _pool_preselect_nodes(pool_text: str, binary: str, log_fn) -> list[dict]:
    """预筛：起一个全量 mihomo → group delay 测活 → 按延迟升序返回节点 dict 列表。"""
    import yaml

    full = yaml.safe_load(pool_text)
    nodes = [p for p in (full.get("proxies") or []) if isinstance(p, dict)]
    if not nodes:
        raise RuntimeError("代理池 yaml 中没有 proxies 列表")
    by_name = {p.get("name"): p for p in nodes}

    m = _Mihomo(binary, "prefilter")
    # 极简配置：不带池子自带的 proxy-groups/rules（组间引用与组名冲突是
    # 常见启动失败源，实测池内就有名为 PASS 的组）。delay 测活用 GLOBAL
    # 组（mihomo 自动包含全部节点）。
    pass_group = _unique_group_name({p.get("name") for p in nodes})
    cfg = {
        "mixed-port": m.mixed_port,
        "external-controller": f"127.0.0.1:{m.ctl_port}",
        "log-level": "warning",
        "mode": "rule",
        "proxies": nodes,
        "proxy-groups": [{"name": pass_group, "type": "select", "proxies": [nodes[0].get("name")]}],
        "rules": [f"MATCH,{pass_group}"],
    }
    m.start(cfg, log_fn)
    delays: dict = {}
    try:
        try:
            # group delay：mihomo 并发测活组内全部节点（一次调用）
            delays = _mihomo_ctl_get(
                m.ctl,
                "/group/GLOBAL/delay?url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=4000",
                timeout=60,
            )
        except Exception as exc:
            log_fn(f"组测活不可用（{type(exc).__name__}），回退逐节点测活")
            import concurrent.futures

            def _one(name: str):
                try:
                    r = _mihomo_ctl_get(
                        m.ctl,
                        f"/proxies/{urllib.parse.quote(name, safe='')}/delay"
                        "?url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=4000",
                        timeout=8,
                    )
                    return name, int(r.get("delay") or 0)
                except Exception:
                    return name, 0

            with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
                for name, d in pool.map(_one, [n for n in by_name if n]):
                    if d > 0:
                        delays[name] = d
    finally:
        m.stop()

    candidates = []
    for name, delay in delays.items():
        node = by_name.get(name)
        if not node or _POOL_SKIP_RE.search(name or ""):
            continue
        candidates.append((delay, node))
    candidates.sort(key=lambda t: t[0])
    return [n for _, n in candidates]


def _pool_worker_config(node: dict, m: _Mihomo) -> dict:
    """单节点 mihomo 配置：规则钉死该节点，浏览器 mixed-port 出口即该节点。"""
    node_name = node.get("name")
    pass_group = _unique_group_name({node_name})
    return {
        "mixed-port": m.mixed_port,
        "external-controller": f"127.0.0.1:{m.ctl_port}",
        "log-level": "warning",
        "mode": "rule",
        "proxies": [node],
        "proxy-groups": [{"name": pass_group, "type": "select", "proxies": [node_name]}],
        "rules": [f"MATCH,{pass_group}"],
    }


def _classify_node_failure(message: str) -> str:
    if "600010" in message:
        return "ip_rejected(600010)"
    if "rendered" in message:
        return "ip_penalized(静默)"
    if "waf" in message or "challenge" in message:
        return "waf"
    return "other"


# 同一轮运行内多站点共享预筛结果（避免重复下载/测活）：{url: (ts, candidates)}
_POOL_CACHE: dict = {}
_POOL_CACHE_TTL_S = 1800


def _get_pool_candidates(pool_url: str, binary: str, log_fn) -> list[dict]:
    """下载+测活+排序，同轮运行内复用（TTL 30 分钟）。"""
    cached = _POOL_CACHE.get(pool_url)
    if cached and time.monotonic() - cached[0] < _POOL_CACHE_TTL_S:
        log_fn(f"复用本轮已预筛的存活节点（{len(cached[1])} 个）")
        return cached[1]
    pool_text = _download_pool_yaml(pool_url)
    candidates = _pool_preselect_nodes(pool_text, binary, log_fn)
    _POOL_CACHE[pool_url] = (time.monotonic(), candidates)
    return candidates


class EgressPool:
    """复用 Clash 订阅池（PROXY_POOL_URL）给**签到 HTTP**做出口轮换的轻量管理器。

    与 Turnstile 的池模式同源（同一订阅、同一预筛），但用途不同：那里是
    「多节点并发探测出令牌」，这里是「单站点请求失败时换一个出口 IP 重试」。

    做法：预筛存活节点后，按需为当前节点起一个「钉死单节点」的 mihomo，
    对外暴露 `http://127.0.0.1:<mixed-port>` 作为 HTTP 代理；每次 next_proxy()
    切到下一个节点（惰性拉起，超量时停掉最旧的，避免进程/内存膨胀）。

    - 节点全部不可用 / 无 mihomo 内核 / 池下载失败 → 自行停用，退化为直连；
    - stop_all() 停掉已起实例但保留候选列表，后续可再次惰性拉起。
    """

    def __init__(self, pool_url: str, log_fn, binary: str | None = None,
                 max_nodes: int | None = None, keep: int | None = None):
        self.pool_url = pool_url
        self.log_fn = log_fn
        self.binary = (binary or os.getenv("MIHOMO_BIN", "mihomo") or "mihomo").strip()
        self.max_nodes = max(1, int(max_nodes if max_nodes is not None
                                    else (os.getenv("CHECKIN_PROXY_MAX_NODES", "12") or 12)))
        self.keep = max(1, int(keep if keep is not None
                               else (os.getenv("CHECKIN_PROXY_KEEP", "2") or 2)))
        self._candidates: list[dict] = []
        self._idx = 0
        self._running: dict[str, _Mihomo] = {}
        self._disabled = False

    def _load(self) -> bool:
        if self._disabled:
            return False
        if self._candidates:
            return True
        if shutil.which(self.binary) is None and not os.path.isfile(self.binary):
            self.log_fn(
                f"未找到 mihomo 内核（{self.binary}），签到出口轮换不可用，改用直连。"
                "安装见 https://github.com/MetaCubeX/mihomo/releases 或设 MIHOMO_BIN"
            )
            self._disabled = True
            return False
        try:
            self.log_fn("拉取代理池并预筛存活节点（供签到 HTTP 出口轮换）...")
            nodes = _get_pool_candidates(self.pool_url, self.binary, self.log_fn)
        except Exception as exc:
            self.log_fn(f"代理池预筛失败（{type(exc).__name__}: {exc}），签到出口轮换不可用")
            self._disabled = True
            return False
        self._candidates = nodes[: self.max_nodes]
        if not self._candidates:
            self.log_fn("代理池无存活节点，签到出口轮换不可用")
            self._disabled = True
            return False
        self.log_fn(f"签到出口轮换就绪（{len(self._candidates)} 个候选节点）")
        return True

    def _start(self, node: dict) -> _Mihomo | None:
        name = str(node.get("name") or f"node-{self._idx}")
        m = _Mihomo(self.binary, f"http{len(self._running)}")
        try:
            m.start(_pool_worker_config(node, m), self.log_fn)
        except Exception as exc:
            self.log_fn(f"  出口节点启动失败 [{name[:24]}]: {type(exc).__name__}")
            m.stop()
            return None
        self._running[name] = m
        self._evict()
        return m

    def _evict(self) -> None:
        while len(self._running) > self.keep:
            oldest = next(iter(self._running))
            self._running.pop(oldest).stop()

    def next_proxy(self) -> str | None:
        """切到下一个存活节点并返回其本地 HTTP 代理 URL；无可回退返回 None。"""
        if not self._load():
            return None
        total = len(self._candidates)
        for _ in range(total):
            node = self._candidates[self._idx % total]
            self._idx += 1
            name = str(node.get("name") or "")
            m = self._running.get(name)
            if m is None:
                m = self._start(node)
                if m is None:
                    continue
            return f"http://127.0.0.1:{m.mixed_port}"
        return None

    def stop_all(self) -> None:
        while self._running:
            _, m = self._running.popitem()
            m.stop()


async def _pool_flow_async(base_url: str, sitekey: str, pool_url: str, headless: bool,
                           log_fn, auth: dict) -> dict:
    binary = os.getenv("MIHOMO_BIN", "mihomo").strip() or "mihomo"
    if shutil.which(binary) is None and not os.path.isfile(binary):
        raise RuntimeError(
            "未找到 mihomo 内核（代理池模式需要）。"
            "请在 CI 安装 mihomo 并设 MIHOMO_BIN，或本地下载："
            "https://github.com/MetaCubeX/mihomo/releases"
        )
    import yaml  # noqa: F401  代理池解析依赖

    concurrency = max(1, int(os.getenv("CHECKIN_POOL_CONCURRENCY", "3") or 3))
    max_nodes = max(1, int(os.getenv("CHECKIN_POOL_MAX_NODES", "24") or 24))
    budget_s = max(120, int(os.getenv("CHECKIN_POOL_BUDGET_S", "900") or 900))

    log_fn("拉取代理池并预筛存活节点...")
    candidates = await asyncio.to_thread(_get_pool_candidates, pool_url, binary, log_fn)
    candidates = candidates[:max_nodes]
    log_fn(f"存活节点 {len(candidates)} 个（按延迟排序，并发 {concurrency} 探测）")
    if not candidates:
        raise ApiError("代理池中没有存活节点；下次运行自动重试（池子每日更新）", transient=True)

    started = time.monotonic()
    claimed = asyncio.Event()
    result_holder: dict = {}
    tally: dict = {}
    node_iter = iter(candidates)
    node_lock = asyncio.Lock()

    async def next_node():
        async with node_lock:
            return next(node_iter, None)

    async def probe_one(node: dict, idx: int) -> str | None:
        """返回 'stop' 表示全局应停止；None 表示继续下一个节点。"""
        name = str(node.get("name") or f"node-{idx}")
        tag = f"[{name[:24]}]"
        wlog = lambda m: log_fn(f"  {tag} {m}")  # noqa: E731
        m = _Mihomo(binary, f"w{idx}")
        try:
            await asyncio.to_thread(m.start, _pool_worker_config(node, m), wlog)
            worker_proxy = f"http://127.0.0.1:{m.mixed_port}"

            async def on_token(page, token):
                if claimed.is_set():
                    wlog("已有其他节点胜出，跳过提交")
                    return {"__skip": True}
                claimed.set()
                wlog(f"节点胜出，提交签到（令牌 {len(token)} 字符）")
                try:
                    return await _submit_checkin_in_page(page, auth, token, wlog)
                except ApiError as submit_exc:
                    if not contains_any(submit_exc.message, ALREADY_DONE_PATTERNS):
                        # 非「已签到」的提交失败 → 释放 claim，让其他节点继续尝试
                        claimed.clear()
                    raise
                except Exception:
                    claimed.clear()
                    raise

            outcome = await asyncio.wait_for(
                _solve_turnstile_chrome(base_url, sitekey, worker_proxy, headless, wlog, auth,
                                        on_token=on_token, abort_check=lambda: claimed.is_set()),
                timeout=120,
            )
            if outcome.get("__skip"):
                return "stop"
            result_holder.update(outcome)
            log_fn(f"  {tag} ✅ 签到成功")
            return "stop"
        except _ClaimedAbort:
            return "stop"
        except asyncio.TimeoutError:
            tally["探测超时"] = tally.get("探测超时", 0) + 1
            log_fn(f"  {tag} ✗ 探测超时（120s）")
            return None
        except ApiError as exc:
            key = _classify_node_failure(exc.message)
            tally[key] = tally.get(key, 0) + 1
            if contains_any(exc.message, ALREADY_DONE_PATTERNS):
                log_fn(f"  {tag} ✅ 今日已签到（节点可用）")
                result_holder.setdefault("already_done", True)
                return "stop"
            log_fn(f"  {tag} ✗ {key}")
            return None
        except Exception as exc:
            tally["环境异常"] = tally.get("环境异常", 0) + 1
            log_fn(f"  {tag} ✗ 环境异常: {type(exc).__name__}")
            return None
        finally:
            await asyncio.to_thread(m.stop)

    async def worker(wid: int):
        while not claimed.is_set() and time.monotonic() - started < budget_s:
            node = await next_node()
            if node is None:
                return
            verdict = await probe_one(node, wid)
            if verdict == "stop":
                return

    workers = [asyncio.create_task(worker(i)) for i in range(concurrency)]
    await asyncio.gather(*workers)

    if result_holder and not result_holder.get("__skip"):
        return result_holder
    if result_holder.get("already_done"):
        raise ApiError("今日已签到", payload={"already_done": True})
    tried = len(candidates)
    summary = "，".join(f"{k}×{v}" for k, v in tally.items()) or "无明细"
    raise ApiError(
        f"代理池探测失败：尝试 {tried} 个节点无一可用（{summary}）；"
        "池子每日更新，下次运行自动重试",
        transient=True,
    )


def solve_turnstile_via_pool(base_url: str, sitekey: str, pool_url: str, headless: bool,
                             log_fn, auth: dict) -> dict:
    """代理池模式同步入口。"""
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except Exception:
            pass
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return _run_async_loop(
        loop,
        _pool_flow_async(base_url, sitekey, pool_url, headless, log_fn, auth),
    )


# ────────────────────────── 分类 ──────────────────────────

def classify_error(err: ApiError) -> str:
    """把 ApiError 归类为稳定状态（顺序即优先级，参考 newapi-checkin classify）。"""
    if err.kind == "waf_block" or err.kind == "waf_challenge":
        return "need_verification"
    if err.status == 401:
        return "need_login"
    msg = err.message or ""
    if contains_any(msg, NOT_OPEN_PATTERNS):
        return "not_open"
    if contains_any(msg, ALREADY_DONE_PATTERNS):
        return "already_done"
    if contains_any(msg, VERIFICATION_PATTERNS):
        return "need_verification"
    if err.transient:
        return "network_error"
    if contains_any(msg, LOGIN_PATTERNS):
        return "need_login"
    return "error"


STATUS_HINTS = {
    "need_login": "凭据失效或不被接受：请重新采集 access_token / user_id（GitHub 登录站点 → 控制台生成系统访问令牌）",
    "need_verification": "站点启用了 Cloudflare/Turnstile 防护，纯 HTTP 无法通过；需浏览器流程或更换代理出口 IP",
    "not_open": "站点未开放签到功能（非账号问题）",
    "network_error": "站点暂时不可达或服务端 5xx，下次运行会自动重试",
    "need_config": "配置缺失：user_id 与 access_token 必须同时提供",
}


# ────────────────────────── 签到状态机 ──────────────────────────

def run_site(site: SiteConfig, *, probe_only: bool = False) -> Outcome:
    tag = f"[{site.name}]"

    if not site.base_url or not site.access_token or not site.user_id:
        return Outcome(site.name, site.base_url, "need_config", STATUS_HINTS["need_config"])

    client = NewApiClient(site)
    log(f"{tag} 开始处理 {site.base_url}")

    try:
        # 1) 验证凭据 + 记录签到前余额（没有比余额差更可靠的发放证据）
        user = client.fetch_user()
        quota_before = user.get("quota")
        quota_before_usd = to_usd(quota_before, site)
        log(f"{tag} 认证有效，当前余额: {fmt_usd(quota_before_usd)}")
        if probe_only:
            return Outcome(site.name, site.base_url, "success", "认证有效", current_quota_usd=quota_before_usd, username=user.get("username") or "")

        # 2) 查签到状态：已签则短路
        status = client.fetch_status()
        if status.get("checked_in_today") is True:
            log(f"{tag} 今日已签到，跳过")
            return Outcome(site.name, site.base_url, "already_done", "今日已签到，无需重复签到",
                           current_quota_usd=quota_before_usd, username=user.get("username") or "")

        # 3) 执行签到；被 Turnstile 拒绝时自动求解令牌重试一次
        try:
            result = client.do_checkin()
        except ApiError as exc:
            result = retry_checkin_with_turnstile(client, site, exc, tag)
        awarded = result.get("quota_awarded")

        # 4) 结果确认：奖励字段缺失/为 0 时不轻信，用余额差与已签标记交叉验证
        awarded_usd = to_usd(awarded, site) if awarded else None
        current_usd = None
        if not awarded_usd:
            time.sleep(1)
            user_after = client.fetch_user()
            current_usd = to_usd(user_after.get("quota"), site)
            if quota_before_usd is not None and current_usd is not None and current_usd - quota_before_usd > 1e-9:
                awarded_usd = round(current_usd - quota_before_usd, 6)
                log(f"{tag} 接口未返回奖励字段，按余额差确认 +{fmt_usd(awarded_usd)}")
            else:
                st2 = client.fetch_status()
                if st2.get("checked_in_today") is True:
                    log(f"{tag} 接口未返回奖励，但站点已标记今日已签到")
                    return Outcome(site.name, site.base_url, "success", "签到成功（站点已标记今日已签到）",
                                   current_quota_usd=current_usd or quota_before_usd,
                                   username=user.get("username") or "")
                return Outcome(site.name, site.base_url, "error",
                               "签到接口返回成功但未发放额度，站点也未标记已签到；可能需要在网页手动签到或接口已变更",
                               current_quota_usd=current_usd or quota_before_usd)
        else:
            # 有奖励字段时不再多发请求：用「签到前余额 + 本次奖励」推导当前余额，
            # 少一次 GET，降低同一出口的请求密度（实测这是触发限流的主因之一）。
            if quota_before_usd is not None and awarded_usd is not None:
                current_usd = round(quota_before_usd + awarded_usd, 6)
            elif quota_before_usd is not None:
                current_usd = quota_before_usd
            else:
                try:
                    current_usd = to_usd(client.fetch_user().get("quota"), site)
                except Exception:
                    current_usd = None

        message = f"签到成功，获得额度：{fmt_usd(awarded_usd)}"
        log(f"{tag} ✓ {message}（当前: {fmt_usd(current_usd)}）")
        return Outcome(site.name, site.base_url, "success", message,
                       quota_awarded_usd=awarded_usd, current_quota_usd=current_usd,
                       username=user.get("username") or "")

    except ApiError as exc:
        kind = classify_error(exc)
        hint = STATUS_HINTS.get(kind, "")
        message = f"{exc.message}" + (f"；{hint}" if hint else "")
        log(f"{tag} ✗ {kind}: {exc.message}")
        # 对外结果只保留稳定提示，不透传接口原始 message，避免泄露用户信息。
        safe_message = hint or "请求失败，请检查站点状态"
        return Outcome(site.name, site.base_url, kind, safe_message)
    except Exception as exc:  # 兜底：未知异常不中断其他站点
        log(f"{tag} ✗ 未预期异常: {type(exc).__name__}")
        return Outcome(site.name, site.base_url, "error", f"{type(exc).__name__}")
    finally:
        # 释放本客户端起的轮换出口进程（mihomo），避免端口/内存泄漏
        try:
            client.close()
        except Exception:
            pass


def to_usd(quota, site: SiteConfig) -> float | None:
    if isinstance(quota, bool) or not isinstance(quota, (int, float)):
        return None
    return quota / (site.quota_per_unit or QUOTA_PER_UNIT)


# ────────────────────────── 配置加载 ──────────────────────────

def load_sites(path: str, only_name: str | None = None) -> list[SiteConfig]:
    if not os.path.exists(path):
        raise SystemExit(f"配置文件不存在: {path}（请参考 ACCOUNTS.example.json 或设置 ACCOUNTS_FILE）")
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    items = raw.get("accounts") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise SystemExit("配置格式错误：应为 {\"accounts\": [...]} 或站点数组")
    sites = []
    seen_keys: set = set()  # 同轮去重用
    for item in items:
        if not isinstance(item, dict):
            continue
        site = SiteConfig(
            name=str(item.get("name") or urllib.parse.urlparse(str(item.get("base_url", ""))).netloc or "未命名"),
            base_url=str(item.get("base_url") or "").rstrip("/"),
            user_id=str(item.get("user_id") or ""),
            access_token=str(item.get("access_token") or ""),
            cookie=str(item.get("cookie") or ""),
            enabled=bool(item.get("enabled", True)),
            referer_path=str(item.get("referer_path") or "/profile"),
            verify_ssl=bool(item.get("verify_ssl", True)),
            proxy=str(item.get("proxy") or ""),
            turnstile=str(item.get("turnstile") or "auto").strip().lower(),
            browser=str(item.get("browser") or os.getenv("CHECKIN_BROWSER", "") or "auto").strip().lower(),
            quota_per_unit=int(item.get("quota_per_unit") or QUOTA_PER_UNIT),
            raw=item,
        )
        if only_name and site.name != only_name:
            continue
        if not site.enabled:
            log(f"[{site.name}] 已禁用，跳过")
            continue
        # 同轮去重：同一 (base_url, access_token) 只跑一次，避免同站点重复打 CF
        # 触发限流（实测：同一站点 5 个相同账号连跑会在第 3 个起被 CF 429/超时拦截）
        dedupe_key = (site.base_url.lower(), site.access_token)
        if dedupe_key in seen_keys:
            log(f"[{site.name}] 与已有站点重复（同 base_url+token），跳过")
            continue
        seen_keys.add(dedupe_key)
        sites.append(site)
    if only_name and not sites:
        raise SystemExit(f"未找到名为 {only_name!r} 的启用站点")
    return sites


# ────────────────────────── 通知与汇总 ──────────────────────────

def notify_telegram(outcomes: list[Outcome]) -> None:
    token = os.getenv("TG_BOT_TOKEN", "")
    chat_id = os.getenv("TG_CHAT_ID", "")
    if not token or not chat_id or not outcomes:
        return
    ok = sum(1 for o in outcomes if o.status in ("success", "already_done"))
    lines = [f"{'✅' if ok == len(outcomes) else '⚠️'} 多站签到 {ok}/{len(outcomes)}"]
    icon_map = {"success": "✅", "already_done": "🎁"}
    for o in outcomes:
        icon = icon_map.get(o.status, "❌")
        detail = ""
        if o.status == "success" and o.quota_awarded_usd:
            detail = f"；获得 {fmt_usd(o.quota_awarded_usd)}"
        if o.current_quota_usd is not None:
            detail += f"；余额 {fmt_usd(o.current_quota_usd)}"
        if o.status not in ("success", "already_done"):
            detail = f"；{o.message[:120]}"
        lines.append(f"{icon} [{o.name}] {o.status}{detail}")
    body = "\n".join(lines)
    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=json.dumps({"chat_id": chat_id, "text": body}).encode(),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.build_opener().open(req, timeout=15).read()
        log("Telegram 通知已发送")
    except Exception as exc:
        log(f"Telegram 通知失败: {type(exc).__name__}")


def write_summary(outcomes: list[Outcome]) -> None:
    """写 GitHub Actions Step Summary（存在 $GITHUB_STEP_SUMMARY 时）。"""
    path = os.getenv("GITHUB_STEP_SUMMARY")
    if not path:
        return
    rows = "\n".join(
        f"| {o.name} | `{o.status}` | {o.message[:80]} | "
        f"{fmt_usd(o.quota_awarded_usd) if o.quota_awarded_usd else '-'} | "
        f"{fmt_usd(o.current_quota_usd) if o.current_quota_usd is not None else '-'} |"
        for o in outcomes
    )
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(
            "## 签到结果\n\n| 站点 | 状态 | 说明 | 获得 | 余额 |\n|---|---|---|---|---|\n"
            + rows + "\n"
        )


# ────────────────────────── 入口 ──────────────────────────

def apply_shard(sites: list[SiteConfig]) -> list[SiteConfig]:
    """按 CHECKIN_SHARD_TOTAL / CHECKIN_SHARD_INDEX 分片，用于把**同一站点的多账号**
    分摊到多次运行，避免单次运行把同一出口的请求打爆触发风控。

    - 同一 `base_url` 有多个账号时：按账号顺序轮转分片，每轮只跑其中一部分；
    - 单账号站点：每轮都跑（分片不影响它）。

    默认不分片（`TOTAL <= 1` 时原样返回）。"""
    try:
        total = int(os.getenv("CHECKIN_SHARD_TOTAL", "1") or "1")
        index = int(os.getenv("CHECKIN_SHARD_INDEX", "0") or "0")
    except ValueError:
        log("CHECKIN_SHARD_TOTAL/INDEX 不是整数，忽略分片")
        return sites
    if total <= 1:
        return sites
    if not 0 <= index < total:
        raise SystemExit(f"CHECKIN_SHARD_INDEX 必须在 [0, {total}) 内")

    groups: dict[str, list[SiteConfig]] = {}
    for s in sites:
        groups.setdefault(s.base_url, []).append(s)

    out: list[SiteConfig] = []
    for members in groups.values():
        if len(members) <= 1:
            out.extend(members)
        else:
            out.extend(m for i, m in enumerate(members) if i % total == index)
    return out


def run_sites_sequential(sites: list[SiteConfig], *, probe_only: bool = False) -> list[Outcome]:
    """串行执行；同一 base_url 的相邻账号之间插入随机间隔，避开站点限流窗口。"""
    delay_min = float(os.getenv("CHECKIN_SITE_DELAY_MIN", "20") or "20")
    delay_max = float(os.getenv("CHECKIN_SITE_DELAY_MAX", "45") or "45")
    delay_max = max(delay_max, delay_min)

    outcomes: list[Outcome] = []
    prev_base: str | None = None
    for site in sites:
        if prev_base == site.base_url and delay_max > 0:
            delay = random.uniform(delay_min, delay_max)
            log(f"同一站点 {site.base_url} 连续签到，等待 {delay:.0f}s 以避开限流窗口")
            time.sleep(delay)
        outcomes.append(run_site(site, probe_only=probe_only))
        prev_base = site.base_url
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description="多站点 New API 自动签到")
    parser.add_argument("--validate", action="store_true", help="校验配置并探测认证（不签到）")
    parser.add_argument("--name", help="只运行指定名称的站点")
    parser.add_argument("--proxy-pool", default="", help="Clash 订阅池 URL（Turnstile 多节点并发过盾 + 签到 HTTP 出口轮换）")
    args = parser.parse_args()
    if args.proxy_pool.strip():
        os.environ["CHECKIN_PROXY_POOL"] = args.proxy_pool.strip()

    accounts_path = os.getenv("ACCOUNTS_FILE", "ACCOUNTS.json")
    sites = load_sites(accounts_path, args.name)
    if not sites:
        log("没有启用站点，退出")
        return 1

    sites = apply_shard(sites)

    log(f"共 {len(sites)} 个站点，模式: {'探测' if args.validate else '签到'}")
    outcomes = run_sites_sequential(sites, probe_only=args.validate)

    print("\n" + "=" * 62)
    ok = 0
    for o in outcomes:
        good = o.status in ("success", "already_done")
        ok += good
        icon = "✅" if good else "❌"
        detail = o.message
        if o.status == "success" and o.quota_awarded_usd:
            detail += f"；当前余额 {fmt_usd(o.current_quota_usd)}"
        print(f"{icon} [{o.name}] {o.status} - {detail}")
        print(f"   站点地址: {o.base_url}")
    print("=" * 62)
    log(f"完成: {ok}/{len(outcomes)}")

    notify_telegram(outcomes)
    write_summary(outcomes)
    return 0 if ok == len(outcomes) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:
        log(f"未预期错误: {type(exc).__name__}")
        sys.exit(2)

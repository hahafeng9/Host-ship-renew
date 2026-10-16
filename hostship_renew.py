#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HostShip 服务器自动续期脚本（会话版 v3）

原理：panel.host-ship.com 是 Jexactyl（Pterodactyl 系）面板，网页登录后
靠 Laravel 会话 Cookie 工作，续期按钮实际调用：
    POST /api/client/servers/<identifier>/renew
带登录会话 Cookie 即可纯 HTTP 续期，绕开登录页的 Turnstile 人机验证
（该验证已实测会拦截 GitHub 机房里的自动化浏览器，三种出口全灭）。

2026-10-16 实测钉死的三个关键点：
  1. 会话有效与否看 GET /api/client/account（200=已登录）。
  2. 本分支没有 GET /api/client/servers 列表路由（404）；服务器列表在
     GET /api/client 根路径返回，identifier 可自动发现。
  3. POST 必须带 X-CSRF-TOKEN 头，其值是任意面板页 HTML 里
     <meta name="csrf-token"> 的原始令牌；用 XSRF-TOKEN Cookie 解码
     冒充会得到 419 CSRF token mismatch。

环境变量（GitHub Secrets）：
    PANEL_COOKIE   必填。浏览器登录面板后任意请求的整行 Cookie 请求头。
    SERVER_ID      可选。服务器 identifier；填错或不填时自动发现。
    PANEL_BASE     可选，默认 https://panel.host-ship.com
    TG_BOT_TOKEN / TG_CHAT_ID  可选，Telegram 通知。
    HOSTSHIP_ROTATED_FILE      工作流注入的暂存文件：每轮把最新 Cookie
                   整行写进去，供工作流回写 Secret（Laravel 每次响应都会
                   重新加密 Cookie，原文变化不等于会话轮换，存最新即可）。

退出码：续期成功/面板拒绝但属窗口或冷却=0；会话失效/真失败=1。
日志只打印 Cookie 指纹（sha256 前 8 位），不打印原文。
"""

import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get('PANEL_BASE', 'https://panel.host-ship.com').rstrip('/')
COOKIE_RAW = os.environ.get('PANEL_COOKIE', '').strip()
SERVER_ID = os.environ.get('SERVER_ID', '').strip()
TG_BOT_TOKEN = os.environ.get('TG_BOT_TOKEN', '').strip()
TG_CHAT_ID = os.environ.get('TG_CHAT_ID', '').strip()
ROTATED_FILE = os.environ.get('HOSTSHIP_ROTATED_FILE', '').strip()

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36')


def fp(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def log(msg: str):
    print(msg, flush=True)


def parse_cookie_header(raw: str) -> dict:
    cookies = {}
    for part in raw.split(';'):
        part = part.strip()
        if not part or '=' not in part:
            continue
        name, value = part.split('=', 1)
        cookies[name.strip()] = value.strip()
    return cookies


def build_cookie_header(cookies: dict) -> str:
    return '; '.join(f'{k}={v}' for k, v in cookies.items())


class Session:
    """手动管理 Cookie 的极简会话；每次响应后吸收服务端下发的新值。"""

    def __init__(self, cookies: dict):
        self.cookies = dict(cookies)
        self.csrf_token = None

    def _headers(self, extra=None):
        headers = {
            'User-Agent': UA,
            'Accept': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'Cookie': build_cookie_header(self.cookies),
        }
        if self.csrf_token:
            headers['X-CSRF-TOKEN'] = self.csrf_token
        xsrf = self.cookies.get('XSRF-TOKEN')
        if xsrf:
            headers['X-XSRF-TOKEN'] = urllib.parse.unquote(xsrf)
        if extra:
            headers.update(extra)
        return headers

    def _capture(self, headers):
        if headers is None:
            return
        for raw in headers.get_all('Set-Cookie') or []:
            first = raw.split(';', 1)[0].strip()
            if '=' not in first:
                continue
            name, value = first.split('=', 1)
            self.cookies[name.strip()] = value.strip()

    def request(self, method: str, path: str):
        url = path if path.startswith('http') else BASE + path
        data = b'{}' if method == 'POST' else None
        extra = {'Content-Type': 'application/json'} if data else None
        req = urllib.request.Request(url, data=data,
                                     headers=self._headers(extra),
                                     method=method)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                self._capture(resp.headers)
                return resp.status, resp.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            self._capture(e.headers)
            return e.code, e.read().decode('utf-8', 'replace')
        except Exception as e:
            return 0, f'{type(e).__name__}: {e}'

    def fetch_csrf_token(self) -> bool:
        """打开一个面板页，从 HTML meta 里取本会话的原始 CSRF 令牌。"""
        for path in ('/', '/auth/login'):
            status, html = self.request('GET', path)
            m = re.search(r'<meta name="csrf-token" content="([^"]+)"',
                          html or '')
            if m:
                self.csrf_token = m.group(1)
                log(f'[INFO] 已获取 CSRF 令牌（长度 {len(self.csrf_token)}）')
                return True
        log('[WARN] 未能从面板页提取 CSRF 令牌')
        return False


def tg_send(text: str):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    try:
        data = urllib.parse.urlencode(
            {'chat_id': TG_CHAT_ID, 'text': text}).encode()
        req = urllib.request.Request(
            f'https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage',
            data=data)
        urllib.request.urlopen(req, timeout=20).read()
    except Exception as e:
        log(f'[WARN] Telegram 通知失败: {e}')


def get_server(sess: Session, identifier: str):
    status, body = sess.request('GET',
                                f'/api/client/servers/{identifier}')
    if status != 200:
        return status, {}
    try:
        data = json.loads(body)
        return 200, data.get('attributes', {}) or {}
    except Exception:
        return status, {}


def discover_identifier(sess: Session):
    """GET /api/client 根路径返回服务器列表，取第一台的 identifier。"""
    status, body = sess.request('GET', '/api/client')
    if status != 200:
        return None
    try:
        data = json.loads(body)
        for item in data.get('data', []):
            if item.get('object') == 'server':
                return item.get('attributes', {}).get('identifier')
    except Exception:
        pass
    return None


def save_latest_cookie(sess: Session):
    if not ROTATED_FILE:
        return
    try:
        with open(ROTATED_FILE, 'w', encoding='utf-8') as f:
            f.write(build_cookie_header(sess.cookies))
        log('[INFO] 最新 Cookie 已暂存，等待回写')
    except Exception as e:
        log(f'[WARN] 暂存 Cookie 失败: {e}')


def main() -> int:
    if not COOKIE_RAW:
        log('[ERROR] 缺少 PANEL_COOKIE 环境变量')
        return 1
    cookies = parse_cookie_header(COOKIE_RAW)
    if not cookies:
        log('[ERROR] PANEL_COOKIE 解析为空，请填整行 Cookie 请求头')
        return 1
    log(f'[INFO] 已载入 Cookie：{len(cookies)} 项（指纹 {fp(COOKIE_RAW)}）')
    sess = Session(cookies)

    # 0) 会话有效性：账号接口 200 才算登录态活着
    status, body = sess.request('GET', '/api/client/account')
    if status != 200:
        log(f'[ERROR] 会话已失效（账号接口 HTTP {status}），'
            '请重新抓取 PANEL_COOKIE')
        tg_send('HostShip 续期失败：面板会话已失效，请重新抓取 Cookie。')
        save_latest_cookie(sess)
        return 1
    try:
        acct = json.loads(body).get('attributes', {})
        log(f"[INFO] 会话有效，账号: {acct.get('username')}")
    except Exception:
        log('[INFO] 会话有效（账号接口 200）')

    # 1) 确定服务器 identifier：先用 SERVER_ID，404 则自动发现
    identifier = SERVER_ID
    attrs = {}
    if identifier:
        status, attrs = get_server(sess, identifier)
        if status == 404:
            log(f'[WARN] SERVER_ID={identifier} 查不到服务器（404），'
                '改走自动发现')
            identifier = None
        elif status != 200:
            log(f'[ERROR] 读取服务器失败: HTTP {status}')
            save_latest_cookie(sess)
            return 1
    if not identifier:
        identifier = discover_identifier(sess)
        if not identifier:
            log('[ERROR] 自动发现失败：账号下没有可见服务器')
            save_latest_cookie(sess)
            return 1
        log(f'[INFO] 自动发现服务器 identifier: {identifier}')
        status, attrs = get_server(sess, identifier)
        if status != 200:
            log(f'[ERROR] 读取服务器失败: HTTP {status}')
            save_latest_cookie(sess)
            return 1

    expiry_before = attrs.get('renewal_expires_at')
    log(f"[INFO] 服务器 {attrs.get('name')} identifier={identifier} "
        f"到期={expiry_before} renewable={attrs.get('renewable')} "
        f"cooldown={attrs.get('renewal_cooldown')} "
        f"suspended={attrs.get('is_suspended')}")

    # 2) 取 CSRF 令牌后调用续期
    sess.fetch_csrf_token()
    status, body = sess.request(
        'POST', f'/api/client/servers/{identifier}/renew')
    if status == 419:
        log('[WARN] CSRF 令牌不匹配（419），刷新令牌后重试一次')
        sess.fetch_csrf_token()
        status, body = sess.request(
            'POST', f'/api/client/servers/{identifier}/renew')
    log(f'[INFO] 续期接口返回: HTTP {status}')
    body_low = body.lower()
    result = 0
    if status in (200, 201, 204):
        _, attrs2 = get_server(sess, identifier)
        expiry_after = attrs2.get('renewal_expires_at')
        if expiry_after and expiry_after != expiry_before:
            log(f'[SUCCESS] 续期成功，新到期时间: {expiry_after}')
            tg_send(f'HostShip 续期成功，新到期：{expiry_after}')
        else:
            log(f'[SUCCESS] 续期接口已接受，回读到期: {expiry_after}')
            tg_send('HostShip 续期接口已接受，请留意面板到期时间。')
    elif 'captcha' in body_low:
        log('[ERROR] 网页会话调用续期也被 captcha 拦住，'
            '需要在面板里手动点续期')
        tg_send('HostShip 续期被 captcha 拦住，需要手动在面板续期。')
        result = 1
    elif status in (401, 403):
        log('[ERROR] 会话被拒绝（续期时），请重新抓取 PANEL_COOKIE')
        tg_send('HostShip 续期失败：面板会话被拒绝，请重新抓取 Cookie。')
        result = 1
    elif status == 419:
        log(f'[ERROR] CSRF 令牌重试后仍不匹配: {body[:200]}')
        result = 1
    elif status in (400, 422, 429):
        # 面板以 4xx 拒绝：多为冷却中/未到窗口/次数上限，属正常跳过，
        # 但把原文带出来便于核对，并发 TG 让用户看得见。
        log(f'[INFO] 面板拒绝续期（HTTP {status}），按未到窗口/冷却处理: '
            f'{body[:250]}')
        tg_send(f'HostShip 本轮未续期（HTTP {status}）：{body[:150]}')
    else:
        log(f'[ERROR] 续期失败: HTTP {status} {body[:250]}')
        tg_send(f'HostShip 续期失败：HTTP {status}')
        result = 1

    save_latest_cookie(sess)
    return result


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HostShip 服务器自动续期脚本（会话版）

原理：panel.host-ship.com 是 Pterodactyl 系面板，网页登录后靠 Laravel
会话 Cookie 工作，续期按钮实际调用：
    POST /api/client/servers/<SERVER_ID>/renew
带上登录会话 Cookie 即可纯 HTTP 续期，绕开登录页的 Turnstile 人机验证
（该验证已实测会拦截 GitHub 机房里的自动化浏览器，三种出口全灭）。

需要的环境变量（GitHub Secrets）：
    PANEL_COOKIE   必填。浏览器登录面板后任意请求的整行 Cookie 请求头。
    SERVER_ID      必填。服务器的短 ID（identifier）。
    PANEL_BASE     可选，默认 https://panel.host-ship.com
    TG_BOT_TOKEN / TG_CHAT_ID  可选，Telegram 通知。
    HOSTSHIP_ROTATED_FILE      由工作流注入的暂存文件路径，会话被服务端
                   轮换时把新 Cookie 整行写进去，供工作流回写 Secret。

退出码：成功/窗口未开=0；会话失效/续期失败=1（工作流标红）。
日志只打印 Cookie 指纹（sha256 前 8 位），不打印原文。
"""

import hashlib
import json
import os
import sys
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
    """极简会话：手动管理 Cookie，捕获服务端轮换的会话值。"""

    def __init__(self, cookies: dict):
        self.cookies = dict(cookies)
        self.session_key = next(
            (k for k in cookies if k.endswith('_session')), None)

    def request(self, method: str, path: str):
        url = BASE + path
        headers = {
            'User-Agent': UA,
            'Accept': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'Cookie': build_cookie_header(self.cookies),
        }
        xsrf = self.cookies.get('XSRF-TOKEN')
        if xsrf:
            headers['X-XSRF-TOKEN'] = urllib.parse.unquote(xsrf)
        data = b'{}' if method == 'POST' else None
        if data is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                self._capture(resp.headers)
                body = resp.read().decode('utf-8', 'replace')
                return resp.status, body
        except urllib.error.HTTPError as e:
            self._capture(e.headers)
            return e.code, e.read().decode('utf-8', 'replace')
        except Exception as e:  # 网络层错误
            return 0, f'{type(e).__name__}: {e}'

    def _capture(self, headers):
        if headers is None:
            return
        for raw in headers.get_all('Set-Cookie') or []:
            first = raw.split(';', 1)[0].strip()
            if '=' not in first:
                continue
            name, value = first.split('=', 1)
            name = name.strip()
            if name in self.cookies and self.cookies[name] != value.strip():
                self.cookies[name] = value.strip()
                log(f'[INFO] Cookie 被服务端更新: {name} '
                    f'(fingerprint {fp(value.strip())})')


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


def pick_fields(attrs: dict) -> dict:
    """从服务器 attributes 里挑出与状态/到期相关的字段打日志。"""
    interesting = {}
    for key, value in attrs.items():
        lk = key.lower()
        if any(s in lk for s in ('expir', 'renew', 'suspend', 'status',
                                 'state', 'date', 'until', 'days', 'name')):
            interesting[key] = value
    return interesting


def extract_expiry(attrs: dict):
    for key in ('expires_at', 'expiry', 'expires', 'renewal_date',
                'expiration_date'):
        if attrs.get(key):
            return str(attrs[key])
    return None


def save_rotation(sess: Session, original_session):
    """会话被服务端轮换时，把更新后的整行 Cookie 写入暂存文件供回写。"""
    if not ROTATED_FILE or not sess.session_key:
        return
    current = sess.cookies.get(sess.session_key)
    if current and original_session and current != original_session:
        with open(ROTATED_FILE, 'w', encoding='utf-8') as f:
            f.write(build_cookie_header(sess.cookies))
        log(f'[INFO] 检测到会话轮换，新 Cookie 已暂存'
            f'（指纹 {fp(current)}），等待回写')


def main() -> int:
    if not COOKIE_RAW or not SERVER_ID:
        log('[ERROR] 缺少 PANEL_COOKIE 或 SERVER_ID 环境变量')
        return 1
    cookies = parse_cookie_header(COOKIE_RAW)
    if not cookies:
        log('[ERROR] PANEL_COOKIE 解析为空，请填整行 Cookie 请求头')
        return 1
    log(f'[INFO] 已载入 Cookie：{len(cookies)} 项'
        f'（指纹 {fp(COOKIE_RAW)}），服务器 {SERVER_ID}')
    sess = Session(cookies)
    original_session = (sess.cookies.get(sess.session_key)
                        if sess.session_key else None)

    # 1) 读取服务器当前状态
    status, body = sess.request('GET', f'/api/client/servers/{SERVER_ID}')
    log(f'[INFO] 读取服务器状态: HTTP {status}')
    if status in (401, 403, 419):
        log('[ERROR] 会话已失效（被面板拒绝），请重新抓取 PANEL_COOKIE')
        tg_send('HostShip 续期失败：面板会话已失效，请重新抓取 Cookie。')
        save_rotation(sess, original_session)
        return 1
    if status == 0:
        log(f'[ERROR] 网络错误：{body[:200]}')
        return 1
    attrs = {}
    try:
        data = json.loads(body)
        attrs = data.get('attributes', data) if isinstance(data, dict) else {}
    except Exception:
        log(f'[WARN] 状态响应不是预期 JSON（前 200 字）：{body[:200]}')
    fields = pick_fields(attrs)
    if fields:
        log(f'[INFO] 服务器字段: {json.dumps(fields, ensure_ascii=False)}')
    expiry_before = extract_expiry(attrs)
    if expiry_before:
        log(f'[INFO] 续期前到期时间: {expiry_before}')

    # 2) 调用续期接口
    status, body = sess.request(
        'POST', f'/api/client/servers/{SERVER_ID}/renew')
    log(f'[INFO] 续期接口返回: HTTP {status}')
    body_low = body.lower()
    result = 0
    if status in (200, 201, 204):
        # 回读确认到期时间是否变化
        _, body2 = sess.request('GET', f'/api/client/servers/{SERVER_ID}')
        expiry_after = None
        try:
            data2 = json.loads(body2)
            attrs2 = data2.get('attributes', data2) \
                if isinstance(data2, dict) else {}
            expiry_after = extract_expiry(attrs2)
        except Exception:
            pass
        if expiry_after and expiry_after != expiry_before:
            log(f'[SUCCESS] 续期成功，新到期时间: {expiry_after}')
            tg_send(f'HostShip 续期成功，新到期：{expiry_after}')
        else:
            log('[SUCCESS] 续期接口已接受（到期时间字段未变或不可见）'
                f'，回读到期: {expiry_after}')
            tg_send('HostShip 续期接口已接受，请留意面板到期时间。')
    elif status == 400 and ('not_available' in body_low
                            or 'not available' in body_low
                            or 'not yet' in body_low
                            or 'remaining' in body_low):
        log('[INFO] 续期窗口未开（未到可续时间），本轮正常跳过')
    elif 'captcha' in body_low:
        log('[ERROR] 网页会话调用续期也被 captcha 拦住，'
            '需要在面板里手动点续期')
        tg_send('HostShip 续期被 captcha 拦住，需要手动在面板续期。')
        result = 1
    elif status in (401, 403, 419):
        log('[ERROR] 会话已失效（续期时被拒绝），请重新抓取 PANEL_COOKIE')
        tg_send('HostShip 续期失败：面板会话已失效，请重新抓取 Cookie。')
        result = 1
    elif status == 400:
        log(f'[WARN] 续期返回 400：{body[:300]}')
    else:
        log(f'[ERROR] 续期失败: HTTP {status} {body[:300]}')
        tg_send(f'HostShip 续期失败：HTTP {status}')
        result = 1

    save_rotation(sess, original_session)
    return result


if __name__ == '__main__':
    sys.exit(main())

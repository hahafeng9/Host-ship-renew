# -*- coding: utf-8 -*-
"""
HostShip 自动续期 (带节点代理版)

流程:
  1. 若配置了 NODE_LINK secret (vless/vmess/trojan/ss 链接),
     自动解析并生成 xray 配置, 在本机拉起 socks5://127.0.0.1:10808
  2. Playwright 浏览器通过该节点代理访问 panel.host-ship.com
  3. 登录 -> 打开服务器页 -> 点击 Renew 续期
  4. 节点不可用时自动回退直连, 并通过 TG 通知
"""

import os
import re
import json
import base64
import shutil
import socket
import subprocess
import zipfile
import urllib.parse

import requests
from playwright.sync_api import sync_playwright

PANEL_URL = "https://panel.host-ship.com/"
LOGIN_URL = PANEL_URL

SOCKS_PORT = 10808
XRAY_DIR = os.environ.get("XRAY_DIR", "xray-bin")
XRAY_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"

LOGGED_IN_MARKERS = [
    'button:has-text("Sign Out")', 'text=Sign Out', 'text=Logout',
    'a[href*="logout"]', 'a[href*="/dashboard"]',
]
RENEW_SUCCESS_MARKERS = [
    "Success", "success", "成功", "续期", "Renewed", "extended", "Extended",
]

STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
window.chrome = window.chrome || { runtime: {} };
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en', 'zh-CN']});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
const origQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (p) =>
    p.name === 'notifications'
        ? Promise.resolve({state: Notification.permission})
        : origQuery(p);
"""


def log(msg): print(f"[INFO] {msg}", flush=True)
def warn(msg): print(f"[WARN] {msg}", flush=True)
def err(msg): print(f"[ERROR] {msg}", flush=True)


# ---------------- Telegram ----------------

def tg_send_text(text):
    token = os.environ.get("TG_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TG_CHAT_ID", "").strip()
    if not token or not chat_id:
        warn("未配置 TG_BOT_TOKEN / TG_CHAT_ID")
        return False
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text}, timeout=20,
        )
        if r.status_code != 200:
            warn(f"TG sendMessage 失败: {r.status_code} {r.text[:200]}")
            return False
        return True
    except Exception as e:
        warn(f"TG sendMessage 异常: {e}")
        return False


def tg_send_photo(path, caption=""):
    token = os.environ.get("TG_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TG_CHAT_ID", "").strip()
    if not token or not chat_id or not os.path.exists(path):
        return False
    try:
        with open(path, "rb") as f:
            r = requests.post(
                f"https://api.telegram.org/bot{token}/sendPhoto",
                data={"chat_id": chat_id, "caption": caption[:1024]},
                files={"photo": f}, timeout=30,
            )
        return r.status_code == 200
    except Exception as e:
        warn(f"TG sendPhoto 异常: {e}")
        return False


def save_debug(page, tag, send=True):
    try:
        path = f"debug_{tag}.png"
        page.screenshot(path=path, full_page=True)
        if send:
            tg_send_photo(path, caption=f"📸 {tag}")
    except Exception as e:
        warn(f"截图失败: {e}")
    try:
        with open(f"debug_{tag}.html", "w", encoding="utf-8") as f:
            f.write(page.content())
    except Exception as e:
        warn(f"保存HTML失败: {e}")
    return None


def log_page_state(page):
    """采集页面上的按钮/iframe 信息, 便于定位验证组件."""
    try:
        btns = page.eval_on_selector_all(
            "button, input[type='submit'], a[class*='btn']",
            "els => els.map(e => (e.innerText || e.value || '').trim()).filter(Boolean)",
        )
        warn(f"页面按钮: {btns[:20]}")
    except Exception as e:
        warn(f"采集按钮失败: {e}")
    try:
        ifr = page.eval_on_selector_all("iframe", "els => els.map(e => e.src)")
        warn(f"页面iframe: {ifr[:10]}")
    except Exception as e:
        warn(f"采集iframe失败: {e}")
    try:
        captcha = page.eval_on_selector_all(
            "[class*='captcha'], [class*='turnstile'], [class*='hcaptcha'], [class*='recaptcha'], [class*='geetest'], [id*='captcha'], [id*='turnstile'], [id*='hcaptcha'], [id*='recaptcha'], [id*='geetest']",
            "els => els.map(e => (e.tagName + '|' + (e.className||'') + '|' + (e.id||'')).slice(0,120))",
        )
        warn(f"疑似验证组件: {captcha[:10]}")
    except Exception:
        pass
    try:
        warn(f"当前URL: {page.url}")
    except Exception:
        pass


# ---------------- 节点解析 (生成浏览器可用的 socks5) ----------------

def _b64pad(s):
    return s + "=" * (-len(s) % 4)


def parse_node_link(link):
    """把 vless/vmess/trojan/ss 分享链接解析成 xray outbound dict."""
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()

    if scheme == "vmess":
        data = json.loads(base64.b64decode(_b64pad(link[8:])).decode("utf-8", "ignore"))
        net = data.get("net", "tcp")
        stream = {"network": net, "security": "tls" if str(data.get("tls")) in ("tls", "True", "true") else "none"}
        if net == "ws":
            stream["wsSettings"] = {"path": data.get("path", "/")}
            if data.get("host"):
                stream["wsSettings"]["headers"] = {"Host": data.get("host")}
        if stream["security"] == "tls":
            stream["tlsSettings"] = {"serverName": data.get("sni") or data.get("host") or data.get("add", "")}
        return {
            "protocol": "vmess",
            "settings": {"vnext": [{
                "address": data["add"],
                "port": int(data["port"]),
                "users": [{"id": data["id"], "alterId": int(data.get("aid") or 0), "security": "auto"}],
            }]},
            "streamSettings": stream,
        }

    if scheme in ("vless", "trojan"):
        u = urllib.parse.urlparse(link)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        net = q.get("type", "tcp")
        security = q.get("security", "none" if scheme == "trojan" else "none")
        if security in ("tls", "reality"):
            ts = {"serverName": q.get("sni", u.hostname), "allowInsecure": q.get("allowInsecure") == "1"}
            if q.get("fp"):
                ts["fingerprint"] = q["fp"]
            if security == "reality":
                ts["publicKey"] = q.get("pbk", "")
                ts["shortId"] = q.get("sid", "")
        stream = {"network": net, "security": security if security != "reality" else "reality"}
        if net == "ws":
            stream["wsSettings"] = {"path": q.get("path", "/")}
            if q.get("host"):
                stream["wsSettings"]["headers"] = {"Host": q["host"]}
        if net == "grpc":
            stream["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
        if security in ("tls", "reality"):
            stream["tlsSettings" if security == "tls" else "realitySettings"] = ts

        if scheme == "vless":
            return {
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": u.hostname,
                    "port": u.port or 443,
                    "users": [{"id": u.username, "encryption": "none", "flow": q.get("flow", "")}],
                }]},
                "streamSettings": stream,
            }
        # trojan
        return {
            "protocol": "trojan",
            "settings": {"servers": [{
                "address": u.hostname,
                "port": u.port or 443,
                "password": urllib.parse.unquote(u.username or ""),
            }]},
            "streamSettings": stream,
        }

    if scheme == "ss":
        body = link[5:].split("#", 1)[0]
        userinfo, hostport = None, None
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            try:
                userinfo = base64.b64decode(_b64pad(userinfo)).decode("utf-8", "ignore")
            except Exception:
                userinfo = urllib.parse.unquote(userinfo)
        else:
            body = base64.b64decode(_b64pad(body)).decode("utf-8", "ignore")
            userinfo, hostport = body.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
        host, port = hostport.rsplit(":", 1)
        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": host, "port": int(port),
                "method": method, "password": password,
            }]},
        }

    raise ValueError(f"不支持的节点协议: {scheme}")


def build_xray_config(outbound):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": SOCKS_PORT,
            "protocol": "socks",
            "settings": {"udp": True, "auth": "noauth"},
        }],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": [{
            "type": "field",
            "ip": ["geoip:private"],
            "outboundTag": "direct",
        }]},
    }


def download_xray():
    """下载(或复用已缓存的) xray 二进制, 返回可执行路径."""
    exe = os.path.join(XRAY_DIR, "xray")
    if os.path.exists(exe):
        log("使用已缓存的 xray")
        return exe
    log("下载 xray ...")
    os.makedirs(XRAY_DIR, exist_ok=True)
    zpath = os.path.join(XRAY_DIR, "xray.zip")
    with requests.get(XRAY_URL, timeout=120, stream=True) as r:
        r.raise_for_status()
        with open(zpath, "wb") as f:
            for chunk in r.iter_content(1 << 16):
                f.write(chunk)
    with zipfile.ZipFile(zpath) as z:
        for name in z.namelist():
            if name.strip("/") in ("xray", "geoip.dat", "geosite.dat"):
                z.extract(name, XRAY_DIR)
    os.remove(zpath)
    os.chmod(exe, 0o755)
    return exe


def start_proxy(link):
    """启动 xray socks5 代理, 返回 (process, proxy_url)."""
    outbound = parse_node_link(link)
    cfg_path = os.path.join(XRAY_DIR, "config.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(build_xray_config(outbound), f, ensure_ascii=False)

    exe = download_xray()
    proc = subprocess.Popen(
        [exe, "run", "-c", cfg_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    proxy_url = f"socks5://127.0.0.1:{SOCKS_PORT}"

    # 等待 socks5 端口就绪
    for _ in range(30):
        if proc.poll() is not None:
            out = proc.stdout.read().decode("utf-8", "ignore")[:500] if proc.stdout else ""
            raise RuntimeError(f"xray 启动失败: {out}")
        try:
            with socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=1):
                return proc, proxy_url
        except OSError:
            import time
            time.sleep(0.5)
    proc.terminate()
    raise RuntimeError("socks5 端口等待超时")


# ---------------- Playwright 主流程 ----------------

def login(page, username, password):
    log("打开登录页...")
    page.goto(LOGIN_URL, timeout=60000, wait_until="domcontentloaded")
    page.wait_for_timeout(3000)
    try:
        page.get_by_placeholder("Username or Email").first.wait_for(state="visible", timeout=60000)
        page.get_by_placeholder("Password").first.wait_for(state="visible", timeout=60000)
    except Exception:
        save_debug(page, "login_form_not_found")
        log_page_state(page)
        raise RuntimeError("未找到登录输入框")

    page.get_by_placeholder("Username or Email").first.fill(username)
    page.get_by_placeholder("Password").first.fill(password)

    # 登录页的 Turnstile 在填完账号密码后才真正拦截提交
    if not solve_human_check(page):
        save_debug(page, "sign_in_not_found")
        raise RuntimeError("登录页人机验证未通过")

    submit = page.locator('button[type="submit"]').first
    appeared = False
    for _ in range(30):
        try:
            if submit.count() > 0 and submit.is_visible() and not submit.is_disabled():
                appeared = True
                break
        except Exception:
            pass
        if _has_turnstile(page):
            solve_human_check(page)
        page.wait_for_timeout(1000)
    if not appeared:
        save_debug(page, "sign_in_not_found")
        log_page_state(page)
        raise RuntimeError("未找到可用的提交按钮")

    page.wait_for_timeout(3000)  # 冷却几秒再点登录
    submit.click()
    for _ in range(30):
        page.wait_for_timeout(1000)
        if _has_turnstile(page) and turnstile_token(page) == "":
            solve_human_check(page)  # 提交后如再弹验证, 继续过
        if any(page.locator(m).count() > 0 for m in LOGGED_IN_MARKERS):
            log(f"登录成功: {page.url}")
            return
    save_debug(page, "login_failed")
    log_page_state(page)
    raise RuntimeError("登录失败")


def get_renewal_days(page):
    try:
        m = re.search(r"RENEWAL\s*(?:IN|:)?\s*(\d+)\s*(?:Day|Days|天)", page.inner_text("body"), re.IGNORECASE)
        return int(m.group(1)) if m else None
    except Exception:
        return None


# ---------------- 人机验证 (Cloudflare Turnstile) ----------------

def turnstile_frames(page):
    return page.locator('iframe[src*="challenges.cloudflare.com/turnstile"]')


def turnstile_token(page):
    try:
        return page.evaluate(
            """() => {
                const el = document.querySelector(
                    'input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"]');
                return el ? el.value : '';
            }"""
        ) or ""
    except Exception:
        return ""


def _has_turnstile(page):
    try:
        if page.locator('input[name="cf-turnstile-response"]').count() > 0:
            return True
    except Exception:
        pass
    try:
        return turnstile_frames(page).count() > 0
    except Exception:
        return False


def _click_turnstile_checkbox(page):
    try:
        tf = page.frame_locator('iframe[src*="challenges.cloudflare.com/turnstile"]').first
        tf.locator("input[type='checkbox']").click(timeout=4000)
        return True
    except Exception:
        pass
    # 兜底1: 点击 iframe 几何中心
    try:
        box = turnstile_frames(page).first.bounding_box()
        if box:
            page.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
            return True
    except Exception:
        pass
    # 兜底2: 页面上只有 hidden input 时, 根据截图位置点验证码容器左侧复选框区域
    try:
        box = page.locator('input[name="cf-turnstile-response"]').first.bounding_box()
        if box:
            x = max(5, box["x"] + 28)
            y = max(5, box["y"] - 18)
            page.mouse.move(x, y)
            page.wait_for_timeout(800)
            page.mouse.click(x, y)
            page.wait_for_timeout(800)
            return True
    except Exception:
        pass
    # 兜底3: 点击验证区域容器左中部
    for sel in ['div.mb-5', 'div[class*="min-h-[65px]"]', 'div.flex.justify-center.min-h-[65px]']:
        try:
            box = page.locator(sel).first.bounding_box()
            if box:
                x = box["x"] + min(32, box["width"] * 0.18)
                y = box["y"] + box["height"] / 2
                page.mouse.move(x, y)
                page.wait_for_timeout(800)
                page.mouse.click(x, y)
                page.wait_for_timeout(800)
                return True
        except Exception:
            pass
    warn("点击验证框失败: 未找到可点击区域")
    return False


def solve_human_check(page, max_rounds=3):
    """等待 Turnstile 出 token; 必要时冷却后点复选框; 仍失败则刷新重试."""
    try:
        if not _has_turnstile(page):
            return True
    except Exception:
        return True
    log("检测到人机验证 (Turnstile), 等待通过...")
    for i in range(max_rounds):
        # 1) 先等自动通过(真实 Chrome 下 managed 模式通常自动完成)
        for _ in range(45):
            token = turnstile_token(page)
            if token != "":
                log("人机验证通过")
                return True
            try:
                submit = page.locator('button[type="submit"]').first
                txt = (submit.inner_text() or '').strip()
                if submit.count() > 0 and not submit.is_disabled() and txt.lower() != 'complete the security check':
                    log("提交按钮已解锁, 视为验证通过")
                    return True
            except Exception:
                pass
            page.wait_for_timeout(1000)
        # 2) 冷却几秒后点击复选框
        page.wait_for_timeout(4000)
        _click_turnstile_checkbox(page)
        for _ in range(15):
            token = turnstile_token(page)
            if token != "":
                log("点击复选框后人机验证通过")
                return True
            try:
                submit = page.locator('button[type="submit"]').first
                txt = (submit.inner_text() or '').strip()
                if submit.count() > 0 and not submit.is_disabled() and txt.lower() != 'complete the security check':
                    log("点击复选框后提交按钮已解锁")
                    return True
            except Exception:
                pass
            page.wait_for_timeout(1000)
        # 3) 仍失败: 刷新页面重试
        warn(f"第 {i + 1} 轮验证未通过, 刷新重试")
        try:
            page.reload(wait_until="domcontentloaded")
            page.wait_for_timeout(3000)
        except Exception as e:
            warn(f"刷新失败: {e}")
    save_debug(page, "captcha_failed")
    log_page_state(page)
    return False


def renew_server(page, server_id):
    url = f"{PANEL_URL}server/{server_id}"
    log(f"打开详情页: {url}")
    page.goto(url, timeout=60000, wait_until="domcontentloaded")
    page.wait_for_timeout(2500)
    solve_human_check(page)  # 详情页也可能弹验证

    if page.locator('text=The requested resource was not found').count() > 0:
        save_debug(page, "page_404")
        return "404"

    days = get_renewal_days(page)
    left = f"剩余 {days} 天" if days is not None else "有效期未知"

    for text in ["Renew", "Renew Server", "续期", "Renouveler"]:
        btn = page.locator(f'button:has-text("{text}")')
        if btn.count() > 0 and btn.first.is_visible():
            # 按钮禁用 → 跳过, 不报错
            if btn.first.is_disabled() or btn.first.get_attribute("disabled") is not None:
                log(f"续期按钮禁用,跳过({left})")
                tg_send_text(f"✅ 服务器 {server_id}:{left},按钮不可用(可能 Renew Limit Reached),本次跳过")
                return "skip"

            btn.first.click()
            log(f"已点击续期按钮: {text}")
            page.wait_for_timeout(2000)
            for c_text in ["Confirm", "确认", "Yes", "OK"]:
                cb = page.locator(f'button:has-text("{c_text}")')
                if cb.count() > 0 and cb.first.is_visible(timeout=2000):
                    cb.first.click()
                    page.wait_for_timeout(2000)
                    break
            for _ in range(10):
                page.wait_for_timeout(1000)
                if any(page.locator(f"text={m}").count() > 0 for m in RENEW_SUCCESS_MARKERS):
                    log(f"续期成功: {url}")
                    return "success"
            save_debug(page, "renew_clicked_unknown")
            return "no_confirmation"

    save_debug(page, "renew_button_not_found")
    return "not_found"


def check_exit_ip(page):
    """通过浏览器检查出口 IP(走代理时验证节点是否生效)."""
    try:
        page.goto("https://api.ipify.org/", timeout=30000, wait_until="domcontentloaded")
        page.wait_for_timeout(1000)
        ip = page.inner_text("body").strip()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            log(f"当前出口 IP: {ip}")
            return ip
    except Exception as e:
        warn(f"出口 IP 检查失败: {e}")
    return None


def launch_browser(playwright, proxy_url):
    args = ["--disable-dev-shm-usage", "--no-sandbox", "--disable-gpu",
            "--disable-blink-features=AutomationControlled"]
    if proxy_url:
        args.append(f"--proxy-server={proxy_url}")
    # 默认有头(配合 xvfb); HEADLESS=1 时才无头
    headless = os.environ.get("HEADLESS", "0").strip() == "1"
    return playwright.chromium.launch(headless=headless, args=args)


def new_page(browser):
    page = browser.new_page(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    )
    page.add_init_script(STEALTH_JS)
    return page


def run(playwright):
    username = os.environ.get("PANEL_USERNAME", "").strip()
    password = os.environ.get("PANEL_PASSWORD", "").strip()
    server_id = os.environ.get("SERVER_ID", "").strip()
    node_link = os.environ.get("NODE_LINK", "").strip()

    if not username or not password:
        err("缺少 PANEL_USERNAME / PANEL_PASSWORD")
        return
    if not server_id:
        err("缺少 SERVER_ID")
        return

    # ---- 启动节点代理 (可选) ----
    proxy_proc = None
    proxy_url = None
    mode = "直连"
    if node_link:
        try:
            proxy_proc, proxy_url = start_proxy(node_link)
            mode = "节点代理"
            log(f"节点代理已就绪: {proxy_url}")
        except Exception as e:
            err(f"节点代理启动失败, 回退直连: {e}")
            tg_send_text(f"⚠️ HostShip 续期: 节点代理启动失败({e}),已回退直连")
            proxy_proc = None
            proxy_url = None

    browser = launch_browser(playwright, proxy_url)
    page = new_page(browser)
    try:
        exit_ip = check_exit_ip(page)
        if proxy_url and exit_ip is None:
            # 节点代理不通, 回退直连重开浏览器
            warn("代理下无法访问外网, 回退直连")
            tg_send_text("⚠️ HostShip 续期: 节点代理不通,已回退直连")
            browser.close()
            proxy_url = None
            mode = "直连(代理回退)"
            browser = launch_browser(playwright, None)
            page = new_page(browser)
            check_exit_ip(page)

        log(f"访问模式: {mode}")
        login(page, username, password)
        result = renew_server(page, server_id)
        ip_note = f"\n出口 IP: {exit_ip}" if exit_ip else ""
        if result == "success":
            tg_send_text(f"✅ HostShip 续期成功: {server_id}\n模式: {mode}{ip_note}")
        elif result == "404":
            tg_send_text(f"❌ 服务器页面 404: {server_id}")
        elif result == "no_confirmation":
            tg_send_text(f"⚠️ 已点击续期但未确认:{server_id},请看截图")
        elif result == "not_found":
            tg_send_text(f"⚠️ 未找到续期按钮:{server_id},请看截图")
        # skip 已在 renew_server 里发过通知,这里不用再发
    except Exception as e:
        err(f"执行失败: {e}")
        save_debug(page, "fatal")
        tg_send_text(f"❌ HostShip 自动续期执行失败:{e}")
    finally:
        try:
            browser.close()
        except Exception:
            pass
        if proxy_proc:
            proxy_proc.terminate()


with sync_playwright() as playwright:
    run(playwright)

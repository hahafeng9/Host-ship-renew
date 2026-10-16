# -*- coding: utf-8 -*-
"""
HostShip 自动续期 (带节点代理版)

流程:
  1. 若配置了 NODE_LINK secret (vless/vmess/hy2/trojan/ss 链接),
     自动解析并生成 sing-box 配置, 在本机拉起 socks5://127.0.0.1:10808
  2. Playwright 浏览器通过该节点代理访问 panel.host-ship.com
  3. 登录 -> 打开服务器页 -> 点击 Renew 续期
  4. 节点不可用时自动回退直连, 并通过 TG 通知
"""

import os
import re
import sys
import json
import base64
import shutil
import socket
import subprocess
import tarfile
import urllib.parse

import requests
try:
    # patchright: 修补 CDP 泄漏的 Playwright 分支, 对 Turnstile 的 Verifying 阶段通过率更高
    from patchright.sync_api import sync_playwright
except ImportError:
    from playwright.sync_api import sync_playwright

PANEL_URL = "https://panel.host-ship.com/"
LOGIN_URL = PANEL_URL

SOCKS_PORT = 10808
PROXY_DIR = os.environ.get("PROXY_DIR", "sing-box-bin")
SINGBOX_VERSION = "1.14.3"
SINGBOX_URL = (f"https://github.com/SagerNet/sing-box/releases/download/"
               f"v{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION}-linux-amd64.tar.gz")

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
    # 不再保存整页 HTML: 其中含已填账号密码的明文表单值, 随 artifact 上传会泄漏
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
    """把 vless/vmess/hy2/trojan/ss 分享链接解析成 sing-box outbound dict."""
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()

    if scheme == "vmess":
        data = json.loads(base64.b64decode(_b64pad(link[8:])).decode("utf-8", "ignore"))
        out = {
            "type": "vmess", "tag": "proxy",
            "server": data["add"], "server_port": int(data["port"]),
            "uuid": data["id"], "alter_id": int(data.get("aid") or 0),
            "security": data.get("scy") or "auto",
        }
        net = data.get("net", "tcp")
        if net == "ws":
            ws = {"type": "ws", "path": data.get("path", "/")}
            if data.get("host"):
                ws["headers"] = {"Host": data["host"]}
            out["transport"] = ws
        if str(data.get("tls")) in ("tls", "True", "true"):
            out["tls"] = {"enabled": True,
                          "server_name": data.get("sni") or data.get("host") or data.get("add", ""),
                          "insecure": str(data.get("allowInsecure")) in ("1", "true", "True")}
        return out

    if scheme in ("vless", "trojan", "hysteria2", "hy2"):
        u = urllib.parse.urlparse(link)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        host = u.hostname
        port = u.port or 443
        net = q.get("type", "tcp")
        security = q.get("security", "tls" if scheme in ("trojan", "hysteria2", "hy2") else "none")

        tls = None
        if security in ("tls", "reality") or scheme in ("trojan", "hysteria2", "hy2"):
            tls = {"enabled": True,
                   "server_name": q.get("sni") or q.get("peer") or host,
                   "insecure": q.get("allowInsecure") == "1" or q.get("insecure") == "1"}
            fp = q.get("fp") or q.get("fingerprint")
            if fp:
                tls["utls"] = {"enabled": True, "fingerprint": fp}
            if security == "reality":
                tls["reality"] = {"enabled": True,
                                  "public_key": q.get("pbk", ""),
                                  "short_id": q.get("sid", "")}
                if "utls" not in tls:
                    tls["utls"] = {"enabled": True, "fingerprint": "chrome"}

        transport = None
        if net == "ws":
            transport = {"type": "ws", "path": q.get("path", "/")}
            if q.get("host"):
                transport["headers"] = {"Host": q["host"]}
        elif net == "grpc":
            transport = {"type": "grpc", "service_name": q.get("serviceName", "")}

        if scheme == "vless":
            out = {"type": "vless", "tag": "proxy", "server": host, "server_port": port,
                   "uuid": urllib.parse.unquote(u.username or "")}
            if q.get("flow"):
                out["flow"] = q["flow"]
        elif scheme == "trojan":
            out = {"type": "trojan", "tag": "proxy", "server": host, "server_port": port,
                   "password": urllib.parse.unquote(u.username or "")}
        else:  # hysteria2 / hy2
            out = {"type": "hysteria2", "tag": "proxy", "server": host, "server_port": port,
                   "password": urllib.parse.unquote(u.username or "")}
            if q.get("obfs") == "salamander" and q.get("obfs-password"):
                out["obfs"] = {"type": "salamander", "password": q["obfs-password"]}
        if transport:
            out["transport"] = transport
        if tls:
            out["tls"] = tls
        return out

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
            "type": "shadowsocks", "tag": "proxy",
            "server": host, "server_port": int(port),
            "method": method, "password": password,
        }

    raise ValueError(f"不支持的节点协议: {scheme}")


def build_proxy_config(outbound):
    return {
        "log": {"level": "warn"},
        "inbounds": [{
            "type": "mixed", "tag": "in",
            "listen": "127.0.0.1", "listen_port": SOCKS_PORT,
        }],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [{"ip_is_private": True, "outbound": "direct"}],
            "final": outbound.get("tag", "proxy"),
        },
    }


def download_singbox():
    """下载(或复用已缓存的) sing-box 二进制, 返回可执行路径."""
    exe = os.path.join(PROXY_DIR, "sing-box")
    if os.path.exists(exe):
        log("使用已缓存的 sing-box")
        return exe
    log("下载 sing-box ...")
    os.makedirs(PROXY_DIR, exist_ok=True)
    tpath = os.path.join(PROXY_DIR, "sing-box.tar.gz")
    with requests.get(SINGBOX_URL, timeout=180, stream=True) as r:
        r.raise_for_status()
        with open(tpath, "wb") as f:
            for chunk in r.iter_content(1 << 16):
                f.write(chunk)
    found = False
    with tarfile.open(tpath) as t:
        for m in t.getmembers():
            if m.name.endswith("/sing-box") and m.isfile():
                with open(exe, "wb") as f:
                    shutil.copyfileobj(t.extractfile(m), f)
                found = True
                break
    os.remove(tpath)
    if not found:
        raise RuntimeError("sing-box 压缩包里没找到二进制")
    os.chmod(exe, 0o755)
    return exe


def start_proxy(link):
    """启动 sing-box socks5 代理, 返回 (process, proxy_url)."""
    outbound = parse_node_link(link)
    os.makedirs(PROXY_DIR, exist_ok=True)
    cfg_path = os.path.join(PROXY_DIR, "config.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(build_proxy_config(outbound), f, ensure_ascii=False)

    exe = download_singbox()
    proc = subprocess.Popen(
        [exe, "run", "-c", cfg_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    proxy_url = f"socks5://127.0.0.1:{SOCKS_PORT}"

    # 等待 socks5 端口就绪
    for _ in range(40):
        if proc.poll() is not None:
            out = proc.stdout.read().decode("utf-8", "ignore")[:500] if proc.stdout else ""
            raise RuntimeError(f"sing-box 启动失败: {out}")
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

    # 验证过程可能清掉已填内容, 提交前补填一次
    try:
        _u = page.get_by_placeholder("Username or Email").first
        _p = page.get_by_placeholder("Password").first
        if (_u.input_value() or "") == "":
            _u.fill(username)
        if (_p.input_value() or "") == "":
            _p.fill(password)
    except Exception:
        pass
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
    return page.locator('iframe[src*="challenges.cloudflare.com"]')


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
    # 方式1: 进 iframe 点内部复选框
    try:
        tf = page.frame_locator('iframe[src*="challenges.cloudflare.com"]').first
        tf.locator("input[type='checkbox']").click(timeout=4000)
        return True
    except Exception:
        pass
    # 方式2: 经 hidden input 定位 widget 容器盒, 点击其左侧复选框位置
    # (截图实证: widget 是 "Verify you are human" 横盒, 复选框在盒子左端)
    try:
        box = page.evaluate(
            """() => {
                const el = document.querySelector(
                    'input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"]');
                if (!el) return null;
                let n = el;
                for (let i = 0; i < 8 && n; i++) {
                    n = n.parentElement;
                    if (!n) break;
                    const r = n.getBoundingClientRect();
                    if (r.width >= 200 && r.height >= 40 && r.height <= 140) {
                        return {x: r.x, y: r.y, width: r.width, height: r.height};
                    }
                }
                return null;
            }""")
        if box:
            x = box["x"] + 26
            y = box["y"] + box["height"] / 2
            page.mouse.move(x - 40, y - 12)
            page.wait_for_timeout(350)
            page.mouse.move(x, y)
            page.wait_for_timeout(450)
            page.mouse.click(x, y)
            page.wait_for_timeout(600)
            return True
    except Exception as e:
        warn(f"定位验证盒失败: {e}")
    # 方式3: iframe 几何位置左端
    try:
        box = turnstile_frames(page).first.bounding_box()
        if box:
            page.mouse.click(box["x"] + 26, box["y"] + box["height"] / 2)
            return True
    except Exception:
        pass
    # 方式4: 已知容器类名兜底(左中部)
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


def _click_security_check_button(page):
    """点击 'Complete the security check' 按钮以触发 Turnstile 执行(本站为点击触发型)."""
    try:
        btn = page.locator('button:has-text("Complete the security check")').first
        if btn.count() == 0 or not btn.is_visible() or btn.is_disabled():
            return False
        box = btn.bounding_box()
        if box:
            page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
            page.wait_for_timeout(600)
        btn.click(timeout=5000)
        log("已点击 Complete the security check 按钮, 等待验证执行")
        return True
    except Exception as e:
        warn(f"点击安全检查按钮失败: {e}")
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
        # 2) 冷却几秒后: 先点 "Complete the security check" 按钮触发验证执行,
        #    再兜底点复选框
        page.wait_for_timeout(4000)
        if _click_security_check_button(page):
            for _ in range(20):
                token = turnstile_token(page)
                if token != "":
                    log("点击安全检查按钮后人机验证通过")
                    return True
                try:
                    submit = page.locator('button[type="submit"]').first
                    txt = (submit.inner_text() or '').strip()
                    if submit.count() > 0 and txt.lower() != 'complete the security check':
                        log("安全检查按钮文案已变, 视为验证通过")
                        return True
                except Exception:
                    pass
                page.wait_for_timeout(1000)
        _click_turnstile_checkbox(page)
        for _ in range(60):
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
        # 3) 仍失败: 不刷新页面(会清掉已填的账号密码), 用 JS 重置 widget 后继续下一轮
        warn(f"第 {i + 1} 轮验证未通过, 重置验证后重试")
        try:
            page.evaluate("() => { try { window.turnstile && window.turnstile.reset(); } catch (e) {} }")
            page.wait_for_timeout(2000)
        except Exception:
            pass
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
    # 优先用系统自带 Google Chrome(指纹更真实, Turnstile 通过率更高), 失败回退 Chromium
    try:
        return playwright.chromium.launch(channel="chrome", headless=headless, args=args)
    except Exception as e:
        warn(f"系统 Chrome 启动失败, 回退 Chromium: {e}")
        return playwright.chromium.launch(headless=headless, args=args)


def new_page(browser):
    # 不覆盖 UA: 用浏览器自带 UA, 避免 UA 与真实内核版本不一致露馅
    page = browser.new_page()
    page.add_init_script(STEALTH_JS)
    return page


def run(playwright):
    username = os.environ.get("PANEL_USERNAME", "").strip()
    password = os.environ.get("PANEL_PASSWORD", "").strip()
    server_id = os.environ.get("SERVER_ID", "").strip()
    node_link = os.environ.get("NODE_LINK", "").strip()

    if not username or not password:
        err("缺少 PANEL_USERNAME / PANEL_PASSWORD")
        return False
    if not server_id:
        err("缺少 SERVER_ID")
        return False

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
        return True
    except Exception as e:
        err(f"执行失败: {e}")
        save_debug(page, "fatal")
        tg_send_text(f"❌ HostShip 自动续期执行失败:{e}")
        return False
    finally:
        try:
            browser.close()
        except Exception:
            pass
        if proxy_proc:
            proxy_proc.terminate()


with sync_playwright() as playwright:
    sys.exit(0 if run(playwright) else 1)

import os
import re
import requests
from playwright.sync_api import sync_playwright

PANEL_URL = "https://panel.host-ship.com/"
LOGIN_URL = PANEL_URL

LOGGED_IN_MARKERS = [
    'button:has-text("Sign Out")', 'text=Sign Out', 'text=Logout',
    'a[href*="logout"]', 'a[href*="/dashboard"]',
]
RENEW_SUCCESS_MARKERS = [
    "Success", "success", "成功", "续期", "Renewed", "extended", "Extended",
]


def log(msg): print(f"[INFO] {msg}")
def warn(msg): print(f"[WARN] {msg}")
def err(msg): print(f"[ERROR] {msg}")


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
        return path
    except Exception as e:
        warn(f"截图失败: {e}")
        return None


def login(page, username, password):
    log("打开登录页...")
    page.goto(LOGIN_URL, timeout=60000, wait_until="domcontentloaded")
    page.wait_for_timeout(2000)
    try:
        page.get_by_placeholder("Username or Email").first.wait_for(state="visible", timeout=30000)
        page.get_by_placeholder("Password").first.wait_for(state="visible", timeout=30000)
    except Exception:
        save_debug(page, "login_form_not_found")
        raise RuntimeError("未找到登录输入框")
    page.get_by_placeholder("Username or Email").first.fill(username)
    page.get_by_placeholder("Password").first.fill(password)
    sign_in = page.locator('button:has-text("Sign In")')
    if sign_in.count() == 0:
        raise RuntimeError("未找到 Sign In 按钮")
    sign_in.first.click()
    for _ in range(20):
        page.wait_for_timeout(1000)
        if any(page.locator(m).count() > 0 for m in LOGGED_IN_MARKERS):
            log(f"登录成功: {page.url}")
            return
    save_debug(page, "login_failed")
    raise RuntimeError("登录失败")


def get_renewal_days(page):
    try:
        m = re.search(r"RENEWAL\s*(?:IN|:)?\s*(\d+)\s*(?:Day|Days|天)", page.inner_text("body"), re.IGNORECASE)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def renew_server(page, server_id):
    url = f"{PANEL_URL}server/{server_id}"
    log(f"打开详情页: {url}")
    page.goto(url, timeout=60000, wait_until="domcontentloaded")
    page.wait_for_timeout(2500)

    if page.locator('text=The requested resource was not found').count() > 0:
        save_debug(page, "page_404")
        return "404"

    days = get_renewal_days(page)
    left = f"剩余 {days} 天" if days is not None else "有效期未知"

    for text in ["Renew", "Renew Server", "续期", "Renouveler"]:
        btn = page.locator(f'button:has-text("{text}")')
        if btn.count() > 0 and btn.first.is_visible():
            # 新增:按钮禁用 → 跳过,不报错
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


def run(playwright):
    username = os.environ.get("PANEL_USERNAME", "").strip()
    password = os.environ.get("PANEL_PASSWORD", "").strip()
    server_id = os.environ.get("SERVER_ID", "").strip()
    if not username or not password:
        err("缺少 PANEL_USERNAME / PANEL_PASSWORD")
        return
    if not server_id:
        err("缺少 SERVER_ID")
        return

    browser = playwright.chromium.launch(
        headless=True,
        args=["--disable-dev-shm-usage", "--no-sandbox", "--disable-gpu"],
    )
    page = browser.new_page(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    )
    try:
        login(page, username, password)
        result = renew_server(page, server_id)
        if result == "success":
            tg_send_text(f"✅ HostShip 续期成功: {server_id}")
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
        browser.close()


with sync_playwright() as playwright:
    run(playwright)

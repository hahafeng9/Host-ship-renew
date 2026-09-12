import os
import requests
from playwright.sync_api import sync_playwright

PANEL_URL = "https://panel.host-ship.com/"
LOGIN_URL = PANEL_URL
SERVER_LIST_URL = "https://panel.host-ship.com/server"

LOGGED_IN_MARKERS = [
    'button:has-text("Sign Out")',
    'text=Sign Out',
    'text=Logout',
    'a[href*="logout"]',
    'a[href*="/dashboard"]',
]

RENEW_SUCCESS_MARKERS = [
    "Success", "success", "成功", "续期", "Renewed", "extended", "Extended",
]


def log(msg):
    print(f"[INFO] {msg}")


def warn(msg):
    print(f"[WARN] {msg}")


def err(msg):
    print(f"[ERROR] {msg}")


# ---------- Telegram 通知 ----------
def tg_send_text(text):
    token = os.environ.get("TG_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TG_CHAT_ID", "").strip()
    if not token or not chat_id:
        warn("未配置 TG_BOT_TOKEN / TG_CHAT_ID,跳过 Telegram 通知")
        return False
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        r = requests.post(url, json={"chat_id": chat_id, "text": text}, timeout=20)
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
        url = f"https://api.telegram.org/bot{token}/sendPhoto"
        with open(path, "rb") as f:
            r = requests.post(
                url,
                data={"chat_id": chat_id, "caption": caption[:1024]},
                files={"photo": f},
                timeout=30,
            )
        if r.status_code != 200:
            warn(f"TG sendPhoto 失败: {r.status_code} {r.text[:200]}")
            return False
        return True
    except Exception as e:
        warn(f"TG sendPhoto 异常: {e}")
        return False


def save_debug(page, tag):
    try:
        path = f"debug_{tag}.png"
        page.screenshot(path=path, full_page=True)
        log(f"已保存截图 {path}")
        tg_send_photo(path, caption=f"❌ {tag}")
        return path
    except Exception as e:
        warn(f"截图失败: {e}")
        return None


# ---------- 业务逻辑 ----------
def login(page, username, password):
    log("打开登录页...")
    page.goto(LOGIN_URL, timeout=60000, wait_until="domcontentloaded")
    page.wait_for_timeout(2000)

    try:
        page.get_by_placeholder("Username or Email").first.wait_for(state="visible", timeout=30000)
        page.get_by_placeholder("Password").first.wait_for(state="visible", timeout=30000)
    except Exception:
        save_debug(page, "login_form_not_found")
        raise RuntimeError("未找到登录输入框,请看 TG 截图")

    page.get_by_placeholder("Username or Email").first.fill(username)
    page.get_by_placeholder("Password").first.fill(password)
    log("已填入用户名密码")

    sign_in = page.locator('button:has-text("Sign In")')
    if sign_in.count() == 0:
        raise RuntimeError("未找到 Sign In 按钮")
    sign_in.first.click()
    log("已点击 Sign In")

    for _ in range(20):
        page.wait_for_timeout(1000)
        if any(page.locator(m).count() > 0 for m in LOGGED_IN_MARKERS):
            log(f"登录成功,当前 URL: {page.url}")
            return
    save_debug(page, "login_failed")
    raise RuntimeError("登录失败(可能账号密码错误或有验证码),见 TG 截图")


def find_server_links(page):
    log("打开服务器列表页...")
    page.goto(SERVER_LIST_URL, timeout=60000, wait_until="domcontentloaded")
    page.wait_for_timeout(3000)

    candidate_selectors = [
        'a[href*="/server/"]',
        'a[href*="/servers/"]',
        'a[href*="/service/"]',
        'a[href*="/services/"]',
    ]
    hrefs = []
    for sel in candidate_selectors:
        for i in range(page.locator(sel).count()):
            href = page.locator(sel).nth(i).get_attribute("href")
            if href and href not in hrefs:
                hrefs.append(href)
        if hrefs:
            log(f"用选择器 '{sel}' 找到 {len(hrefs)} 个服务器链接")
            return hrefs

    save_debug(page, "no_server_links")
    warn("没找到服务器链接,见 TG 截图")
    return []


def renew_server(page, url):
    full_url = url if url.startswith("http") else f"{PANEL_URL.rstrip('/')}{url}"
    log(f"打开详情页: {full_url}")
    page.goto(full_url, timeout=60000, wait_until="domcontentloaded")
    page.wait_for_timeout(2500)

    for text in ["Renew", "续期", "Renouveler"]:
        btn = page.locator(f'button:has-text("{text}")')
        if btn.count() > 0 and btn.first.is_visible():
            btn.first.click()
            log(f"已点击续期按钮: {text}")
            page.wait_for_timeout(2000)

            for c_text in ["Confirm", "确认", "Yes", "OK"]:
                if page.locator(f'button:has-text("{c_text}")').count() > 0:
                    page.locator(f'button:has-text("{c_text}")').first.click()
                    log(f"已点击确认: {c_text}")
                    page.wait_for_timeout(2000)
                    break

            for _ in range(10):
                page.wait_for_timeout(1000)
                if any(page.locator(f"text={m}").count() > 0 for m in RENEW_SUCCESS_MARKERS):
                    log(f"续期成功: {full_url}")
                    page.screenshot(path="renew_ok.png", full_page=True)
                    return True
            warn(f"点了续期但没看到成功提示, {full_url}")
            save_debug(page, "renew_unknown")
            return False

    warn(f"没找到续期按钮, {full_url}")
    return False


def run(playwright):
    username = os.environ.get("PANEL_USERNAME", "").strip()
    password = os.environ.get("PANEL_PASSWORD", "").strip()
    if not username or not password:
        err("缺少 PANEL_USERNAME / PANEL_PASSWORD")
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
        hrefs = find_server_links(page)
        if not hrefs:
            err("没有找到任何服务器,流程结束")
            tg_send_text("⚠️ HostShip:未找到任何服务器链接")
            return

        ok = 0
        for idx, href in enumerate(hrefs, 1):
            log(f"--- {idx}/{len(hrefs)} ---")
            try:
                if renew_server(page, href):
                    ok += 1
            except Exception as e:
                warn(f"处理 {href} 出错: {e}")
        log(f"全部完成,成功 {ok}/{len(hrefs)}")

        # 成功/部分成功总结(带成功截图)
        summary = f"✅ HostShip 续期完成:{ok}/{len(hrefs)} 成功"
        tg_send_text(summary)
        if ok > 0 and os.path.exists("renew_ok.png"):
            tg_send_photo("renew_ok.png", caption=summary)

    except Exception as e:
        err(f"执行失败: {e}")
        save_debug(page, "fatal")
        tg_send_text(f"❌ HostShip 自动续期执行失败:{e}")
    finally:
        browser.close()


with sync_playwright() as playwright:
    run(playwright)

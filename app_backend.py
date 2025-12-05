from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import re
from threading import Lock
import requests
import hashlib
import os
import sys
import time
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__)
CORS(app)

FORBIDDEN_HOSTS = ["melliun.org", "nejatngo.org", "dw.com", "hammihanonline.ir"]
keyword_lock = Lock()
image_hash_lock = Lock()

# 🚨 شبیه سازی دیتابیس
CONTENT_HISTORY = {}
CONTENT_HISTORY_LOCK = Lock()
FORBIDDEN_IMAGE_HASHES = set()

# 🚨 سیستم لاگ‌گیری سروری
LOG_DATA = {
    'blocked_requests': [],  # درخواست‌های بلاک شده
    'analyses': [],  # تحلیل‌های انجام شده
    'users': set()  # IP کاربران
}
LOG_LOCK = Lock()
MAX_LOGS = 1000

# تنظیمات
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; Content-Guard-Bot/1.0;)'
}
DOWNLOAD_TIMEOUT = 3

SENSITIVE_KEYWORDS = {
    r'(?:\s|^)شورش', r'(?:\s|^)تحریم', r'(?:\s|^)بحران', r'(?:\s|^)سقوط',
    r'(?:\s|^)ضدنظام', r'(?:\s|^)اعتراض', r'(?:\s|^)برانداز',
    r'(?:\s|^)قیام', r'(?:\s|^)آزادی', r'(?:\s|^)رهبر', r'(?:\s|^)خامنه‌ای',
    r'(?:\s|^)انقلاب', r'(?:\s|^)سپاه', r'(?:\s|^)بسیج', r'(?:\s|^)گشت\sارشاد',
    r'(?:\s|^)سرکوب', r'(?:\s|^)فتنه', r'(?:\s|^)رژیم', r'(?:\s|^)جمهوری',
    r'(?:\s|^)اعدام', r'(?:\s|^)نظام', r'(?:\s|^)ولایت\sفقیه', r'(?:\s|^)ملا',
    r'(?:\s|^)قوه\sقضاییه', r'(?:\s|^)زندانی\sسیاسی', r'(?:\s|^)دیکتاتور'
}


# ========== سیستم لاگ‌گیری سروری ==========
def get_client_ip():
    """دریافت IP کاربر"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr


def log_blocked_request(ip, url, action, reason, content_preview=""):
    """ثبت درخواست بلاک شده"""
    with LOG_LOCK:
        LOG_DATA['users'].add(ip)

        log_entry = {
            'id': f"{int(time.time())}_{len(LOG_DATA['blocked_requests'])}",
            'timestamp': time.time(),
            'datetime': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ip': ip,
            'url': url,
            'action': action,
            'reason': reason,
            'content_preview': content_preview[:200] if content_preview else "",
            'user_agent': request.headers.get('User-Agent', 'Unknown')
        }

        LOG_DATA['blocked_requests'].append(log_entry)

        # محدود کردن تعداد لاگ‌ها
        if len(LOG_DATA['blocked_requests']) > MAX_LOGS:
            LOG_DATA['blocked_requests'] = LOG_DATA['blocked_requests'][-MAX_LOGS:]

        return log_entry


def log_analysis(ip, content_data, result):
    """ثبت تحلیل انجام شده"""
    with LOG_LOCK:
        log_entry = {
            'timestamp': time.time(),
            'datetime': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ip': ip,
            'text_length': len(content_data.get('text', '')),
            'links_count': len(content_data.get('links', [])),
            'images_count': len(content_data.get('imageSources', [])),
            'result_action': result.get('action', 'UNKNOWN'),
            'result_reason': result.get('reason', ''),
            'has_forbidden_links': any(
                any(host in link for host in FORBIDDEN_HOSTS)
                for link in content_data.get('links', [])
            ),
            'has_forbidden_images': any(
                any(host in img for host in FORBIDDEN_HOSTS)
                for img in content_data.get('imageSources', [])
            )
        }

        LOG_DATA['analyses'].append(log_entry)

        if len(LOG_DATA['analyses']) > MAX_LOGS:
            LOG_DATA['analyses'] = LOG_DATA['analyses'][-MAX_LOGS:]

        return log_entry


def get_logs_stats():
    """دریافت آمار لاگ‌ها"""
    with LOG_LOCK:
        now = time.time()
        last_24h = now - 86400

        recent_logs = [log for log in LOG_DATA['blocked_requests']
                       if log['timestamp'] > last_24h]

        stats = {
            'total_blocks': len(LOG_DATA['blocked_requests']),
            'total_analyses': len(LOG_DATA['analyses']),
            'unique_users': len(LOG_DATA['users']),
            'blocks_24h': len(recent_logs),
            'actions_distribution': defaultdict(int),
            'top_domains': defaultdict(int)
        }

        for log in LOG_DATA['blocked_requests']:
            stats['actions_distribution'][log['action']] += 1

            # استخراج دامنه از URL
            try:
                domain = log['url'].split('//')[-1].split('/')[0]
                stats['top_domains'][domain] += 1
            except:
                pass

        return stats


# ========== توابع اصلی بدون تغییر ==========
def get_image_hash(url):
    try:
        if not url.startswith('http'):
            return None

        response = requests.get(url, headers=REQUEST_HEADERS, timeout=DOWNLOAD_TIMEOUT, stream=True)
        response.raise_for_status()

        content_type = response.headers.get('Content-Type', '')
        if 'image' not in content_type:
            return None

        sha256_hash = hashlib.sha256()
        for chunk in response.iter_content(chunk_size=4096):
            sha256_hash.update(chunk)

        return sha256_hash.hexdigest()

    except requests.exceptions.RequestException:
        return None
    except Exception:
        return None


def normalize_text(text):
    text = str(text).lower()
    text = text.replace('ي', 'ی').replace('ك', 'ک')
    text = re.sub(r'[^\w\s]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def check_keyword_robust(article_text):
    normalized_text = normalize_text(article_text)

    with keyword_lock:
        for pattern in SENSITIVE_KEYWORDS:
            if re.search(pattern, normalized_text):
                return True
    return False


def simulate_learning(content_data):
    article_text = content_data.get('text', '')
    image_sources = content_data.get('imageSources', [])

    normalized_text = normalize_text(article_text)
    content_hash = hashlib.md5(normalized_text[:500].encode('utf-8')).hexdigest()

    with CONTENT_HISTORY_LOCK:
        if content_hash in CONTENT_HISTORY:
            return 0, 0
        CONTENT_HISTORY[content_hash] = True

    all_words = set(re.findall(r'[\u0600-\u06FF\u0750-\u077F]{4,}', normalized_text))
    newly_added_keywords = 0
    with keyword_lock:
        for word in all_words:
            safe_term = r'(?:\s|^)' + re.escape(word)
            if safe_term not in SENSITIVE_KEYWORDS:
                SENSITIVE_KEYWORDS.add(safe_term)
                newly_added_keywords += 1

    newly_added_hashes = 0
    with image_hash_lock:
        for src in image_sources:
            if any(host in src for host in FORBIDDEN_HOSTS):
                img_hash = get_image_hash(src)
                if img_hash and img_hash not in FORBIDDEN_IMAGE_HASHES:
                    FORBIDDEN_IMAGE_HASHES.add(img_hash)
                    newly_added_hashes += 1

    return newly_added_keywords, newly_added_hashes


def check_nested_api_logic(content_data):
    article_text = content_data.get('text', '')
    links_to_check = content_data.get('links', [])
    image_sources = content_data.get('imageSources', [])

    has_forbidden_source = any(any(host in src for host in FORBIDDEN_HOSTS) for src in image_sources) or any(
        any(host in link for host in FORBIDDEN_HOSTS) for link in links_to_check)

    if has_forbidden_source:
        new_k, new_i = simulate_learning(content_data)
        if new_k > 0 or new_i > 0:
            print(f"AUTOMATIC LEARNING: Added {new_k} new keywords and {new_i} new image hashes.")

    with image_hash_lock:
        for src in image_sources:
            current_hash = get_image_hash(src)
            if current_hash and current_hash in FORBIDDEN_IMAGE_HASHES:
                return {
                    "action": "FILTER_HARD",
                    "reason": "HIGH_PRIORITY: Known Forbidden Image Hash Detected"
                }

    if any(any(host in src for host in FORBIDDEN_HOSTS) for src in image_sources):
        return {
            "action": "FILTER_HARD",
            "reason": "HIGH_PRIORITY: Image Source from Forbidden Host Detected (URL Match)"
        }

    has_forbidden_link = any(any(host in link for host in FORBIDDEN_HOSTS) for link in links_to_check)

    if has_forbidden_link:
        if len(article_text) > 100 and check_keyword_robust(article_text):
            return {
                "action": "FILTER_HARD",
                "reason": "Nested Logic: Forbidden Link + Sensitive Topic Match (Robust)"
            }
        return {
            "action": "FILTER_HARD",
            "reason": "HIGH_PRIORITY: Forbidden Link Detected"
        }

    if check_keyword_robust(article_text):
        return {"action": "FILTER_LIGHT", "reason": "Generic Sensitive Topic Found (Robust)"}

    return {"action": "ALLOW", "reason": "Content is clear."}


# ========== Endpoints جدید برای لاگ‌گیری ==========
@app.route('/', methods=['GET'])
def home():
    with image_hash_lock:
        total_images = len(FORBIDDEN_IMAGE_HASHES)

    stats = get_logs_stats()

    return f"""
    <html>
        <head>
            <title>Iran Blocker API</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{
                    font-family: Tahoma, Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: #f5f5f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 0 20px rgba(0,0,0,0.1);
                }}
                h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                h2 {{ color: #34495e; }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 15px;
                    margin: 20px 0;
                }}
                .stat-box {{
                    background: #ecf0f1;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                }}
                .stat-number {{
                    font-size: 32px;
                    font-weight: bold;
                    color: #2c3e50;
                }}
                .stat-label {{
                    color: #7f8c8d;
                    font-size: 14px;
                }}
                .test-box {{
                    background: #fff3cd;
                    border-left: 4px solid #ffc107;
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 5px;
                }}
                .log-controls {{
                    background: #e8f4fc;
                    padding: 20px;
                    border-radius: 8px;
                    margin: 20px 0;
                }}
                .btn {{
                    display: inline-block;
                    padding: 10px 20px;
                    margin: 5px;
                    background: #3498db;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    border: none;
                    cursor: pointer;
                    font-size: 14px;
                }}
                .btn-danger {{ background: #e74c3c; }}
                .btn-success {{ background: #27ae60; }}
                .btn:hover {{ opacity: 0.9; }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                th {{ background: #34495e; color: white; }}
                tr:hover {{ background: #f5f5f5; }}
                .log-entry {{ font-family: monospace; font-size: 12px; }}
                .timestamp {{ color: #7f8c8d; font-size: 11px; }}
                .action-filter_hard {{ color: #e74c3c; font-weight: bold; }}
                .action-filter_light {{ color: #f39c12; }}
                .action-allow {{ color: #27ae60; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🚫 Iran Blocker API</h1>

                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="stat-number">{stats['total_blocks']}</div>
                        <div class="stat-label">کل بلاک‌ها</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{stats['blocks_24h']}</div>
                        <div class="stat-label">بلاک‌های 24h</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{stats['unique_users']}</div>
                        <div class="stat-label">کاربران منحصر</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(SENSITIVE_KEYWORDS)}</div>
                        <div class="stat-label">کلمات کلیدی</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{total_images}</div>
                        <div class="stat-label">تصاویر ممنوعه</div>
                    </div>
                </div>

                <div class="log-controls">
                    <h3>📊 مدیریت لاگ‌ها</h3>
                    <button class="btn btn-success" onclick="refreshLogs()">🔄 بروزرسانی لاگ‌ها</button>
                    <button class="btn" onclick="downloadLogs()">📥 دانلود لاگ‌ها (JSON)</button>
                    <button class="btn btn-danger" onclick="clearLogs()">🧹 حذف همه لاگ‌ها</button>
                    <a class="btn" href="/logs_view">📋 مشاهده کامل لاگ‌ها</a>
                </div>

                <div class="test-box">
                    <h3>🔍 تست عملکرد افزونه</h3>
                    <p>برای تست، روی لینک‌های زیر کلیک کنید:</p>
                    <p>
                        <a href="https://www.nejatngo.org" target="_blank" class="btn">www.nejatngo.org</a>
                        <a href="https://www.hammihanonline.ir" target="_blank" class="btn">www.hammihanonline.ir</a>
                        <a href="https://www.dw.com" target="_blank" class="btn">www.dw.com</a>
                        <a href="https://www.melliun.org" target="_blank" class="btn">www.melliun.org</a>
                    </p>
                    <p><small>⚠️ این سایت‌ها باید توسط افزونه مسدود شوند.</small></p>
                </div>

                <h3>📈 آخرین بلاک‌ها</h3>
                <div id="recent-logs">
                    <table>
                        <thead>
                            <tr>
                                <th>زمان</th>
                                <th>IP</th>
                                <th>عملیات</th>
                                <th>دلیل</th>
                                <th>URL</th>
                            </tr>
                        </thead>
                        <tbody id="logs-table-body">
                            <!-- لاگ‌ها با JavaScript بارگذاری می‌شوند -->
                        </tbody>
                    </table>
                </div>

                <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 14px;">
                    <p>📅 آخرین بروزرسانی: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p>🌐 سرور: https://iran-blockers-o21z.onrender.com</p>
                    <p>📊 Endpoint لاگ‌ها: <code>/get_logs</code>, <code>/download_logs</code>, <code>/clear_logs</code></p>
                </div>
            </div>

            <script>
                // بارگذاری اولیه لاگ‌ها
                loadRecentLogs();

                async function loadRecentLogs() {{
                    try {{
                        const response = await fetch('/get_recent_logs');
                        const data = await response.json();

                        const tbody = document.getElementById('logs-table-body');
                        tbody.innerHTML = '';

                        data.logs.forEach(log => {{
                            const row = document.createElement('tr');
                            row.className = 'log-entry';

                            const actionClass = 'action-' + log.action.toLowerCase().replace(' ', '_');

                            row.innerHTML = `
                                <td class="timestamp">${{log.datetime}}</td>
                                <td><small>${{log.ip}}</small></td>
                                <td><span class="${{actionClass}}">${{log.action}}</span></td>
                                <td>${{log.reason}}</td>
                                <td><small>${{log.url.substring(0, 50)}}...</small></td>
                            `;

                            tbody.appendChild(row);
                        }});
                    }} catch (error) {{
                        console.error('خطا در بارگذاری لاگ‌ها:', error);
                    }}
                }}

                async function refreshLogs() {{
                    await loadRecentLogs();
                    alert('✅ لاگ‌ها بروزرسانی شدند');
                }}

                async function downloadLogs() {{
                    try {{
                        const response = await fetch('/download_logs');
                        const blob = await response.blob();
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = 'iran_blocker_logs_' + Date.now() + '.json';
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        window.URL.revokeObjectURL(url);
                    }} catch (error) {{
                        alert('❌ خطا در دانلود لاگ‌ها');
                        console.error(error);
                    }}
                }}

                async function clearLogs() {{
                    if (confirm('آیا مطمئن هستید که می‌خواهید همه لاگ‌ها را حذف کنید؟')) {{
                        try {{
                            const response = await fetch('/clear_logs', {{ method: 'POST' }});
                            const result = await response.json();

                            if (result.success) {{
                                alert('✅ همه لاگ‌ها حذف شدند');
                                loadRecentLogs();
                            }} else {{
                                alert('❌ خطا در حذف لاگ‌ها');
                            }}
                        }} catch (error) {{
                            alert('❌ خطا در حذف لاگ‌ها');
                            console.error(error);
                        }}
                    }}
                }}

                // بروزرسانی خودکار هر 30 ثانیه
                setInterval(loadRecentLogs, 30000);
            </script>
        </body>
    </html>
    """, 200


@app.route('/logs_view', methods=['GET'])
def logs_view():
    """صفحه نمایش کامل لاگ‌ها"""
    stats = get_logs_stats()

    with LOG_LOCK:
        all_logs = LOG_DATA['blocked_requests'][-100:]  # 100 تا آخرین

    logs_html = ""
    for log in reversed(all_logs):
        action_class = f"action-{log['action'].lower().replace(' ', '_')}"
        logs_html += f"""
        <tr>
            <td class="timestamp">{log['datetime']}</td>
            <td><small>{log['ip']}</small></td>
            <td><span class="{action_class}">{log['action']}</span></td>
            <td>{log['reason']}</td>
            <td><small>{log['url'][:60]}...</small></td>
            <td><small>{log['user_agent'][:40]}...</small></td>
        </tr>
        """

    return f"""
    <html>
        <head>
            <title>Iran Blocker - لاگ کامل</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Tahoma; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }}
                h1 {{ color: #2c3e50; }}
                .controls {{ margin: 20px 0; padding: 15px; background: #e8f4fc; border-radius: 5px; }}
                .btn {{ padding: 10px 15px; margin: 5px; background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer; }}
                .btn-danger {{ background: #e74c3c; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
                th {{ background: #34495e; color: white; }}
                .timestamp {{ font-size: 12px; color: #666; }}
                .action-filter_hard {{ color: #e74c3c; font-weight: bold; }}
                .action-filter_light {{ color: #f39c12; }}
                .action-allow {{ color: #27ae60; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📋 لاگ کامل سیستم</h1>
                <div class="controls">
                    <a href="/" class="btn">🏠 بازگشت به صفحه اصلی</a>
                    <button onclick="window.location.reload()" class="btn">🔄 بروزرسانی</button>
                    <button onclick="downloadAllLogs()" class="btn">📥 دانلود همه لاگ‌ها</button>
                    <span style="margin-left: 20px; color: #666;">
                        نمایش {len(all_logs)} لاگ از {stats['total_blocks']} لاگ
                    </span>
                </div>

                <table>
                    <thead>
                        <tr>
                            <th>زمان</th>
                            <th>IP</th>
                            <th>عملیات</th>
                            <th>دلیل</th>
                            <th>URL</th>
                            <th>User Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                        {logs_html}
                    </tbody>
                </table>
            </div>

            <script>
                async function downloadAllLogs() {{
                    const response = await fetch('/download_logs');
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'iran_blocker_full_logs_' + Date.now() + '.json';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                }}
            </script>
        </body>
    </html>
    """, 200


@app.route('/analyze_content_api', methods=['POST'])
def analyze_content_api():
    """Endpoint اصلی تحلیل"""
    ip = get_client_ip()
    data = request.get_json()

    if not data or 'content' not in data:
        return jsonify({"error": "No content provided."}), 400

    content_data = data['content']
    result = check_nested_api_logic(content_data)

    # ثبت لاگ در سیستم سروری
    log_blocked_request(
        ip=ip,
        url=request.url,
        action=result['action'],
        reason=result['reason'],
        content_preview=content_data.get('text', '')[:200]
    )

    log_analysis(ip, content_data, result)

    return jsonify(result)


@app.route('/get_recent_logs', methods=['GET'])
def get_recent_logs():
    """دریافت 20 لاگ اخیر"""
    with LOG_LOCK:
        recent_logs = LOG_DATA['blocked_requests'][-20:]

    return jsonify({
        'success': True,
        'count': len(recent_logs),
        'logs': recent_logs
    })


@app.route('/get_logs', methods=['GET'])
def get_logs():
    """دریافت همه لاگ‌ها"""
    with LOG_LOCK:
        return jsonify({
            'success': True,
            'stats': get_logs_stats(),
            'blocked_requests': LOG_DATA['blocked_requests'],
            'analyses': LOG_DATA['analyses'],
            'unique_users': list(LOG_DATA['users']),
            'total_logs': len(LOG_DATA['blocked_requests']) + len(LOG_DATA['analyses'])
        })


@app.route('/download_logs', methods=['GET'])
def download_logs():
    """دانلود لاگ‌ها به صورت JSON"""
    with LOG_LOCK:
        logs_data = {
            'export_time': datetime.now().isoformat(),
            'stats': get_logs_stats(),
            'blocked_requests': LOG_DATA['blocked_requests'],
            'analyses': LOG_DATA['analyses'],
            'system_info': {
                'keywords_count': len(SENSITIVE_KEYWORDS),
                'image_hashes_count': len(FORBIDDEN_IMAGE_HASHES),
                'forbidden_hosts': FORBIDDEN_HOSTS
            }
        }

    response = jsonify(logs_data)
    response.headers.set('Content-Type', 'application/json')
    response.headers.set('Content-Disposition', 'attachment', filename=f'iran_blocker_logs_{int(time.time())}.json')
    return response


@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    """حذف همه لاگ‌ها"""
    with LOG_LOCK:
        LOG_DATA['blocked_requests'] = []
        LOG_DATA['analyses'] = []
        LOG_DATA['users'] = set()

    return jsonify({
        'success': True,
        'message': 'All logs cleared',
        'timestamp': time.time()
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5050))
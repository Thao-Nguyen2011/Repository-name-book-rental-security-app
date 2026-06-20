from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]

SQL_PAYLOADS = ["'", "' OR '1'='1", '" OR "1"="1', "admin'--"]
XSS_PAYLOAD = "<script>alert('xss')</script>"
SQL_ERRORS = [
    "sql syntax",
    "sqlite",
    "mysql",
    "postgresql",
    "syntax error",
    "database error",
    "unclosed quotation",
    "you have an error in your sql",
]

ADMIN_PATHS = ["/admin", "/admin/backup-db", "/scan-history", "/security-scan"]


def add_result(results, name, status, level, detail, solution, module="Tổng quát"):
    results.append({
        "module": module,
        "name": name,
        "status": status,
        "level": level,
        "detail": detail,
        "solution": solution,
    })


def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return None
    parsed = urlparse(url)
    if not parsed.netloc:
        return None
    return url


def origin_url(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def build_payload_url(url, key, value):
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[key] = value
    return urlunparse(parsed._replace(query=urlencode(params)))


def detect_sql_error(text):
    lowered = text.lower()
    return any(error in lowered for error in SQL_ERRORS)


def scan_https(url, results):
    if url.startswith("https://"):
        add_result(
            results,
            "Kiểm tra HTTPS",
            "An toàn",
            "Thấp",
            "Website đang sử dụng HTTPS.",
            "Tiếp tục duy trì chứng chỉ SSL/TLS hợp lệ khi triển khai thực tế.",
            "Giao thức",
        )
    else:
        add_result(
            results,
            "Kiểm tra HTTPS",
            "Có vấn đề",
            "Cao",
            "Website đang sử dụng HTTP, dữ liệu truyền tải có thể bị nghe lén trong môi trường thật.",
            "Khi triển khai production cần cấu hình SSL/TLS và chuyển website sang HTTPS.",
            "Giao thức",
        )


def scan_security_headers(response, results):
    missing_headers = [header for header in SECURITY_HEADERS if header not in response.headers]
    if missing_headers:
        add_result(
            results,
            "Kiểm tra Security Headers",
            "Thiếu cấu hình",
            "Trung bình",
            "Website thiếu header bảo mật: " + ", ".join(missing_headers),
            "Bổ sung CSP, X-Frame-Options, X-Content-Type-Options, HSTS và Referrer-Policy.",
            "Header bảo mật",
        )
    else:
        add_result(
            results,
            "Kiểm tra Security Headers",
            "An toàn",
            "Thấp",
            "Website có đầy đủ header bảo mật cơ bản.",
            "Tiếp tục duy trì cấu hình bảo mật khi triển khai thực tế.",
            "Header bảo mật",
        )


def scan_cookie_flags(response, results):
    set_cookie = response.headers.get("Set-Cookie", "")
    if not set_cookie:
        add_result(
            results,
            "Kiểm tra Cookie bảo mật",
            "Không phát hiện cookie",
            "Thấp",
            "Trang được kiểm tra chưa trả về Set-Cookie trong phản hồi hiện tại.",
            "Kiểm tra thêm trang đăng nhập hoặc trang sau khi xác thực để đánh giá session cookie.",
            "Session/Cookie",
        )
        return

    missing = []
    cookie_lower = set_cookie.lower()
    if "httponly" not in cookie_lower:
        missing.append("HttpOnly")
    if "samesite" not in cookie_lower:
        missing.append("SameSite")
    if response.url.startswith("https://") and "secure" not in cookie_lower:
        missing.append("Secure")

    if missing:
        add_result(
            results,
            "Kiểm tra Cookie bảo mật",
            "Cần bổ sung",
            "Trung bình",
            "Cookie còn thiếu thuộc tính bảo vệ: " + ", ".join(missing),
            "Cấu hình session cookie có HttpOnly, SameSite và Secure khi chạy HTTPS.",
            "Session/Cookie",
        )
    else:
        add_result(
            results,
            "Kiểm tra Cookie bảo mật",
            "Tốt",
            "Thấp",
            "Cookie phản hồi đã có các thuộc tính bảo vệ cơ bản.",
            "Tiếp tục kiểm thử cookie sau đăng nhập và khi triển khai production.",
            "Session/Cookie",
        )


def scan_forms(base_url, soup, results):
    forms = soup.find_all("form")
    if not forms:
        add_result(
            results,
            "Kiểm tra Form nhập liệu",
            "Không tìm thấy",
            "Thấp",
            "Không tìm thấy form nhập liệu trên trang này.",
            "Nếu website có form ở trang khác, hãy nhập đúng URL trang đó để kiểm tra.",
            "Form",
        )
        return

    form_descriptions = []
    post_forms_without_csrf = []
    upload_forms = []
    risky_uploads = []

    for index, form in enumerate(forms, 1):
        method = form.get("method", "GET").upper()
        action = urljoin(base_url, form.get("action") or base_url)
        inputs = form.find_all(["input", "textarea", "select"])
        names = [inp.get("name") for inp in inputs if inp.get("name")]
        form_descriptions.append(
            f"Form {index}: method={method}, action={action}, trường={', '.join(names) if names else 'không có name'}"
        )

        has_csrf = any(
            "csrf" in (inp.get("name", "") + inp.get("id", "")).lower()
            or "token" in (inp.get("name", "") + inp.get("id", "")).lower()
            for inp in inputs
        )
        if method == "POST" and not has_csrf:
            post_forms_without_csrf.append(f"Form {index}")

        file_inputs = [inp for inp in form.find_all("input") if inp.get("type", "").lower() == "file"]
        if file_inputs:
            upload_forms.append(f"Form {index}")
            for inp in file_inputs:
                accept = (inp.get("accept") or "").strip().lower()
                if not accept or accept in {"*", "*/*"}:
                    risky_uploads.append(f"Form {index} chưa giới hạn định dạng file")

    add_result(
        results,
        "Kiểm tra Form nhập liệu",
        "Có form",
        "Thấp",
        f"Phát hiện {len(forms)} form nhập liệu. " + " | ".join(form_descriptions[:4]),
        "Cần kiểm tra validate dữ liệu, CSRF, phân quyền và xử lý lỗi ở từng form quan trọng.",
        "Form",
    )

    if post_forms_without_csrf:
        add_result(
            results,
            "Kiểm tra CSRF token ở form POST",
            "Cần bổ sung",
            "Trung bình",
            "Các form POST chưa thấy token chống CSRF: " + ", ".join(post_forms_without_csrf[:5]),
            "Nên dùng Flask-WTF hoặc tự sinh CSRF token cho form POST quan trọng như đăng nhập, thêm/sửa/xóa dữ liệu.",
            "Form/CSRF",
        )
    else:
        add_result(
            results,
            "Kiểm tra CSRF token ở form POST",
            "Chưa phát hiện vấn đề rõ ràng",
            "Thấp",
            "Không phát hiện form POST thiếu token trong trang hiện tại hoặc trang không có form POST.",
            "Vẫn cần kiểm thử thủ công toàn bộ chức năng cập nhật dữ liệu.",
            "Form/CSRF",
        )

    if upload_forms:
        level = "Trung bình" if risky_uploads else "Thấp"
        status = "Cần kiểm tra" if risky_uploads else "Có giới hạn cơ bản"
        detail = "Phát hiện form upload file: " + ", ".join(upload_forms)
        if risky_uploads:
            detail += ". " + "; ".join(risky_uploads[:3])
        add_result(
            results,
            "Kiểm tra Upload file",
            status,
            level,
            detail,
            "Chỉ cho upload ảnh hợp lệ, đổi tên file bằng secure_filename, lưu ngoài vùng thực thi và kiểm tra MIME/đuôi file.",
            "Upload",
        )

    reflected = False
    for form in forms[:3]:
        method = form.get("method", "GET").upper()
        action = urljoin(base_url, form.get("action") or base_url)
        inputs = [inp.get("name") for inp in form.find_all(["input", "textarea"]) if inp.get("name")]
        if method == "GET" and inputs:
            params = {name: XSS_PAYLOAD for name in inputs[:3]}
            try:
                response = requests.get(action, params=params, timeout=8)
                if XSS_PAYLOAD in response.text:
                    reflected = True
                    break
            except Exception:
                continue

    if reflected:
        add_result(
            results,
            "Kiểm tra XSS tại form GET",
            "Có nguy cơ",
            "Cao",
            "Một form GET phản hồi lại payload script chưa được mã hóa.",
            "Escape dữ liệu khi hiển thị ra HTML và validate dữ liệu nhập từ form.",
            "XSS",
        )
    else:
        add_result(
            results,
            "Kiểm tra XSS tại form GET",
            "Chưa phát hiện",
            "Thấp",
            "Chưa phát hiện XSS phản xạ cơ bản tại các form GET được kiểm thử.",
            "Tiếp tục kiểm tra thủ công với form POST và các trường dữ liệu quan trọng.",
            "XSS",
        )


def scan_query_parameters(url, results):
    found_sql = False
    found_xss = False

    for payload in SQL_PAYLOADS:
        test_url = build_payload_url(url, "test", payload)
        try:
            response = requests.get(test_url, timeout=8)
            if detect_sql_error(response.text):
                found_sql = True
                break
        except Exception:
            continue

    try:
        xss_url = build_payload_url(url, "q", XSS_PAYLOAD)
        response = requests.get(xss_url, timeout=8)
        if XSS_PAYLOAD in response.text:
            found_xss = True
    except Exception:
        pass

    if found_sql:
        add_result(
            results,
            "Kiểm tra SQL Injection qua tham số URL",
            "Có nguy cơ",
            "Cao",
            "Website phản hồi lỗi cơ sở dữ liệu khi truyền payload đặc biệt qua tham số URL.",
            "Dùng prepared statements/ORM an toàn, kiểm soát lỗi và không hiển thị lỗi database ra giao diện.",
            "SQL Injection",
        )
    else:
        add_result(
            results,
            "Kiểm tra SQL Injection qua tham số URL",
            "Chưa phát hiện",
            "Thấp",
            "Chưa phát hiện dấu hiệu SQL Injection cơ bản qua tham số URL.",
            "Vẫn cần kiểm thử thêm ở form đăng nhập, tìm kiếm và các API xử lý dữ liệu.",
            "SQL Injection",
        )

    if found_xss:
        add_result(
            results,
            "Kiểm tra XSS phản xạ qua URL",
            "Có nguy cơ",
            "Cao",
            "Website phản hồi lại đoạn script chưa được xử lý.",
            "Mã hóa dữ liệu đầu ra, lọc dữ liệu đầu vào và cấu hình Content-Security-Policy.",
            "XSS",
        )
    else:
        add_result(
            results,
            "Kiểm tra XSS phản xạ qua URL",
            "Chưa phát hiện",
            "Thấp",
            "Chưa phát hiện dấu hiệu XSS phản xạ cơ bản qua URL.",
            "Nên kiểm tra thêm ở ô tìm kiếm, bình luận, đăng ký và các trường nhập liệu khác.",
            "XSS",
        )


def scan_admin_paths(url, results):
    base = origin_url(url)
    exposed = []
    protected = []
    for path in ADMIN_PATHS:
        target = urljoin(base, path)
        try:
            response = requests.get(target, timeout=8, allow_redirects=True)
        except Exception:
            continue
        body = response.text.lower()
        redirected_to_login = "login" in response.url.lower() or "đăng nhập" in body or "dang nhap" in body
        if response.status_code == 200 and not redirected_to_login:
            exposed.append(path)
        else:
            protected.append(path)

    if exposed:
        add_result(
            results,
            "Kiểm tra truy cập đường dẫn quản trị",
            "Có nguy cơ",
            "Cao",
            "Một số đường dẫn quản trị có thể truy cập khi chưa xác thực: " + ", ".join(exposed),
            "Bắt buộc kiểm tra đăng nhập và vai trò ở mọi route quản trị, không chỉ ẩn menu trên giao diện.",
            "Phân quyền",
        )
    else:
        add_result(
            results,
            "Kiểm tra truy cập đường dẫn quản trị",
            "Được bảo vệ",
            "Thấp",
            "Các đường dẫn quản trị phổ biến chưa cho thấy khả năng truy cập trái phép trong kiểm thử cơ bản.",
            "Tiếp tục rà soát toàn bộ URL quản trị và API bằng decorator phân quyền.",
            "Phân quyền",
        )


def scan_error_disclosure(response, results):
    text = response.text.lower()
    risky_words = ["traceback", "werkzeug debugger", "debugger active", "sqlite error", "sqlalchemy.exc"]
    found = [word for word in risky_words if word in text]
    if found:
        add_result(
            results,
            "Kiểm tra lộ thông tin lỗi hệ thống",
            "Có nguy cơ",
            "Cao",
            "Trang phản hồi có dấu hiệu lộ thông tin lỗi/debug: " + ", ".join(found),
            "Tắt debug khi triển khai, cấu hình trang lỗi chung và ghi log lỗi ở phía server.",
            "Cấu hình lỗi",
        )
    else:
        add_result(
            results,
            "Kiểm tra lộ thông tin lỗi hệ thống",
            "Chưa phát hiện",
            "Thấp",
            "Chưa phát hiện dấu hiệu lộ traceback/debug trong phản hồi hiện tại.",
            "Khi demo có thể bật debug, nhưng khi triển khai thật cần tắt debug=True.",
            "Cấu hình lỗi",
        )


def scan_website(url):
    results = []
    url = normalize_url(url)
    if not url:
        add_result(
            results,
            "Kiểm tra URL",
            "Lỗi",
            "Cao",
            "URL không hợp lệ vì thiếu http:// hoặc https:// hoặc thiếu tên miền.",
            "Nhập đúng định dạng, ví dụ: http://127.0.0.1:5000/login",
            "Tổng quát",
        )
        return results

    scan_https(url, results)

    try:
        response = requests.get(url, timeout=8)
    except Exception:
        add_result(
            results,
            "Kết nối website",
            "Lỗi",
            "Cao",
            "Không thể kết nối tới website.",
            "Kiểm tra lại URL hoặc đảm bảo website đang chạy.",
            "Kết nối",
        )
        return results

    add_result(
        results,
        "Kiểm tra phản hồi HTTP",
        "Đã phản hồi",
        "Thấp" if response.status_code < 400 else "Trung bình",
        f"Website phản hồi mã trạng thái HTTP {response.status_code}, kích thước nội dung khoảng {len(response.text)} ký tự.",
        "Theo dõi mã trạng thái bất thường như 4xx/5xx khi kiểm thử các trang quan trọng.",
        "Kết nối",
    )

    scan_security_headers(response, results)
    scan_cookie_flags(response, results)
    scan_error_disclosure(response, results)

    soup = BeautifulSoup(response.text, "html.parser")
    scan_forms(url, soup, results)
    scan_query_parameters(url, results)
    scan_admin_paths(url, results)

    return results

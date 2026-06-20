from functools import wraps
import json
import os
import sqlite3
from datetime import datetime, timedelta

from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from scanner import scan_website

app = Flask(__name__)
app.secret_key = "book_rental_security_secret_key"

DATABASE = "database.db"
UPLOAD_FOLDER = os.path.join("static", "uploads")
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "svg"}

ROLES = {
    "customer": "Khách hàng",
    "staff": "Nhân viên",
    "admin": "Admin",
}

PERMISSIONS = {
    "manage_books": {"staff", "admin"},
    "manage_rentals": {"staff", "admin"},
    "manage_users": {"admin"},
    "security_scan": {"admin"},
}

RENTAL_STATUS = ["Chờ xác nhận", "Đã xác nhận", "Đã trả", "Đã hủy"]
DEFAULT_RENTAL_DAYS = 7
LATE_FEE_PER_DAY = 3000


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today_text():
    return datetime.now().strftime("%Y-%m-%d")


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def save_cover_image(file_storage):
    if not file_storage or not file_storage.filename:
        return ""
    if not allowed_image(file_storage.filename):
        return ""

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    filename = secure_filename(file_storage.filename)
    unique_name = f"{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{filename}"
    save_path = os.path.join(UPLOAD_FOLDER, unique_name)
    file_storage.save(save_path)
    return "/" + save_path.replace(os.sep, "/")


def create_default_covers():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    cover_data = [
        ("doraemon.svg", "Doraemon", "#38bdf8"),
        ("conan.svg", "Conan", "#6366f1"),
        ("harry-potter.svg", "Harry Potter", "#7c3aed"),
        ("dac-nhan-tam.svg", "Dac Nhan Tam", "#0f766e"),
        ("nha-gia-kim.svg", "Nha Gia Kim", "#f59e0b"),
        ("hoa-vang-co-xanh.svg", "Hoa Vang", "#22c55e"),
        ("default-cover.svg", "Sach Truyen", "#64748b"),
    ]
    for filename, title, color in cover_data:
        path = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.exists(path):
            continue
        svg = f"""<svg xmlns='http://www.w3.org/2000/svg' width='360' height='520' viewBox='0 0 360 520'>
<rect width='360' height='520' rx='28' fill='{color}'/>
<rect x='36' y='52' width='288' height='416' rx='18' fill='rgba(255,255,255,0.18)' stroke='rgba(255,255,255,0.55)' stroke-width='3'/>
<text x='180' y='235' font-family='Arial, sans-serif' font-size='34' font-weight='700' fill='white' text-anchor='middle'>{title}</text>
<text x='180' y='285' font-family='Arial, sans-serif' font-size='22' fill='rgba(255,255,255,0.88)' text-anchor='middle'>Book Rental</text>
<text x='180' y='380' font-family='Arial, sans-serif' font-size='18' fill='rgba(255,255,255,0.75)' text-anchor='middle'>Anh bia demo</text>
</svg>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(svg)


def ensure_column(cur, table, column, definition):
    columns = [row[1] for row in cur.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in columns:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    create_default_covers()
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'customer',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            category TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            description TEXT,
            cover_image TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS rentals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rental_code TEXT,
            user_id INTEGER NOT NULL,
            book_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT,
            due_at TEXT,
            returned_at TEXT,
            late_fee REAL DEFAULT 0,
            note TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(book_id) REFERENCES books(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_code TEXT UNIQUE NOT NULL,
            rental_id INTEGER UNIQUE NOT NULL,
            subtotal REAL DEFAULT 0,
            late_fee REAL DEFAULT 0,
            total_amount REAL DEFAULT 0,
            issued_at TEXT NOT NULL,
            created_by INTEGER,
            note TEXT,
            FOREIGN KEY(rental_id) REFERENCES rentals(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            total INTEGER NOT NULL,
            high_count INTEGER NOT NULL,
            medium_count INTEGER NOT NULL,
            low_count INTEGER NOT NULL,
            risk_score INTEGER DEFAULT 0,
            results_json TEXT NOT NULL,
            created_by INTEGER,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            detail TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    ensure_column(cur, "users", "created_at", "TEXT")
    ensure_column(cur, "users", "last_login", "TEXT")
    ensure_column(cur, "books", "cover_image", "TEXT")
    ensure_column(cur, "rentals", "rental_code", "TEXT")
    ensure_column(cur, "rentals", "created_at", "TEXT")
    ensure_column(cur, "rentals", "updated_at", "TEXT")
    ensure_column(cur, "rentals", "due_at", "TEXT")
    ensure_column(cur, "rentals", "returned_at", "TEXT")
    ensure_column(cur, "rentals", "late_fee", "REAL DEFAULT 0")
    ensure_column(cur, "rentals", "note", "TEXT")
    ensure_column(cur, "scan_history", "risk_score", "INTEGER DEFAULT 0")

    admin = cur.execute("SELECT * FROM users WHERE username = ?", ("admin",)).fetchone()
    if not admin:
        cur.execute(
            "INSERT INTO users (fullname, username, password, role, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Quản trị viên", "admin", generate_password_hash("admin123"), "admin", now_text()),
        )
    else:
        cur.execute("UPDATE users SET role = ? WHERE username = ?", ("admin", "admin"))

    staff = cur.execute("SELECT * FROM users WHERE username = ?", ("staff",)).fetchone()
    if not staff:
        cur.execute(
            "INSERT INTO users (fullname, username, password, role, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Nhân viên thư viện", "staff", generate_password_hash("staff123"), "staff", now_text()),
        )

    count_books = cur.execute("SELECT COUNT(*) AS total FROM books").fetchone()["total"]
    if count_books == 0:
        sample_books = [
            ("Doraemon Tập 1", "Fujiko F. Fujio", "Truyện tranh", 10, 5000, "Truyện tranh thiếu nhi nổi tiếng.", "/static/uploads/doraemon.svg"),
            ("Conan Tập 1", "Gosho Aoyama", "Trinh thám", 8, 6000, "Truyện trinh thám hấp dẫn.", "/static/uploads/conan.svg"),
            ("Harry Potter", "J.K. Rowling", "Tiểu thuyết", 5, 10000, "Tiểu thuyết giả tưởng nổi tiếng.", "/static/uploads/harry-potter.svg"),
            ("Đắc Nhân Tâm", "Dale Carnegie", "Kỹ năng sống", 7, 8000, "Sách kỹ năng giao tiếp và phát triển bản thân.", "/static/uploads/dac-nhan-tam.svg"),
            ("Nhà Giả Kim", "Paulo Coelho", "Tiểu thuyết", 6, 9000, "Câu chuyện truyền cảm hứng về hành trình theo đuổi ước mơ.", "/static/uploads/nha-gia-kim.svg"),
            ("Tôi Thấy Hoa Vàng Trên Cỏ Xanh", "Nguyễn Nhật Ánh", "Văn học Việt Nam", 9, 7000, "Tác phẩm nhẹ nhàng, gần gũi với tuổi học trò.", "/static/uploads/hoa-vang-co-xanh.svg"),
        ]
        cur.executemany(
            "INSERT INTO books (title, author, category, quantity, price, description, cover_image) VALUES (?, ?, ?, ?, ?, ?, ?)",
            sample_books,
        )
    else:
        samples = {
            "Doraemon Tập 1": "/static/uploads/doraemon.svg",
            "Conan Tập 1": "/static/uploads/conan.svg",
            "Harry Potter": "/static/uploads/harry-potter.svg",
            "Đắc Nhân Tâm": "/static/uploads/dac-nhan-tam.svg",
            "Nhà Giả Kim": "/static/uploads/nha-gia-kim.svg",
            "Tôi Thấy Hoa Vàng Trên Cỏ Xanh": "/static/uploads/hoa-vang-co-xanh.svg",
        }
        for title, cover in samples.items():
            cur.execute("UPDATE books SET cover_image = COALESCE(NULLIF(cover_image, ''), ?) WHERE title = ?", (cover, title))

    extra_books = [
        ("Mắt Biếc", "Nguyễn Nhật Ánh", "Văn học Việt Nam", 12, 7000, "Tác phẩm nổi tiếng về tuổi trẻ, tình bạn và tình yêu trong sáng.", "/static/uploads/default-cover.svg"),
        ("Cho Tôi Xin Một Vé Đi Tuổi Thơ", "Nguyễn Nhật Ánh", "Văn học Việt Nam", 10, 7000, "Câu chuyện nhẹ nhàng, hài hước và giàu cảm xúc về tuổi thơ.", "/static/uploads/default-cover.svg"),
        ("Sherlock Holmes", "Arthur Conan Doyle", "Trinh thám", 9, 9000, "Tuyển tập truyện trinh thám kinh điển với nhân vật Sherlock Holmes.", "/static/uploads/default-cover.svg"),
        ("Tuổi Trẻ Đáng Giá Bao Nhiêu", "Rosie Nguyễn", "Kỹ năng sống", 11, 8000, "Cuốn sách truyền cảm hứng về học tập, trải nghiệm và phát triển bản thân.", "/static/uploads/default-cover.svg"),
        ("Tôi Tài Giỏi, Bạn Cũng Thế", "Adam Khoo", "Kỹ năng học tập", 7, 8500, "Sách hướng dẫn phương pháp học tập hiệu quả dành cho học sinh, sinh viên.", "/static/uploads/default-cover.svg"),
        ("Không Gia Đình", "Hector Malot", "Tiểu thuyết", 6, 9000, "Tiểu thuyết giàu giá trị nhân văn về nghị lực và tình cảm gia đình.", "/static/uploads/default-cover.svg"),
        ("Hoàng Tử Bé", "Antoine de Saint-Exupéry", "Văn học nước ngoài", 8, 7500, "Tác phẩm nổi tiếng với nhiều bài học sâu sắc về tình yêu và cuộc sống.", "/static/uploads/default-cover.svg"),
        ("Lược Sử Thời Gian", "Stephen Hawking", "Khoa học", 5, 12000, "Cuốn sách phổ biến kiến thức vũ trụ học và khoa học hiện đại.", "/static/uploads/default-cover.svg"),
        ("Clean Code", "Robert C. Martin", "Công nghệ thông tin", 4, 15000, "Sách nhập môn về tư duy viết mã sạch, dễ đọc và dễ bảo trì.", "/static/uploads/default-cover.svg"),
        ("Python Cơ Bản", "Nhiều tác giả", "Công nghệ thông tin", 8, 10000, "Tài liệu học Python căn bản phù hợp với sinh viên CNTT.", "/static/uploads/default-cover.svg"),
    ]
    for book_item in extra_books:
        exists = cur.execute("SELECT id FROM books WHERE title = ?", (book_item[0],)).fetchone()
        if not exists:
            cur.execute(
                "INSERT INTO books (title, author, category, quantity, price, description, cover_image) VALUES (?, ?, ?, ?, ?, ?, ?)",
                book_item,
            )

    cur.execute("UPDATE rentals SET rental_code = 'BR' || id WHERE rental_code IS NULL OR rental_code = ''")
    cur.execute("UPDATE rentals SET due_at = date(created_at, '+7 day') WHERE due_at IS NULL OR due_at = ''")
    cur.execute("UPDATE rentals SET late_fee = 0 WHERE late_fee IS NULL")

    conn.commit()
    conn.close()


def log_action(action, detail=""):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_logs (user_id, action, detail, created_at) VALUES (?, ?, ?, ?)",
            (session.get("user_id"), action, detail, now_text()),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Bạn cần đăng nhập để sử dụng chức năng này.")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapper


def role_required(*allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                flash("Bạn cần đăng nhập để sử dụng chức năng này.")
                return redirect(url_for("login"))
            if session.get("role") not in allowed_roles:
                flash("Bạn không có quyền truy cập chức năng này.")
                return redirect(url_for("index"))
            return view_func(*args, **kwargs)
        return wrapper
    return decorator


def permission_required(permission_name):
    return role_required(*PERMISSIONS.get(permission_name, set()))


@app.context_processor
def inject_permissions():
    role = session.get("role")
    return {
        "roles": ROLES,
        "can_manage_books": role in PERMISSIONS["manage_books"],
        "can_manage_rentals": role in PERMISSIONS["manage_rentals"],
        "can_manage_users": role in PERMISSIONS["manage_users"],
        "can_security_scan": role in PERMISSIONS["security_scan"],
    }


def count_levels(results):
    return {
        "high": sum(1 for item in results if item.get("level") == "Cao"),
        "medium": sum(1 for item in results if item.get("level") == "Trung bình"),
        "low": sum(1 for item in results if item.get("level") == "Thấp"),
    }


def calculate_risk_score(levels):
    score = levels["high"] * 30 + levels["medium"] * 12 + levels["low"] * 3
    return min(score, 100)


def calculate_late_fee(due_at):
    if not due_at:
        return 0
    try:
        due_date = datetime.strptime(due_at[:10], "%Y-%m-%d").date()
    except ValueError:
        return 0
    late_days = (datetime.now().date() - due_date).days
    if late_days <= 0:
        return 0
    return late_days * LATE_FEE_PER_DAY


def money_vnd(value):
    try:
        return f"{float(value):,.0f} VNĐ"
    except (TypeError, ValueError):
        return "0 VNĐ"


@app.template_filter("money_vnd")
def money_vnd_filter(value):
    return money_vnd(value)


def generate_invoice_code(rental_id):
    return f"HD{datetime.now().strftime('%Y%m%d')}-{int(rental_id):05d}"


def get_invoice_data(rental_id):
    conn = get_db()
    rental = conn.execute(
        """
        SELECT
            rentals.id,
            rentals.rental_code,
            rentals.status,
            rentals.created_at,
            rentals.updated_at,
            rentals.due_at,
            rentals.returned_at,
            rentals.late_fee,
            rentals.note,
            users.id AS user_id,
            users.fullname,
            users.username,
            books.title AS book_title,
books.author,
books.category,
books.price,
books.cover_image
        FROM rentals
        JOIN users ON rentals.user_id = users.id
        JOIN books ON rentals.book_id = books.id
        WHERE rentals.id = ?
        """,
        (rental_id,),
    ).fetchone()
    conn.close()
    return rental


def create_or_update_invoice(rental_id):
    rental = get_invoice_data(rental_id)
    if not rental or rental["status"] == "Đã hủy":
        return None

    subtotal = float(rental["price"] or 0)
    late_fee = float(rental["late_fee"] or 0)
    total_amount = subtotal + late_fee

    conn = get_db()
    old_invoice = conn.execute("SELECT * FROM invoices WHERE rental_id = ?", (rental_id,)).fetchone()

    if old_invoice:
        invoice_code = old_invoice["invoice_code"]
        issued_at = old_invoice["issued_at"]
        conn.execute(
            """
            UPDATE invoices
            SET subtotal = ?, late_fee = ?, total_amount = ?, note = ?
            WHERE rental_id = ?
            """,
            (
                subtotal,
                late_fee,
                total_amount,
                f"Hóa đơn thuê sách cho đơn {rental['rental_code'] or rental_id}",
                rental_id,
            ),
        )
    else:
        invoice_code = generate_invoice_code(rental_id)
        issued_at = now_text()
        conn.execute(
            """
            INSERT INTO invoices (
                invoice_code, rental_id, subtotal, late_fee,
                total_amount, issued_at, created_by, note
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                invoice_code,
                rental_id,
                subtotal,
                late_fee,
                total_amount,
                issued_at,
                session.get("user_id"),
                f"Hóa đơn thuê sách cho đơn {rental['rental_code'] or rental_id}",
            ),
        )

    conn.commit()
    conn.close()

    return {
        "invoice_code": invoice_code,
        "issued_at": issued_at,
        "rental": rental,
        "subtotal": subtotal,
        "late_fee": late_fee,
        "total_amount": total_amount,
    }


def invoice_to_text(invoice):
    rental = invoice["rental"]
    return "﻿" + f"""
HÓA ĐƠN THUÊ SÁCH
==================================================

Mã hóa đơn: {invoice["invoice_code"]}
Mã đơn thuê: {rental["rental_code"] or rental["id"]}
Ngày lập: {invoice["issued_at"]}

THÔNG TIN KHÁCH HÀNG
--------------------------------------------------
Họ tên: {rental["fullname"]}
Tài khoản: {rental["username"]}

THÔNG TIN SÁCH THUÊ
--------------------------------------------------
Tên sách: {rental["book_title"]}
Tác giả: {rental["author"]}
Thể loại: {rental["category"]}

THÔNG TIN ĐƠN THUÊ
--------------------------------------------------
Trạng thái: {rental["status"]}
Ngày tạo đơn: {rental["created_at"]}
Ngày cập nhật: {rental["updated_at"] or "Chưa cập nhật"}
Hạn trả: {rental["due_at"] or "Chưa có"}
Ngày trả: {rental["returned_at"] or "Chưa trả"}

THANH TOÁN
--------------------------------------------------
Tiền thuê sách: {money_vnd(invoice["subtotal"])}
Phí quá hạn: {money_vnd(invoice["late_fee"])}
Tổng tiền: {money_vnd(invoice["total_amount"])}

Ghi chú: {rental["note"] or "Không có"}

==================================================
Người lập hóa đơn: ______________________________

Khách hàng ký nhận: _____________________________
"""


@app.template_filter("status_class")
def status_class_filter(status):
    mapping = {
        "Chờ xác nhận": "pending",
        "Đã xác nhận": "approved",
        "Đã trả": "returned",
        "Đã hủy": "cancelled",
    }
    return mapping.get(status, "pending")


@app.template_filter("level_class")
def level_class_filter(level):
    mapping = {"Cao": "danger-level", "Trung bình": "warning-level", "Thấp": "safe-level"}
    return mapping.get(level, "safe-level")


@app.route("/")
def index():
    conn = get_db()
    total_books = conn.execute("SELECT COUNT(*) AS total FROM books").fetchone()["total"]
    total_rentals = conn.execute("SELECT COUNT(*) AS total FROM rentals").fetchone()["total"]
    total_scans = conn.execute("SELECT COUNT(*) AS total FROM scan_history").fetchone()["total"]
    featured_books = conn.execute("SELECT * FROM books ORDER BY quantity DESC, id ASC LIMIT 6").fetchall()
    conn.close()
    return render_template(
        "index.html",
        total_books=total_books,
        total_rentals=total_rentals,
        total_scans=total_scans,
        featured_books=featured_books,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        fullname = request.form.get("fullname", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(fullname) < 2:
            flash("Vui lòng nhập họ tên hợp lệ.")
            return redirect(url_for("register"))
        if len(username) < 3:
            flash("Tên đăng nhập phải có ít nhất 3 ký tự.")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("Mật khẩu phải có ít nhất 6 ký tự.")
            return redirect(url_for("register"))
        if password != confirm_password:
            flash("Mật khẩu nhập lại không khớp.")
            return redirect(url_for("register"))

        conn = get_db()
        cur = conn.cursor()
        existing_user = cur.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if existing_user:
            conn.close()
            flash("Tên đăng nhập đã tồn tại.")
            return redirect(url_for("register"))

        cur.execute(
            "INSERT INTO users (fullname, username, password, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (fullname, username, generate_password_hash(password), "customer", now_text()),
        )
        conn.commit()
        conn.close()
        flash("Đăng ký thành công. Vui lòng đăng nhập.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password"], password):
            conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_text(), user["id"]))
            conn.commit()
            conn.close()
            session.clear()
            session["user_id"] = user["id"]
            session["fullname"] = user["fullname"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            log_action("Đăng nhập", f"Tài khoản {username} đăng nhập với vai trò {user['role']}")
            flash(f"Đăng nhập thành công với vai trò {ROLES.get(user['role'], user['role'])}.")
            if user["role"] in ("admin", "staff"):
                return redirect(url_for("admin"))
            return redirect(url_for("books"))

        conn.close()
        flash("Sai tên đăng nhập hoặc mật khẩu.")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    log_action("Đăng xuất", "Người dùng đăng xuất khỏi hệ thống")
    session.clear()
    flash("Đã đăng xuất.")
    return redirect(url_for("index"))


@app.route("/books")
def books():
    keyword = request.args.get("keyword", "").strip()
    category = request.args.get("category", "").strip()
    availability = request.args.get("availability", "").strip()

    query = "SELECT * FROM books WHERE 1=1"
    params = []
    if keyword:
        query += " AND (title LIKE ? OR author LIKE ? OR category LIKE ?)"
        params.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
    if category:
        query += " AND category = ?"
        params.append(category)
    if availability == "available":
        query += " AND quantity > 0"
    elif availability == "out":
        query += " AND quantity <= 0"
    query += " ORDER BY id DESC"

    conn = get_db()
    book_list = conn.execute(query, params).fetchall()
    categories = conn.execute("SELECT DISTINCT category FROM books ORDER BY category").fetchall()
    conn.close()
    return render_template("books.html", books=book_list, keyword=keyword, category=category, availability=availability, categories=categories)


@app.route("/book/<int:book_id>")
def book_detail(book_id):
    conn = get_db()
    book = conn.execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()
    conn.close()
    if not book:
        flash("Không tìm thấy sách/truyện.")
        return redirect(url_for("books"))
    return render_template("book_detail.html", book=book)


@app.route("/rent/<int:book_id>")
@login_required
def rent_book(book_id):
    if session.get("role") in ("admin", "staff"):
        flash("Tài khoản quản trị/nhân viên không cần gửi yêu cầu thuê sách.")
        return redirect(url_for("books"))

    conn = get_db()
    book = conn.execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()
    if not book:
        conn.close()
        flash("Không tìm thấy sách.")
        return redirect(url_for("books"))
    if book["quantity"] <= 0:
        conn.close()
        flash("Sách đã hết, không thể thuê.")
        return redirect(url_for("books"))

    existed = conn.execute(
        """
        SELECT * FROM rentals
        WHERE user_id = ? AND book_id = ? AND status IN ('Chờ xác nhận', 'Đã xác nhận')
        """,
        (session["user_id"], book_id),
    ).fetchone()
    if existed:
        conn.close()
        flash("Bạn đã có đơn thuê sách này đang xử lý hoặc chưa trả.")
        return redirect(url_for("my_rentals"))

    rental_code = "BR" + datetime.now().strftime("%Y%m%d%H%M%S") + str(session["user_id"])
    due_at = (datetime.now() + timedelta(days=DEFAULT_RENTAL_DAYS)).strftime("%Y-%m-%d")
    conn.execute(
        """
        INSERT INTO rentals (rental_code, user_id, book_id, status, created_at, updated_at, due_at, late_fee, note)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (rental_code, session["user_id"], book_id, "Chờ xác nhận", now_text(), now_text(), due_at, 0, "Đơn thuê đang chờ nhân viên xác nhận."),
    )
    conn.commit()
    conn.close()
    log_action("Tạo đơn thuê", f"Khách hàng tạo đơn thuê sách ID {book_id}, hạn trả {due_at}")
    flash("Gửi yêu cầu thuê sách thành công.")
    return redirect(url_for("my_rentals"))


@app.route("/my-rentals")
@login_required
def my_rentals():
    conn = get_db()
    rentals = conn.execute(
        """
        SELECT rentals.id, rentals.rental_code, books.title, books.author, rentals.status,
               rentals.created_at, rentals.updated_at, rentals.due_at, rentals.returned_at,
               rentals.late_fee, rentals.note
        FROM rentals
        JOIN books ON rentals.book_id = books.id
        WHERE rentals.user_id = ?
        ORDER BY rentals.id DESC
        """,
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return render_template("admin.html", title="Lịch sử thuê sách", rentals=rentals, mode="my_rentals")


@app.route("/admin")
@permission_required("manage_rentals")
def admin():
    rental_status = request.args.get("status", "").strip()
    book_keyword = request.args.get("book_keyword", "").strip()

    conn = get_db()
    users = conn.execute("SELECT id, fullname, username, role, created_at, last_login FROM users ORDER BY id").fetchall()

    book_query = "SELECT * FROM books WHERE 1=1"
    book_params = []
    if book_keyword:
        book_query += " AND (title LIKE ? OR author LIKE ? OR category LIKE ?)"
        book_params.extend([f"%{book_keyword}%", f"%{book_keyword}%", f"%{book_keyword}%"])
    book_query += " ORDER BY id DESC"
    books_data = conn.execute(book_query, book_params).fetchall()

    rental_query = """
        SELECT rentals.id, rentals.rental_code, users.fullname, users.username, books.title,
               rentals.status, rentals.created_at, rentals.updated_at, rentals.due_at,
               rentals.returned_at, rentals.late_fee, rentals.note
        FROM rentals
        JOIN users ON rentals.user_id = users.id
        JOIN books ON rentals.book_id = books.id
        WHERE 1=1
    """
    rental_params = []
    if rental_status:
        rental_query += " AND rentals.status = ?"
        rental_params.append(rental_status)
    rental_query += " ORDER BY rentals.id DESC"
    rentals = conn.execute(rental_query, rental_params).fetchall()

    stats = {
        "books": conn.execute("SELECT COUNT(*) AS total FROM books").fetchone()["total"],
        "users": conn.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"],
        "pending": conn.execute("SELECT COUNT(*) AS total FROM rentals WHERE status = 'Chờ xác nhận'").fetchone()["total"],
        "approved": conn.execute("SELECT COUNT(*) AS total FROM rentals WHERE status = 'Đã xác nhận'").fetchone()["total"],
        "returned": conn.execute("SELECT COUNT(*) AS total FROM rentals WHERE status = 'Đã trả'").fetchone()["total"],
        "overdue": conn.execute("SELECT COUNT(*) AS total FROM rentals WHERE status = 'Đã xác nhận' AND due_at < ?", (today_text(),)).fetchone()["total"],
        "scans": conn.execute("SELECT COUNT(*) AS total FROM scan_history").fetchone()["total"],
        "late_fee": conn.execute("SELECT COALESCE(SUM(late_fee), 0) AS total FROM rentals").fetchone()["total"],
        "invoices": conn.execute("SELECT COUNT(*) AS total FROM invoices").fetchone()["total"],
    }
    conn.close()

    return render_template(
        "admin.html",
        title="Trang quản trị",
        users=users,
        books=books_data,
        rentals=rentals,
        mode="admin",
        stats=stats,
        rental_status=rental_status,
        rental_statuses=RENTAL_STATUS,
        book_keyword=book_keyword,
    )


@app.route("/admin/add-book", methods=["POST"])
@permission_required("manage_books")
def add_book():
    try:
        title = request.form.get("title", "").strip()
        author = request.form.get("author", "").strip()
        category = request.form.get("category", "").strip()
        quantity = int(request.form.get("quantity", 0))
        price = float(request.form.get("price", 0))
        description = request.form.get("description", "").strip()
        cover_image = request.form.get("cover_image", "").strip()
        uploaded_cover = save_cover_image(request.files.get("cover_file"))
        if uploaded_cover:
            cover_image = uploaded_cover
        if not cover_image:
            cover_image = "/static/uploads/default-cover.svg"
        if not title or not author or not category or quantity < 0 or price < 0:
            raise ValueError
    except ValueError:
        flash("Dữ liệu sách không hợp lệ. Vui lòng kiểm tra lại.")
        return redirect(url_for("admin"))

    conn = get_db()
    conn.execute(
        "INSERT INTO books (title, author, category, quantity, price, description, cover_image) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (title, author, category, quantity, price, description, cover_image),
    )
    conn.commit()
    conn.close()
    log_action("Thêm sách", f"Thêm sách: {title}")
    flash("Thêm sách thành công.")
    return redirect(url_for("admin"))


@app.route("/admin/edit-book/<int:book_id>", methods=["GET", "POST"])
@permission_required("manage_books")
def edit_book(book_id):
    conn = get_db()
    book = conn.execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()
    if not book:
        conn.close()
        flash("Không tìm thấy sách cần sửa.")
        return redirect(url_for("admin"))

    if request.method == "POST":
        try:
            title = request.form.get("title", "").strip()
            author = request.form.get("author", "").strip()
            category = request.form.get("category", "").strip()
            quantity = int(request.form.get("quantity", 0))
            price = float(request.form.get("price", 0))
            description = request.form.get("description", "").strip()
            cover_image = request.form.get("cover_image", "").strip()
            uploaded_cover = save_cover_image(request.files.get("cover_file"))
            if uploaded_cover:
                cover_image = uploaded_cover
            if not cover_image:
                cover_image = "/static/uploads/default-cover.svg"
            if not title or not author or not category or quantity < 0 or price < 0:
                raise ValueError
        except ValueError:
            conn.close()
            flash("Dữ liệu cập nhật không hợp lệ.")
            return redirect(url_for("edit_book", book_id=book_id))

        conn.execute(
            """
            UPDATE books
            SET title = ?, author = ?, category = ?, quantity = ?, price = ?, description = ?, cover_image = ?
            WHERE id = ?
            """,
            (title, author, category, quantity, price, description, cover_image, book_id),
        )
        conn.commit()
        conn.close()
        log_action("Sửa sách", f"Cập nhật sách ID {book_id}: {title}")
        flash("Cập nhật sách thành công.")
        return redirect(url_for("admin"))

    conn.close()
    return render_template("edit_book.html", book=book)


@app.route("/admin/delete-book/<int:book_id>")
@permission_required("manage_books")
def delete_book(book_id):
    conn = get_db()
    book = conn.execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()
    active_rental = conn.execute(
        "SELECT * FROM rentals WHERE book_id = ? AND status IN ('Chờ xác nhận', 'Đã xác nhận')",
        (book_id,),
    ).fetchone()
    if active_rental:
        conn.close()
        flash("Không thể xóa sách đang có đơn thuê chưa hoàn tất.")
        return redirect(url_for("admin"))

    conn.execute("DELETE FROM rentals WHERE book_id = ?", (book_id,))
    conn.execute("DELETE FROM books WHERE id = ?", (book_id,))
    conn.commit()
    conn.close()
    log_action("Xóa sách", f"Xóa sách ID {book_id}: {book['title'] if book else ''}")
    flash("Xóa sách thành công.")
    return redirect(url_for("admin"))


@app.route("/admin/approve-rental/<int:rental_id>")
@permission_required("manage_rentals")
def approve_rental(rental_id):
    invoice_needed = False
    conn = get_db()
    rental = conn.execute("SELECT * FROM rentals WHERE id = ?", (rental_id,)).fetchone()
    if rental and rental["status"] == "Chờ xác nhận":
        book = conn.execute("SELECT * FROM books WHERE id = ?", (rental["book_id"],)).fetchone()
        if book and book["quantity"] > 0:
            conn.execute(
                "UPDATE rentals SET status = ?, updated_at = ?, note = ? WHERE id = ?",
                ("Đã xác nhận", now_text(), "Đơn thuê đã được nhân viên xác nhận.", rental_id),
            )
            conn.execute("UPDATE books SET quantity = quantity - 1 WHERE id = ?", (rental["book_id"],))
            invoice_needed = True
            flash("Đã xác nhận đơn thuê và tạo hóa đơn.")
            log_action("Xác nhận thuê", f"Xác nhận đơn thuê ID {rental_id}")
        else:
            flash("Sách đã hết, không thể xác nhận.")
    else:
        flash("Đơn thuê không hợp lệ hoặc đã xử lý.")
    conn.commit()
    conn.close()

    if invoice_needed:
        create_or_update_invoice(rental_id)
        log_action("Tạo hóa đơn", f"Tạo/cập nhật hóa đơn cho đơn thuê ID {rental_id}")

    return redirect(url_for("admin"))

@app.route("/admin/return-rental/<int:rental_id>")
@permission_required("manage_rentals")
def return_rental(rental_id):
    invoice_needed = False
    conn = get_db()
    rental = conn.execute("SELECT * FROM rentals WHERE id = ?", (rental_id,)).fetchone()
    if rental and rental["status"] == "Đã xác nhận":
        late_fee = calculate_late_fee(rental["due_at"])
        note = "Khách hàng đã trả sách đúng hạn."
        if late_fee > 0:
            note = f"Khách hàng trả sách quá hạn, phí phát sinh {late_fee:,.0f} VNĐ."
        conn.execute(
            """
            UPDATE rentals
            SET status = ?, updated_at = ?, returned_at = ?, late_fee = ?, note = ?
            WHERE id = ?
            """,
            ("Đã trả", now_text(), today_text(), late_fee, note, rental_id),
        )
        conn.execute("UPDATE books SET quantity = quantity + 1 WHERE id = ?", (rental["book_id"],))
        invoice_needed = True
        flash("Đã xác nhận trả sách và cập nhật hóa đơn.")
        log_action("Xác nhận trả", f"Xác nhận trả đơn ID {rental_id}, phí trễ hạn {late_fee:,.0f} VNĐ")
    else:
        flash("Chỉ có thể trả sách đối với đơn đã xác nhận.")
    conn.commit()
    conn.close()

    if invoice_needed:
        create_or_update_invoice(rental_id)
        log_action("Cập nhật hóa đơn", f"Cập nhật hóa đơn sau khi trả sách cho đơn ID {rental_id}")

    return redirect(url_for("admin"))

@app.route("/admin/cancel-rental/<int:rental_id>")
@permission_required("manage_rentals")
def cancel_rental(rental_id):
    conn = get_db()
    rental = conn.execute("SELECT * FROM rentals WHERE id = ?", (rental_id,)).fetchone()
    if rental and rental["status"] == "Chờ xác nhận":
        conn.execute(
            "UPDATE rentals SET status = ?, updated_at = ?, note = ? WHERE id = ?",
            ("Đã hủy", now_text(), "Đơn thuê đã bị hủy trước khi xác nhận.", rental_id),
        )
        flash("Đã hủy đơn thuê.")
        log_action("Hủy đơn thuê", f"Hủy đơn thuê ID {rental_id}")
    else:
        flash("Chỉ có thể hủy đơn đang chờ xác nhận.")
    conn.commit()
    conn.close()
    return redirect(url_for("admin"))


@app.route("/admin/update-role/<int:user_id>", methods=["POST"])
@permission_required("manage_users")
def update_role(user_id):
    new_role = request.form.get("role")
    if new_role not in ROLES:
        flash("Vai trò không hợp lệ.")
        return redirect(url_for("admin"))
    if user_id == session.get("user_id") and new_role != "admin":
        flash("Không thể tự hạ quyền tài khoản Admin đang đăng nhập.")
        return redirect(url_for("admin"))

    conn = get_db()
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    log_action("Cập nhật phân quyền", f"Cập nhật tài khoản ID {user_id} sang vai trò {new_role}")
    flash("Cập nhật phân quyền tài khoản thành công.")
    return redirect(url_for("admin"))


@app.route("/security-scan", methods=["GET", "POST"])
@permission_required("security_scan")
def security_scan():
    if request.method == "POST":
        raw_urls = request.form.get("urls", "").strip() or request.form.get("url", "").strip()
        urls = [line.strip() for line in raw_urls.replace(",", "\n").splitlines() if line.strip()]
        if not urls:
            flash("Vui lòng nhập ít nhất một URL cần kiểm tra.")
            return redirect(url_for("security_scan"))
        if len(urls) > 5:
            flash("Bản demo chỉ quét tối đa 5 URL trong một lần để tránh quá tải.")
            return redirect(url_for("security_scan"))

        scans = []
        conn = get_db()
        for url in urls:
            results = scan_website(url)
            levels = count_levels(results)
            risk_score = calculate_risk_score(levels)
            scanned_at = now_text()
            cur = conn.execute(
                """
                INSERT INTO scan_history (url, scanned_at, total, high_count, medium_count, low_count, risk_score, results_json, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (url, scanned_at, len(results), levels["high"], levels["medium"], levels["low"], risk_score, json.dumps(results, ensure_ascii=False), session.get("user_id")),
            )
            scans.append({
                "history_id": cur.lastrowid,
                "url": url,
                "scanned_at": scanned_at,
                "results": results,
                "levels": levels,
                "risk_score": risk_score,
            })
        conn.commit()
        conn.close()
        log_action("Quét lỗ hổng", f"Thực hiện quét {len(urls)} URL")
        return render_template("scan_result.html", scans=scans)
    return render_template("security_scan.html")


@app.route("/scan-history")
@permission_required("security_scan")
def scan_history():
    conn = get_db()
    histories = conn.execute(
        """
        SELECT scan_history.*, users.fullname
        FROM scan_history
        LEFT JOIN users ON scan_history.created_by = users.id
        ORDER BY scan_history.id DESC
        LIMIT 100
        """
    ).fetchall()
    conn.close()
    return render_template("scan_history.html", histories=histories)


@app.route("/scan-history/<int:history_id>")
@permission_required("security_scan")
def scan_detail(history_id):
    conn = get_db()
    history = conn.execute("SELECT * FROM scan_history WHERE id = ?", (history_id,)).fetchone()
    conn.close()
    if not history:
        flash("Không tìm thấy lịch sử quét.")
        return redirect(url_for("scan_history"))
    scans = [{
        "history_id": history["id"],
        "url": history["url"],
        "scanned_at": history["scanned_at"],
        "results": json.loads(history["results_json"]),
        "levels": {"high": history["high_count"], "medium": history["medium_count"], "low": history["low_count"]},
        "risk_score": history["risk_score"],
    }]
    return render_template("scan_result.html", scans=scans)


@app.route("/scan-history/<int:history_id>/export")
@permission_required("security_scan")
def export_scan(history_id):
    conn = get_db()
    history = conn.execute("SELECT * FROM scan_history WHERE id = ?", (history_id,)).fetchone()
    conn.close()
    if not history:
        flash("Không tìm thấy lịch sử quét.")
        return redirect(url_for("scan_history"))

    results = json.loads(history["results_json"])
    lines = [
        "BÁO CÁO KẾT QUẢ QUÉT LỖ HỔNG",
        f"URL: {history['url']}",
        f"Thời gian quét: {history['scanned_at']}",
        f"Tổng kiểm tra: {history['total']}",
        f"Điểm rủi ro: {history['risk_score']}/100",
        f"Mức Cao: {history['high_count']}",
        f"Mức Trung bình: {history['medium_count']}",
        f"Mức Thấp: {history['low_count']}",
        "",
    ]
    for index, item in enumerate(results, 1):
        lines.extend([
            f"{index}. {item.get('name')}",
            f"   Nhóm kiểm tra: {item.get('module', '')}",
            f"   Trạng thái: {item.get('status')}",
            f"   Mức độ: {item.get('level')}",
            f"   Chi tiết: {item.get('detail')}",
            f"   Đề xuất: {item.get('solution')}",
            "",
        ])
    content = "\ufeff" + "\n".join(lines)
    filename = f"scan_report_{history_id}.txt"
    return Response(
        content,
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/analytics")
@permission_required("manage_rentals")
def analytics():
    conn = get_db()
    rental_by_status = conn.execute(
        """
        SELECT status, COUNT(*) AS total
        FROM rentals
        GROUP BY status
        ORDER BY total DESC
        """
    ).fetchall()
    popular_books = conn.execute(
        """
        SELECT books.title, books.author, COUNT(rentals.id) AS total_rentals
        FROM books
        LEFT JOIN rentals ON books.id = rentals.book_id
        GROUP BY books.id
        ORDER BY total_rentals DESC, books.title ASC
        LIMIT 10
        """
    ).fetchall()
    low_stock_books = conn.execute(
        """
        SELECT id, title, author, quantity
        FROM books
        WHERE quantity <= 2
        ORDER BY quantity ASC, title ASC
        """
    ).fetchall()
    scan_overview = conn.execute(
        """
        SELECT
            COUNT(*) AS total_scans,
            COALESCE(SUM(high_count), 0) AS high_total,
            COALESCE(SUM(medium_count), 0) AS medium_total,
            COALESCE(SUM(low_count), 0) AS low_total,
            COALESCE(ROUND(AVG(risk_score), 1), 0) AS avg_risk_score
        FROM scan_history
        """
    ).fetchone()
    latest_scans = conn.execute(
        """
        SELECT url, scanned_at, high_count, medium_count, low_count, risk_score
        FROM scan_history
        ORDER BY id DESC
        LIMIT 5
        """
    ).fetchall()
    rental_overview = conn.execute(
        """
        SELECT
            COUNT(*) AS total_rentals,
            SUM(CASE WHEN status = 'Đã xác nhận' AND due_at < date('now') THEN 1 ELSE 0 END) AS overdue_total,
            COALESCE(SUM(late_fee), 0) AS late_fee_total
        FROM rentals
        """
    ).fetchone()
    conn.close()
    return render_template(
        "analytics.html",
        rental_by_status=rental_by_status,
        popular_books=popular_books,
        low_stock_books=low_stock_books,
        scan_overview=scan_overview,
        latest_scans=latest_scans,
        rental_overview=rental_overview,
    )


def build_invoice_view_model(invoice):
    rental = invoice["rental"]

    rental_days = DEFAULT_RENTAL_DAYS
    try:
        if rental["created_at"] and rental["due_at"]:
            start = datetime.strptime(rental["created_at"][:10], "%Y-%m-%d").date()
            due = datetime.strptime(rental["due_at"][:10], "%Y-%m-%d").date()
            rental_days = max((due - start).days, 1)
    except Exception:
        rental_days = DEFAULT_RENTAL_DAYS

    return {
        "shop_name": "BOOK RENTAL SECURITY",
        "shop_address": "Đà Nẵng",
        "shop_phone": "0900 000 000",
        "shop_email": "bookrental.demo@gmail.com",
        "invoice_code": invoice["invoice_code"],
        "issued_at": invoice["issued_at"],
        "customer_name": rental["fullname"],
        "customer_username": rental["username"],
        "rental_code": rental["rental_code"] or rental["id"],
        "status": rental["status"],
        "created_at": rental["created_at"],
        "due_at": rental["due_at"] or "Chưa có",
        "returned_at": rental["returned_at"],
        "book_title": rental["book_title"],
        "book_author": rental["author"],
        "book_category": rental["category"],
        "rental_days": rental_days,
        "unit_price": invoice["subtotal"],
        "subtotal": invoice["subtotal"],
        "late_fee": invoice["late_fee"],
        "total_amount": invoice["total_amount"],
        "note": rental["note"],
    }


@app.route("/invoice/<int:rental_id>")
@login_required
def invoice_detail(rental_id):
    rental = get_invoice_data(rental_id)

    if not rental:
        flash("Không tìm thấy đơn thuê.")
        return redirect(url_for("index"))

    is_manager = session.get("role") in ("admin", "staff")
    is_owner = rental["user_id"] == session.get("user_id")

    if not is_manager and not is_owner:
        flash("Bạn không có quyền xem hóa đơn này.")
        return redirect(url_for("index"))

    if rental["status"] == "Đã hủy":
        flash("Không thể xem hóa đơn cho đơn đã hủy.")
        return redirect(url_for("admin") if is_manager else url_for("my_rentals"))

    invoice = create_or_update_invoice(rental_id)
    if not invoice:
        flash("Không thể tạo hóa đơn cho đơn thuê này.")
        return redirect(url_for("admin") if is_manager else url_for("my_rentals"))

    log_action("Xem hóa đơn", f"Xem hóa đơn {invoice['invoice_code']} cho đơn thuê ID {rental_id}")
    return render_template("invoice.html", invoice=build_invoice_view_model(invoice))


@app.route("/invoice/<int:rental_id>/download")
@login_required
def download_invoice(rental_id):
    rental = get_invoice_data(rental_id)

    if not rental:
        flash("Không tìm thấy đơn thuê.")
        return redirect(url_for("index"))

    is_manager = session.get("role") in ("admin", "staff")
    is_owner = rental["user_id"] == session.get("user_id")
    if not is_manager and not is_owner:
        flash("Bạn không có quyền tải hóa đơn này.")
        return redirect(url_for("index"))

    if rental["status"] == "Đã hủy":
        flash("Không thể xuất hóa đơn cho đơn đã hủy.")
        return redirect(url_for("my_rentals") if not is_manager else url_for("admin"))

    invoice = create_or_update_invoice(rental_id)
    if not invoice:
        flash("Không thể tạo hóa đơn cho đơn thuê này.")
        return redirect(url_for("my_rentals") if not is_manager else url_for("admin"))

    filename = f"hoa_don_{invoice['invoice_code']}.txt"
    log_action("Tải hóa đơn", f"Tải hóa đơn {invoice['invoice_code']} cho đơn thuê ID {rental_id}")

    return Response(
        invoice_to_text(invoice),
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/admin/export-rentals")
@permission_required("manage_rentals")
def export_rentals():
    conn = get_db()
    rentals = conn.execute(
        """
        SELECT rentals.id, rentals.rental_code, users.fullname, users.username, books.title, books.author,
               rentals.status, rentals.created_at, rentals.due_at, rentals.returned_at,
               rentals.updated_at, rentals.late_fee, rentals.note
        FROM rentals
        JOIN users ON rentals.user_id = users.id
        JOIN books ON rentals.book_id = books.id
        ORDER BY rentals.id DESC
        """
    ).fetchall()
    conn.close()

    headers = [
        "ID", "Mã đơn thuê", "Họ tên", "Tài khoản", "Tên sách", "Tác giả",
        "Trạng thái", "Ngày tạo", "Hạn trả", "Ngày trả", "Ngày cập nhật",
        "Phí quá hạn", "Ghi chú"
    ]
    lines = [";".join(headers)]

    for item in rentals:
        values = [
            item["id"], item["rental_code"] or "", item["fullname"] or "", item["username"] or "",
            item["title"] or "", item["author"] or "", item["status"] or "",
            item["created_at"] or "", item["due_at"] or "", item["returned_at"] or "",
            item["updated_at"] or "", item["late_fee"] or 0, item["note"] or "",
        ]
        safe_values = []
        for value in values:
            text = str(value).replace('"', '""')
            safe_values.append(f'"{text}"')
        lines.append(";".join(safe_values))

    content = "\ufeff" + "\n".join(lines)
    filename = f"danh_sach_don_thue_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    log_action("Xuất CSV", "Xuất danh sách đơn thuê định dạng CSV")

    return Response(
        content,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/admin/audit-logs")
@permission_required("manage_users")
def audit_logs():
    conn = get_db()
    logs = conn.execute(
        """
        SELECT audit_logs.*, users.fullname, users.username
        FROM audit_logs
        LEFT JOIN users ON audit_logs.user_id = users.id
        ORDER BY audit_logs.id DESC
        LIMIT 100
        """
    ).fetchall()
    conn.close()
    return render_template("audit_logs.html", logs=logs)


@app.route("/admin/backup-db")
@permission_required("manage_users")
def backup_db():
    if not os.path.exists(DATABASE):
        init_db()
    log_action("Sao lưu database", "Admin tải file database.db")
    return send_file(DATABASE, as_attachment=True, download_name="database_backup.db")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)

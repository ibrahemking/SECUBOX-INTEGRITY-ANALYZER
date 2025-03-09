import os
import sqlite3
import subprocess
import bcrypt
import base64
import hashlib
from flask import Flask, request, render_template, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename
from flask import send_from_directory
from flask import send_file
import zipfile
import tempfile
from flask import session
from datetime import datetime
import json
from flask import jsonify
import logging
import mimetypes  # مكتبة لتحديد نوع الملف
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes






logging.basicConfig(
    level=logging.DEBUG,  # يمكنك تعديل المستوى إلى DEBUG للتفاصيل
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)




# إعداد التطبيق وتهيئة الإعدادات
app = Flask(__name__)

# Secret key
app.secret_key = b'\xfa\x9f\xd3\xb2\xd4\xd3...'  # المفتاح العشوائي
UPLOAD_FOLDER = 'uploads'  # المجلد الأساسي
PROJECTS_FOLDER_NAME = 'projects'  # مجلد المشاريع
REPORTS_FOLDER_NAME = 'reports'  # مجلد التقارير
ALLOWED_EXTENSIONS = {
    'py', 'cpp', 'c', 'cs', 'java', 'js', 'ts', 'php', 'rb', 'rs', 'go', 'swift',
    'scala', 'json', 'yaml', 'yml', 'sol', 'dockerfile', 'tf', 'kt', 'sh', 'el',
    'ml', 'html', 'pl', 'lua', 'tsx', 'cmake', 'bash', 'ps1', 'm', 'dart'
}


app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def connect_db():
    conn = sqlite3.connect('users_database.db')
    conn.execute("PRAGMA foreign_keys = ON")  # تفعيل المفاتيح الخارجية
    return conn

def setup_db():
    conn = connect_db()
    cursor = conn.cursor()
    
    # إنشاء جدول المستخدمين
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # إنشاء جدول المشاريع
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            project_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            project_name TEXT NOT NULL,
            uploaded_file_path TEXT NOT NULL,
            language TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
        )
    ''')

    # إنشاء جدول التقارير مع تعديل project_id وتفعيل ON DELETE SET NULL
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            report_id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,  -- السماح بالقيم NULL
            tool_name TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects (project_id) ON DELETE SET NULL
        )
    ''')

    conn.commit()
    conn.close()



# تحديد تنسيق التاريخ
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    return datetime.fromtimestamp(value).strftime(format)


# التحقق من الملفات المسموح بها
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Create user folder
def create_user_folder(username):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    os.makedirs(user_folder, exist_ok=True)

# Main Route
@app.route('/')
def home():
    return render_template('welcome.html')

# صفحة تسجيل الدخول
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')

        conn = connect_db()
        cursor = conn.cursor()

        if "@" in identifier:
            cursor.execute('SELECT password, salt FROM users WHERE email = ?', (identifier,))
        else:
            cursor.execute('SELECT password, salt FROM users WHERE username = ?', (identifier,))

        result = cursor.fetchone()
        conn.close()

        if result:
            stored_password, stored_salt = result
            stored_salt = bytes.fromhex(stored_salt)  # تحويل `Salt` من نص إلى `Bytes`

            # ✅ التحقق من صحة كلمة المرور
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                # 🔑 اشتقاق مفتاح التشفير من كلمة المرور المدخلة
                encryption_key = derive_key_from_password(password, stored_salt)

                # 🗄️ حفظ اسم المستخدم والمفتاح في الجلسة لاستخدامه لاحقًا
                session['username'] = identifier
                session['encryption_key'] = encryption_key.decode()  # تخزينه كنص يمكن قراءته

                return redirect(url_for('analysis'))
            else:
                flash("Invalid password.", "error")
        else:
            flash("Username or email not registered.", "error")

    return render_template('login.html')





# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)  # حذف اسم المستخدم من الجلسة
    flash("Logged out successfully!", "success")
    return redirect(url_for('home'))


# Singnup 
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # 🧂 توليد `Salt` عشوائي لكل مستخدم جديد
        salt = os.urandom(16)

        # 🔒 تشفير كلمة المرور باستخدام `bcrypt`
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        try:
            conn = connect_db()
            cursor = conn.cursor()

            # إدخال بيانات المستخدم في جدول `users` مع تخزين الملح (`Salt`)
            cursor.execute('INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)', 
                           (username, email, hashed_password, salt.hex()))

            conn.commit()
            conn.close()

            # إنشاء مجلد للمستخدم
            create_user_folder(username)

            flash("Account created successfully!", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "error")

    return render_template('signup.html')


################################################################################################################################
###############################
# 
# Encrption
#
###############################
def derive_key_from_password(password: str, salt: bytes):
    """ 🔑 اشتقاق مفتاح التشفير من كلمة المرور باستخدام PBKDF2 """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # طول المفتاح (256-bit)
        salt=salt,
        iterations=100000  # عدد التكرارات
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def get_encryption_key(username):
    """ استرجاع مفتاح التشفير الخاص بالمستخدم من قاعدة البيانات """
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT encryption_keys.user_key 
        FROM encryption_keys 
        JOIN users ON users.user_id = encryption_keys.user_id 
        WHERE users.username = ?
    """, (username,))
    key = cursor.fetchone()
    conn.close()
    return key[0] if key else None


def encrypt_file(file_path, encryption_key):
    """ 🔐 تشفير الملف باستخدام مفتاح التشفير المستخرج من كلمة المرور """
    fernet = Fernet(encryption_key)

    with open(file_path, 'rb') as file:
        original_data = file.read()

    encrypted_data = fernet.encrypt(original_data)

    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

    print("✅ تم تشفير الملف:", file_path)



def decrypt_file(file_path, encryption_key):
    """ 🔓 فك تشفير الملف باستخدام مفتاح التشفير المستخرج من كلمة المرور """
    fernet = Fernet(encryption_key)

    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    with open(file_path, 'wb') as file:
        file.write(decrypted_data)

    print("✅ تم فك تشفير الملف:", file_path)


def decrypt_file_content(file_path, encryption_key):
    """ فك تشفير محتوى الملف وإعادته كنص """
    fernet = Fernet(encryption_key.encode())

    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        return decrypted_data.decode("utf-8")  # تحويل البيانات المفكوكة إلى نص
    except InvalidToken:
        logging.error("⚠️ الملف ليس مشفرًا أو مفتاح التشفير غير متطابق!")
        return encrypted_data.decode("utf-8")  # إعادة المحتوى كما هو دون فك التشفير




################################################################################################################################
###############################
# 
# Whitebox
#
###############################
@app.route('/analysis', methods=['GET', 'POST'])
def analysis():
    logging.debug("بدء دالة analysis")
    username = session.get('username', 'Guest')
    if username == 'Guest':
        logging.debug("المستخدم غير مسجل، إعادة التوجيه لصفحة تسجيل الدخول")
        flash("Please log in to access this page.", "error")
        return redirect(url_for('login'))

    # 🔹 جلب مفتاح التشفير من `session`
    encryption_key = session.get('encryption_key')
    if not encryption_key:
        logging.error("❌ مفتاح التشفير غير متوفر في `session`!")
        flash("Encryption key not found. Please log in again.", "error")
        return redirect(url_for('login'))

    # إعداد المسارات وإنشاء المجلدات
    user_folder = os.path.join(UPLOAD_FOLDER, username)
    projects_folder = os.path.join(user_folder, PROJECTS_FOLDER_NAME)
    reports_folder = os.path.join(user_folder, "reports_whitebox")
    os.makedirs(projects_folder, exist_ok=True)
    os.makedirs(reports_folder, exist_ok=True)
    logging.debug(f"المجلدات جاهزة: {projects_folder}, {reports_folder}")

    extension_language_map = {
        '.py': 'Python', '.cpp': 'C++', '.c': 'C', '.cs': 'C#', '.java': 'Java',
        '.js': 'JavaScript', '.ts': 'TypeScript', '.php': 'PHP', '.rb': 'Ruby',
        '.rs': 'Rust', '.go': 'Go', '.swift': 'Swift', '.scala': 'Scala',
        '.json': 'JSON', '.yaml': 'YAML', '.yml': 'YAML', '.sol': 'Solidity',
        '.dockerfile': 'Dockerfile', '.tf': 'Terraform', '.kt': 'Kotlin',
        '.sh': 'Shell', '.bash': 'Bash', '.el': 'Elixir', '.ml': 'OCaml',
        '.html': 'HTML', '.pl': 'Perl', '.lua': 'Lua', '.tsx': 'TypeScript (React)',
        '.cmake': 'CMake', '.ps1': 'PowerShell', '.m': 'Objective-C', '.dart': 'Dart'
    }

    if request.method == 'POST' and 'file' in request.files:
        logging.debug("تم إرسال نموذج رفع ملف")
        file = request.files['file']
        services = request.form.getlist('services[]')
        report_type = request.form.get('report_type', 'html')

        if file.filename == '':
            logging.debug("لم يتم اختيار ملف")
            flash("No file selected!", "error")
            return redirect(request.url)

        if not allowed_file(file.filename):
            logging.debug(f"نوع الملف غير مسموح: {file.filename}")
            flash("Unsupported file type!", "error")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        file_path = os.path.join(projects_folder, filename)

        # 🔹 منع إعادة الحفظ إذا كان الملف موجودًا
        if not os.path.exists(file_path):
            file.save(file_path)
            logging.debug(f"تم حفظ الملف: {file_path}")

        # حساب الهاش للملف
        file_hash = calculate_sha256(file_path)

        try:
            conn = connect_db()
            cursor = conn.cursor()

            # جلب user_id من قاعدة البيانات
            cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            if not user:
                logging.error("المستخدم غير موجود في قاعدة البيانات")
                flash("User not found in the database.", "error")
                return redirect(request.url)

            user_id = user[0]
            logging.debug(f"user_id: {user_id}")

            # تحديد لغة الملف
            file_extension = os.path.splitext(filename)[1].lower()
            language = extension_language_map.get(file_extension, 'Unknown')

            # 🔹 إجراء الفحص قبل التشفير
            for tool in services:
                logging.debug(f"معالجة الأداة: {tool}")
                report_path = None

                if tool == "Flawfinder":
                    report_path = run_flawfinder(file_path, reports_folder, report_type)
                elif tool == "Bandit":
                    report_name = f"{os.path.splitext(filename)[0]}_bandit.{report_type}"
                    report_path = os.path.join(reports_folder, report_name)
                    run_bandit(file_path, report_type, report_path)
                elif tool == "Semgrep":
                    try:
                        report_path = run_semgrep(file_path, reports_folder, user_id, conn)
                    except Exception as e:
                        logging.exception("Exception during Semgrep analysis")
                        flash(f"Semgrep analysis encountered an error: {str(e)}", "error")

                # 🔹 تشفير التقرير إذا كان من `reports_whitebox`
                if report_path and "reports_whitebox" in report_path:
                    encrypt_file(report_path, encryption_key)  # 🔐 تشفير التقرير
                    logging.debug(f"تم تشفير التقرير: {report_path}")

                # حساب الهاش للتقرير
                if report_path:
                    report_hash = calculate_sha256(report_path)

                    # حفظ تقرير التحليل في قاعدة البيانات إذا تم إنشاؤه
                    cursor.execute(
                        '''
                        INSERT INTO reports (project_id, user_id, project_name, tool_name, details, created_at, updated_at, file_hash)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
                        ''',
                        (user_id, user_id, filename, tool, report_path, report_hash)
                    )
                    flash(f"{tool} analysis completed: {os.path.basename(report_path)}", "success")

            # 🔹 الآن يتم **تشفير الملف بعد انتهاء الفحص**
            encrypt_file(file_path, encryption_key)  # 🔐 تشفير الملف بعد الفحص
            logging.debug(f"تم تشفير الملف: {file_path}")

            # 🔹 تسجيل المشروع بعد الفحص والتشفير
            cursor.execute(
                '''
                INSERT INTO projects (user_id, project_name, uploaded_file_path, language, status, file_hash)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (user_id, filename, file_path, language, 'Analyzed', file_hash)
            )
            conn.commit()
            conn.close()

            logging.debug("تم حفظ بيانات المشروع والتقارير في قاعدة البيانات")
        except Exception as e:
            logging.exception("Error during analysis process")
            flash(f"Error during analysis: {str(e)}", "error")

    # استرجاع المشاريع والتقارير
    try:
        conn = connect_db()
        cursor = conn.cursor()

        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        user_id = user[0] if user else None

        # استرجاع التقارير
        cursor.execute(
            '''
            SELECT details, tool_name, created_at, project_name, file_hash
            FROM reports
            WHERE user_id = ?
            ''',
            (user_id,)
        )
        reports = cursor.fetchall()
        logging.debug(f"عدد التقارير المسترجعة: {len(reports)}")

        # استرجاع المشاريع
        cursor.execute(
            '''
            SELECT project_id, project_name, uploaded_file_path, language, created_at, file_hash
            FROM projects
            WHERE user_id = ?
            ''',
            (user_id,)
        )
        projects = cursor.fetchall()
        logging.debug(f"عدد المشاريع المسترجعة: {len(projects)}")

        conn.close()
    except Exception as e:
        logging.exception("Error fetching reports/projects")
        reports, projects = [], []

    logging.debug("إنهاء دالة analysis والانتقال للعرض")
    return render_template('analysis.html', username=username, reports=reports, projects=projects)

def calculate_sha256(file_path):
    """ يحسب SHA-256 لأي ملف """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()







def escapejs_filter(s):
    if s is None:
        return ''
    # بديل بسيط لهروب علامات الاقتباس؛ يمكنك تحسينه حسب الحاجة
    return s.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')

app.jinja_env.filters['escapejs'] = escapejs_filter

################################################################################################################################


def convert_json_to_html(json_path, html_path):
    """
    تحويل تقرير Semgrep من JSON إلى HTML باستخدام تصميم index.html.
    """
    try:
        with open(json_path, 'r', encoding="utf-8") as f:
            report_data = json.load(f)

        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Your Security Report</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-black text-green-400 font-mono">
            <div class="container mx-auto p-5">
                <h1 class="text-2xl text-green-500 font-bold text-center mb-5">🔍 Security Scan Report</h1>
                <div id="report-container" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        """

        findings = report_data.get("results", [])
        if not findings:
            html_content += '<p class="text-center text-white">No vulnerabilities found.</p>'
        else:
            for result in findings:
                check_id = result.get("check_id", "N/A")
                file_path = result.get("path", "N/A")
                severity = result.get("extra", {}).get("severity", "Unknown")
                message = result.get("extra", {}).get("message", "No details")
                metadata = result.get("extra", {}).get("metadata", {})

                cwe = metadata.get("cwe", "N/A")
                if isinstance(cwe, list):
                    cwe = ", ".join(cwe)

                references = metadata.get("references", [])
                references_html = " ".join([f'<a href="{ref}" target="_blank" class="text-blue-400 underline">[Ref]</a>' for ref in references]) if references else "N/A"

                vuln_class = metadata.get("vulnerability_class", "N/A")
                if isinstance(vuln_class, list):
                    vuln_class = ", ".join(vuln_class)

                likelihood = metadata.get("likelihood", "N/A")
                impact = metadata.get("impact", "N/A")
                confidence = metadata.get("confidence", "N/A")
                source_link = metadata.get("shortlink") or metadata.get("source") or "N/A"

                html_content += f"""
                <div class="bg-gray-900 text-green-400 p-4 m-2 rounded-lg border border-green-500 shadow-lg">
                    <h2 class="text-xl font-bold text-green-300 mb-2">{check_id}</h2>
                    <p class="text-sm text-gray-300 mb-1">📁 <strong>File:</strong> <span class="text-green-500">{file_path}</span></p>
                    <p class="text-sm mb-1">⚠️ <strong>Severity:</strong> {severity}</p>
                    <p class="text-sm mb-1">🔎 <strong>Details:</strong> {message}</p>
                    <p class="text-sm mb-1">📌 <strong>CWE:</strong> {cwe}</p>
                    <p class="text-sm mb-1">🔗 <strong>References:</strong> {references_html}</p>
                    <p class="text-sm mb-1">🛑 <strong>Vulnerability Class:</strong> {vuln_class}</p>
                    <p class="text-sm mb-1">📉 <strong>Likelihood:</strong> {likelihood}</p>
                    <p class="text-sm mb-1">💥 <strong>Impact:</strong> {impact}</p>
                    <p class="text-sm mb-1">🔍 <strong>Confidence:</strong> {confidence}</p>
                    <p class="text-sm mb-1">🔗 <strong>Source:</strong> <a href="{source_link}" target="_blank" class="text-blue-400 underline">View Rule</a></p>
                </div>
                """

        html_content += """
                </div>
            </div>
        </body>
        </html>
        """

        with open(html_path, 'w', encoding="utf-8") as f:
            f.write(html_content)

        print(f"✅ HTML report saved: {html_path}")

    except Exception as e:
        print(f"❌ Error converting JSON to HTML: {e}")

######################################################################################################
# View Project
@app.route('/view-project/<username>/<path:filename>')
def view_project(username, filename):
    project_path = os.path.join(app.root_path, 'uploads', username, 'projects', filename)
    
    if not os.path.exists(project_path):
        return jsonify({"error": "File not found"}), 404

    # 🔹 جلب مفتاح التشفير من `session` بدلاً من قاعدة البيانات
    encryption_key = session.get('encryption_key')
    if not encryption_key:
        logging.error("❌ مفتاح التشفير غير متوفر في `session`!")
        return jsonify({"error": "Encryption key not found. Please log in again."}), 500

    try:
        # 🔐 فك تشفير المحتوى فقط إذا كان مشفرًا
        content = decrypt_file_content(project_path, encryption_key)
        return jsonify({"content": content, "filename": filename}), 200
    except Exception as e:
        logging.exception("Error decrypting project file")
        return jsonify({"error": f"Error reading file: {str(e)}"}), 500



# Download Project
@app.route('/download_project')
def download_project():
    project_id = request.args.get('project_id')
    if not project_id:
        flash("Project ID not provided.", "error")
        return redirect(url_for('analysis'))

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT users.username, projects.uploaded_file_path 
        FROM projects 
        JOIN users ON users.user_id = projects.user_id 
        WHERE projects.project_id = ?
    """, (project_id,))
    project = cursor.fetchone()
    conn.close()

    if not project:
        flash("Project not found.", "error")
        return redirect(url_for('analysis'))

    username, file_path = project
    if not os.path.exists(file_path):
        flash("Project file not found.", "error")
        return redirect(url_for('analysis'))

    # 🔹 جلب مفتاح التشفير من `session` بدلاً من قاعدة البيانات
    encryption_key = session.get('encryption_key')
    if not encryption_key:
        logging.error("❌ مفتاح التشفير غير متوفر في `session`!")
        flash("Encryption key not found. Please log in again.", "error")
        return redirect(url_for('analysis'))

    # 🔐 فك تشفير الملف قبل إرساله
    decrypt_file(file_path, encryption_key)
    logging.debug(f"✅ تم فك تشفير الملف: {file_path}")

    return send_file(file_path, as_attachment=True)




# Delete Project
@app.route('/delete_project/<int:project_id>', methods=['POST'])
def delete_project(project_id):
    conn = connect_db()
    cursor = conn.cursor()
    
    # التحقق مما إذا كان المشروع موجودًا
    cursor.execute("SELECT uploaded_file_path FROM projects WHERE project_id = ?", (project_id,))
    project = cursor.fetchone()
    
    if project:
        file_path = project[0]
        if os.path.exists(file_path):
            os.remove(file_path)  # حذف الملف من المجلد
        cursor.execute("DELETE FROM projects WHERE project_id = ?", (project_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True})  # إرجاع JSON للواجهة
    else:
        conn.close()
        return jsonify({"success": False})



###########################################################################################################
# Download Report
@app.route('/download_report')
def download_report():
    report_path = request.args.get('report_path')  # الحصول على مسار التقرير

    if not report_path:
        flash("Invalid request: No report path provided.", "error")
        return redirect(url_for('analysis'))

    # التأكد من أن المسار لا يحتوي على تكرار غير ضروري
    sanitized_report_path = report_path.replace("uploads/" + report_path, "uploads/")

    # تحديد المسار الصحيح
    full_report_path = os.path.join(app.root_path, sanitized_report_path)

    # التحقق من وجود التقرير
    if not os.path.exists(full_report_path):
        flash("Report not found!", "error")
        return redirect(url_for('analysis'))

    # 🔹 التحقق مما إذا كان التقرير يخص `reports_whitebox`
    if "reports_whitebox" in report_path:
        # 🔹 جلب مفتاح التشفير من `session`
        encryption_key = session.get('encryption_key')
        if not encryption_key:
            logging.error("❌ مفتاح التشفير غير متوفر في `session`!")
            flash("Encryption key not found. Please log in again.", "error")
            return redirect(url_for('login'))

        # 🔐 فك تشفير التقرير قبل إرساله
        decrypt_file(full_report_path, encryption_key)
        logging.debug(f"✅ تم فك تشفير التقرير: {full_report_path}")

    return send_file(full_report_path, as_attachment=True)




# # View Report
@app.route('/view-report/<username>/<report_type>/<path:filename>')
def view_report(username, report_type, filename):
    # التأكد من عدم وجود "uploads/username/reports_whitebox/" مرتين في المسار
    sanitized_filename = filename.replace(f"uploads/{username}/{report_type}/", "")

    # تحديد المسار الصحيح للتقرير
    report_path = os.path.join(app.root_path, 'uploads', username, report_type, sanitized_filename)

    # التحقق من وجود التقرير
    if not os.path.exists(report_path):
        return jsonify({"error": "Report not found!", "path": report_path}), 404

    # 🔹 إذا كان التقرير يخص `reports_whitebox`، نقوم بفك تشفيره قبل عرضه
    if report_type == "reports_whitebox":
        # 🔹 جلب مفتاح التشفير من `session`
        encryption_key = session.get('encryption_key')
        if not encryption_key:
            logging.error("❌ مفتاح التشفير غير متوفر في `session`!")
            return jsonify({"error": "Encryption key not found. Please log in again."}), 500

        try:
            # 🔐 فك تشفير المحتوى مباشرة قبل الإرسال
            content = decrypt_file_content(report_path, encryption_key)

            # 🔹 إذا كان التقرير بصيغة HTML، أرسله كـ `text/html`
            if sanitized_filename.endswith('.html'):
                return content, 200, {'Content-Type': 'text/html'}

            # إذا لم يكن HTML، أرسله كـ JSON
            return jsonify({"success": True, "filename": sanitized_filename, "content": content}), 200
        except Exception as e:
            logging.exception("Error decrypting report file")
            return jsonify({"error": f"Error reading report: {str(e)}"}), 500

    # إذا كان التقرير بصيغة HTML ولكنه ليس مشفرًا، قدّمه مباشرة
    if sanitized_filename.endswith('.html'):
        return send_file(report_path, mimetype='text/html')

    try:
        with open(report_path, 'r', encoding="utf-8") as file:
            content = file.read()  # قراءة محتوى التقرير

        return jsonify({"success": True, "filename": sanitized_filename, "content": content}), 200
    except Exception as e:
        return jsonify({"error": f"Error reading report: {str(e)}"}), 500




# Delete Report
@app.route('/delete-report/<username>/<report_type>/<filename>', methods=['POST'])
def delete_report(username, report_type, filename):
    # تحديد المسار الصحيح للتقرير
    report_path = os.path.join(app.root_path, 'uploads', username, report_type, filename)

    try:
        if os.path.exists(report_path):
            os.remove(report_path)  # حذف الملف من النظام

            # حذف التقرير من قاعدة البيانات إذا كان من نوع whitebox
            if report_type == "reports_whitebox":
                conn = connect_db()
                cursor = conn.cursor()
                cursor.execute(
                    '''
                    DELETE FROM reports
                    WHERE details LIKE ?
                    ''',
                    (f"%{filename}",)  # البحث عن اسم الملف فقط داخل مسار التفاصيل
                )
                conn.commit()
                conn.close()

            return jsonify({"success": True, "message": f"Report '{filename}' has been deleted successfully."}), 200
        else:
            return jsonify({"success": False, "message": f"Report '{filename}' not found."}), 404

    except Exception as e:
        return jsonify({"success": False, "message": f"Error deleting the report: {str(e)}"}), 500


################################################################################################################################################################################

###############################
# 
# Tools Whitebox
#
###############################
def run_flawfinder(file_path, reports_folder, report_type):
    flawfinder_script = os.path.join(os.getcwd(), 'flawfinder')  # مسار أداة Flawfinder
    base_name = os.path.splitext(os.path.basename(file_path))[0]  # اسم الملف بدون الامتداد
    output_path = os.path.join(reports_folder, f"{base_name}.{report_type}")  # مسار التقرير النهائي

    command = f"python {flawfinder_script} --columns --{report_type} {file_path} > {output_path}"
    subprocess.run(command, shell=True, check=True)
    return output_path



def run_bandit(file_path, report_type, output_path):
    command = f"bandit -r {file_path} --format {report_type} -o {output_path}"
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running Bandit: {e}")



def run_semgrep(file_path, reports_folder, project_id, conn):
    """
    تشغيل أداة Semgrep، حفظ التقرير بصيغة JSON، وتحويله إلى HTML.
    
    :param file_path: مسار الملف المراد تحليله.
    :param reports_folder: مجلد التقارير.
    :param project_id: معرف المشروع المرتبط بالتقرير.
    :param conn: اتصال قاعدة البيانات.
    :return: مسار التقرير النهائي.
    """
    try:
        base_name, file_extension = os.path.splitext(os.path.basename(file_path))  # استخراج الاسم والامتداد
        json_report_path = os.path.join(reports_folder, f"{base_name}_semgrep.json")  # تقرير JSON
        html_report_path = os.path.join(reports_folder, f"{base_name}_semgrep.html")  # تقرير HTML

        # **خريطة الامتدادات إلى مجلدات Semgrep**
        language_folders = {
            '.py': 'python',
            '.cpp': 'c',  
            '.c': 'c',
            '.cs': 'csharp',
            '.java': 'java',
            '.js': 'javascript',
            '.ts': 'javascript',
            '.tsx': 'typescript',
            '.php': 'php',
            '.rb': 'ruby',
            '.rs': 'rust',
            '.go': 'go',
            '.swift': 'swift',
            '.scala': 'scala',
            '.json': 'json',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.sol': 'solidity',
            '.dockerfile': 'dockerfile',
            '.tf': 'terraform',
            '.kt': 'kotlin',
            '.sh': 'bash',
            '.bash': 'bash',
            '.el': 'elixir',
            '.ml': 'ocaml',
            '.html': 'html',
            '.pl': 'perl',
            '.lua': 'lua',
            '.cmake': 'cmake',
            '.ps1': 'powershell',
            '.m': 'objective-c',
            '.dart': 'dart'
        }
        # تحديد المجلد المناسب داخل `semgrep-rules`
        semgrep_rules_folder = language_folders.get(file_extension, None)

        # إذا لم يتم العثور على مجلد مطابق، استخدم `semgrep-rules` كافتراضي
        semgrep_config_path = f"./semgrep-rules/{semgrep_rules_folder}" if semgrep_rules_folder else "./semgrep-rules"

        # أمر تشغيل Semgrep
        semgrep_command = [
            "/home/king/central-venv/central-env/bin/semgrep",
            "--config", "auto",
            "--config", semgrep_config_path,  # إضافة مجلد القواعد المناسب
            "--max-memory", "0",
            "--timeout", "0",
            "--json",
            file_path
        ]

        with open(json_report_path, "w") as output_file:
            subprocess.run(semgrep_command, check=True, stdout=output_file, stderr=subprocess.PIPE, text=True)

        # تحويل JSON إلى HTML
        convert_json_to_html(json_report_path, html_report_path)

        # تحديث قاعدة البيانات
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO reports (project_id, tool_name, details, created_at, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', (project_id, 'Semgrep', html_report_path))
        conn.commit()

        print(f"✅ Semgrep analysis completed and saved to database: {html_report_path}")

        return html_report_path

    except subprocess.CalledProcessError as e:
        print(f"❌ Error running Semgrep: {e.stderr}")
        return None

    except Exception as e:
        print(f"❌ Unexpected error in Semgrep analysis: {e}")
        return None





###############################
# 
# BlackBox
#
###############################
@app.route('/analysis-black', methods=['GET', 'POST'])
def analysis_black():
    username = session.get('username', 'Guest')

    if username == 'Guest':
        flash("Please log in to access this page.", "error")
        return redirect(url_for('login'))

    # إعداد مسار التقارير
    reports_folder = os.path.join(UPLOAD_FOLDER, username, "reports_blackbox")
    os.makedirs(reports_folder, exist_ok=True)

    # إذا كان هناك عملية فحص جديدة
    if request.method == 'POST':
        url = request.form.get('url')
        scan_type = request.form.get('scan_type')

        if not url or not scan_type:
            flash("Please provide a valid URL and select a scan type.", "error")
            return redirect(request.url)

        # استخراج اسم الموقع من الرابط
        site_name = url.replace("https://", "").replace("http://", "").split("/")[0]
        site_folder = os.path.join(reports_folder, site_name)  # مجلد الموقع
        os.makedirs(site_folder, exist_ok=True)

        # مسارات التقارير
        json_output_file = os.path.join(site_folder, f"{site_name}_{scan_type}.json")
        html_output_file = os.path.join(site_folder, f"{site_name}_{scan_type}.html")

        # تحديد الأوامر بناءً على نوع الفحص
        command = f"nuclei -u {url} -t ~/.nuclei-templates/ -json-export {json_output_file}"
        
        
        if scan_type == "normal":
            command += ""
        elif scan_type == "delayed":
            command += " -rate-limit 10 -H 'User-Agent: Mozilla/5.0' -silent"
        elif scan_type == "comprehensive":
            command += " -tags cve,misconfiguration,exposure -rate-limit 30 -H 'User-Agent: Mozilla/5.0' -silent"
        elif scan_type == "fast":
            command += " -severity low,medium -rate-limit 50 -H 'User-Agent: Mozilla/5.0' -silent"
        elif scan_type == "advanced":
            command += " -tags xss,sqli,ssrf -severity medium,high -rate-limit 20 -H 'User-Agent: Mozilla/5.0' -silent"

        # تشغيل الفحص
        try:
            subprocess.run(command, shell=True, check=True)

            # تشغيل script.py لتحويل JSON إلى HTML
            if os.path.exists(json_output_file):
                script_command = f"python script.py {json_output_file} {html_output_file}"
                result = subprocess.run(script_command, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    flash(f"Scan completed successfully for {site_name}! Reports saved as JSON and HTML.", "success")
                else:
                    flash(f"Failed to generate HTML report. Error: {result.stderr}", "error")
            else:
                flash("Scan completed but the JSON report could not be saved.", "error")

        except subprocess.CalledProcessError as e:
            flash(f"Error during scan: {str(e)}", "error")

    # **تنظيم التقارير حسب المواقع**
    sites_reports = {}
    for site in os.listdir(reports_folder):
        site_path = os.path.join(reports_folder, site)
        if os.path.isdir(site_path):  # تأكد أنه مجلد وليس ملف
            reports = []
            for report_file in os.listdir(site_path):
                report_path = os.path.join(site_path, report_file)
                if os.path.isfile(report_path):
                    created_at = os.path.getctime(report_path)  # توقيت الإنشاء
                    is_html = report_file.endswith(".html")
                    is_json = report_file.endswith(".json")
                    reports.append({
                        "name": report_file,
                        "path": report_path,
                        "created_at": created_at,
                        "type": "HTML" if is_html else "JSON" if is_json else "Unknown"
                    })
            reports.sort(key=lambda x: x["created_at"], reverse=True)
            sites_reports[site] = reports  # حفظ التقارير تحت اسم الموقع

    return render_template('analysis-black.html', username=username, sites_reports=sites_reports)

# Serve uploaded reports 
@app.route('/uploads/<username>/<report_type>/<path:filename>')
def serve_uploads(username, report_type, filename):
    # تحديد المسار الكامل للتقرير
    report_path = os.path.join(app.root_path, 'uploads', username, report_type, filename)

    # التحقق من وجود الملف
    if not os.path.exists(report_path):
        flash("The requested report does not exist or has been deleted.", "error")
        # إعادة التوجيه إلى الصفحة المناسبة
        if report_type == "reports_blackbox":
            return redirect(url_for('analysis_black'))
        elif report_type == "reports_whitebox":
            return redirect(url_for('analysis'))

    # تقديم الملف إذا كان موجودًا
    return send_from_directory(os.path.join(app.root_path, 'uploads', username, report_type), filename)


# Delete blackbox report 
@app.route('/delete-blackbox-report/<username>/<path:filename>', methods=['POST'])
def delete_blackbox_report(username, filename):
    """
    حذف تقرير الفاحص الأسود داخل المسار الصحيح للمجلدات وإعادة التوجيه للصفحة بدون JSON.
    """
    try:
        # استخراج الموقع من `filename`
        parts = filename.split('/')
        if len(parts) < 2:
            return redirect(url_for('analysis_black'))

        site_name = parts[0]  # استخراج اسم الموقع
        actual_filename = '/'.join(parts[1:])  # استخراج اسم الملف بدون الموقع

        # تحديد المسار الصحيح داخل `reports_blackbox`
        report_path = os.path.join(app.root_path, 'uploads', username, "reports_blackbox", site_name, actual_filename)

        print(f"🔍 Attempting to delete: {report_path}")  # DEBUGGING

        # التحقق مما إذا كان الملف موجودًا ثم حذفه
        if os.path.exists(report_path):
            os.remove(report_path)  # حذف التقرير من الملفات
            print(f"✅ Deleted successfully: {report_path}")  # DEBUGGING
        else:
            print(f"⚠️ File not found: {report_path}")  # DEBUGGING
            return redirect(url_for('analysis_black'))

        return redirect(url_for('analysis_black'))  # ✅ إعادة التوجيه بعد الحذف

    except Exception as e:
        print(f"❌ Error deleting report: {str(e)}")  # DEBUGGING
        return redirect(url_for('analysis_black'))



if __name__ == '__main__':
    setup_db()
    app.run(debug=True)
    # app.run(host='0.0.0.0', port=5000, debug=True)

import json
from jinja2 import Environment, FileSystemLoader
import os
import sys

# تحديد المسار الكامل للقالب ومجلد الإخراج
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # جذر المشروع
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")  # مسار القوالب
OUTPUT_DIR = os.path.join(BASE_DIR, "reports_blackbox")  # مسار تخزين التقارير

# التأكد من وجود مجلد الإخراج
os.makedirs(OUTPUT_DIR, exist_ok=True)

# تحميل القالب باستخدام Jinja2
env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
template = env.get_template("template.html")

# قراءة ملف JSON
def load_json(json_file):
    try:
        with open(json_file, "r") as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        print(f"خطأ: الملف '{json_file}' غير موجود.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"خطأ: الملف '{json_file}' ليس ملف JSON صالح.")
        sys.exit(1)

# التأكد من وجود matched-at
def enrich_data_with_urls(data):
    for vuln in data:
        if "matched-at" not in vuln or not vuln["matched-at"]:
            vuln["matched-at"] = "https://example.com/no-url-provided"
    return data

# إنشاء تقرير HTML
def generate_html(data, output_file):
    html_content = template.render(vulnerabilities=data, year=2025)  # تمرير السنة الحالية
    with open(output_file, "w") as file:
        file.write(html_content)

if __name__ == "__main__":
    # التحقق من وجود معامل ملف JSON
    if len(sys.argv) != 3:
        print("الاستخدام: python script.py <اسم ملف JSON> <اسم ملف HTML>")
        sys.exit(1)

    # الحصول على اسم ملف JSON واسم ملف HTML من المعاملات
    json_file = sys.argv[1]
    output_html_file = sys.argv[2]

    # تحميل البيانات من JSON
    json_data = load_json(json_file)

    # إثراء البيانات بالروابط
    enriched_data = enrich_data_with_urls(json_data)

    # إنشاء تقرير HTML
    generate_html(enriched_data, output_html_file)

    print(f"Created HTML report: {output_html_file}")

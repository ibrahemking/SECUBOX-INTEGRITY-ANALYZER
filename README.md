🛡️ SECUBOX INTEGRITY ANALYZER

📌 مقدمة
SECUBOX INTEGRITY ANALYZER هو نظام تحليل أمني متكامل يساعد على فحص الكود البرمجي وتحليل المواقع لاكتشاف الثغرات الأمنية باستخدام White-Box Testing و Black-Box Testing.

🔥 الميزات الرئيسية
✅ تحليل WhiteBox: يسمح للمستخدمين برفع مشاريعهم البرمجية وتحليلها باستخدام Flawfinder و Bandit و Semgrep.
✅ تحليل BlackBox: يمكن فحص مواقع الويب بإدخال عنوان URL واختيار نوع الفحص (Normal, Delayed, Comprehensive, Fast, Advanced).
✅ نظام تشفير قوي: يتم اشتقاق مفتاح التشفير من كلمة المرور باستخدام PBKDF2HMAC لحماية الملفات والتقارير.
✅ تقارير التحليل: يتم حفظ التقارير حاليًا بصيغة HTML فقط، مع إمكانية دعم JSON, CSV, SARIF مستقبلًا.
✅ واجهة سهلة الاستخدام: تعتمد على Flask في الخلفية و Tailwind CSS في الواجهة الأمامية.

🚀 التثبيت والتشغيل
1️⃣ المتطلبات الأساسية
Python 3.8+
Flask
SQLite3
Nuclei (لتحليل BlackBox)
Semgrep, Bandit, Flawfinder
2️⃣ تثبيت الحزم المطلوبة
pip install -r requirements.txt
3️⃣ تثبيت أداة Nuclei (لتحليل BlackBox)
sudo apt install nuclei -y
4️⃣ تحميل قوالب Nuclei ووضعها في المجلد /home/username
git clone https://github.com/projectdiscovery/nuclei-templates.git ~/.nuclei-templates
للتحقق من نجاح العملية:
ls ~/.nuclei-templates
5️⃣ تشغيل التطبيق
python app.py
ثم افتح المتصفح وانتقل إلى:
http://127.0.0.1:5000/
🔒 نظام التشفير والأمان
يعتمد SECUBOX INTEGRITY ANALYZER على تشفير البيانات لحماية الملفات والتقارير باستخدام اشتقاق مفتاح التشفير من كلمة المرور عبر خوارزمية: PBKDF2HMAC (Password-Based Key Derivation Function 2 with HMAC).

✅ كيف يعمل التشفير؟
عند تسجيل المستخدم، يتم اشتقاق مفتاح التشفير من كلمة المرور باستخدام PBKDF2HMAC.
يتم استخدام المفتاح الناتج لتشفير المشاريع والتقارير باستخدام Fernet.
عند الحاجة إلى فك التشفير، يتم إعادة اشتقاق المفتاح بنفس الطريقة باستخدام كلمة مرور المستخدم.
🔑 تفاصيل آلية التشفير
PBKDF2HMAC مع خوارزمية SHA256
Salt يتم إنشاؤه عشوائيًا لكل مستخدم وتخزينه بشكل آمن
100,000 تكرار لزيادة الأمان ضد الهجمات العنيفة (Brute Force)
طول المفتاح النهائي 32 bytes لاستخدامه مع Fernet
🔐 هذا يضمن أن الملفات والتقارير لا يمكن فك تشفيرها إلا باستخدام كلمة مرور المستخدم الأصلية. 🚀

⚙️ التقنيات المستخدمة
Back-end: Flask, SQLite, Werkzeug
Front-end: Tailwind CSS, JavaScript
Security Tools: Semgrep, Bandit, Flawfinder, Nuclei
Encryption: bcrypt, PBKDF2HMAC, Fernet
👥 المساهمة والتطوير
نرحب بالمساهمات في المشروع!
إذا كنت ترغب في المساهمة:

قم بعمل Fork للمستودع.
أنشئ Branch جديد للتحسينات أو الميزات.
أرسل Pull Request وسنراجعه.
📜 الترخيص
هذا المشروع متاح تحت رخصة MIT، مما يعني أنه يمكنك استخدامه بحرية مع الالتزام بشروط الرخصة.

💡 إذا كان لديك أي استفسارات أو اقتراحات، لا تتردد في التواصل معنا!



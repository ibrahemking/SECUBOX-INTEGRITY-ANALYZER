// الحصول على العناصر المطلوبة
const passwordInput = document.getElementById("login__password");
const confirmPasswordInput = document.getElementById("login__confirm-password");
const signUpButton = document.querySelector('input[type="submit"]');

// العناصر الخاصة بالتحقق من كلمة المرور
const criteria = {
    length: document.getElementById("length"),
    uppercase: document.getElementById("uppercase"),
    lowercase: document.getElementById("lowercase"),
    number: document.getElementById("number"),
    special: document.getElementById("special")
};

// التحقق من كلمة المرور وتحديث التحقق
function validatePassword() {
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    // التحقق من الشروط
    criteria.length.classList.toggle("valid", password.length >= 8);
    criteria.uppercase.classList.toggle("valid", /[A-Z]/.test(password));
    criteria.lowercase.classList.toggle("valid", /[a-z]/.test(password));
    criteria.number.classList.toggle("valid", /\d/.test(password));
    criteria.special.classList.toggle("valid", /[!@#$%^&*(),.?":{}|<>]/.test(password));

    // التحقق من تطابق كلمة المرور مع تأكيد كلمة المرور
    const isPasswordValid = password.length >= 8 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /\d/.test(password) && /[!@#$%^&*(),.?":{}|<>]/.test(password);
    const isPasswordMatch = password === confirmPassword;

    // تمكين أو تعطيل زر التسجيل
    signUpButton.disabled = !(isPasswordValid && isPasswordMatch);
}

// إضافة الأحداث عند الكتابة في كلا الحقلين
passwordInput.addEventListener("input", validatePassword);
confirmPasswordInput.addEventListener("input", validatePassword);

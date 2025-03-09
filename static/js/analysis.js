function updateFileName() {
  const fileInput = document.getElementById('file');
  const fileNameDisplay = document.getElementById('file-name');
  const fileNameText = document.getElementById('file-name-text');

  // التأكد من وجود ملف محدد
  if (fileInput.files.length > 0) {
      const fileName = fileInput.files[0].name;
      fileNameText.textContent = fileName;
      fileNameDisplay.classList.remove('hidden');

      // استخراج الامتداد
      const extension = fileName.split('.').pop().toLowerCase();
      console.log("📂 تم رفع الملف بامتداد:", extension);

      // إعادة تعيين (إلغاء تحديد) جميع الأدوات أولًا
      const flawfinder = document.getElementById('flawfinder');
      const bandit = document.getElementById('bandit');
      const semgrep = document.getElementById('semgrep');

      flawfinder.checked = false;
      bandit.checked = false;
      semgrep.checked = false;

      // تحديد الأدوات بناءً على نوع الملف
      if (extension === 'py') {
          console.log("✅ تم اختيار: Bandit و Semgrep");
          bandit.checked = true;
          semgrep.checked = true;
      } else if (['c', 'cpp'].includes(extension)) {
          console.log("✅ تم اختيار: Flawfinder و Semgrep");
          flawfinder.checked = true;
          semgrep.checked = true;
      } else {
          console.log("✅ تم اختيار: Semgrep فقط للغات الأخرى");
          semgrep.checked = true;
      }

      // تحديث الواجهة لجعل الأدوات المختارة مرئية بوضوح
      document.querySelectorAll('.service-option').forEach(option => {
          const checkbox = option.querySelector('input[type="checkbox"]');
          if (checkbox.checked) {
              option.classList.add('bg-blue-600', 'text-white');
          } else {
              option.classList.remove('bg-blue-600', 'text-white');
          }
      });
  } else {
      fileNameDisplay.classList.add('hidden');
  }
}





// For Services (Checkboxes)
document.querySelectorAll('.service-option').forEach(option => {
  option.addEventListener('click', () => {
    const checkbox = option.querySelector('input[type="checkbox"]');
    checkbox.checked = !checkbox.checked;
    option.classList.toggle('bg-blue-600', checkbox.checked);
    option.classList.toggle('text-white', checkbox.checked);
  });
});

// For Report Type (Radio Buttons)
document.querySelectorAll('.report-option').forEach(option => {
  option.addEventListener('click', () => {
    document.querySelectorAll('.report-option').forEach(o => o.classList.remove('bg-blue-600', 'text-white'));
    const radio = option.querySelector('input[type="radio"]');
    radio.checked = true;
    option.classList.add('bg-blue-600', 'text-white');
  });
});




function openModal(details, tool, createdAt, projectName) {
  document.getElementById("modalProjectName").textContent = projectName;
  document.getElementById("modalTool").textContent = tool;
  document.getElementById("modalCreatedAt").textContent = createdAt;

  // التحقق إذا كان التقرير بصيغة HTML أو ملف نصي
  if (details.endsWith('.html')) {
      let username = "{{ username }}";  // جلب اسم المستخدم
      let reportUrl = `/view-report/${username}/reports_whitebox/${encodeURIComponent(details)}`;

      document.getElementById("modalDetails").innerHTML = `<iframe src="${reportUrl}" class="w-full h-96 bg-white"></iframe>`;
  } else {
      document.getElementById("modalDetails").textContent = details;
  }

  document.getElementById("reportModal").classList.remove("hidden");
}


function viewReport(event, filename) {
    event.preventDefault();  // منع الانتقال إلى رابط آخر

    let username = "{{ username }}";  // جلب اسم المستخدم
    let reportUrl = `/view-report/${username}/reports_whitebox/${encodeURIComponent(filename)}`;

    // تحديث الـ Modal ليحتوي على التقرير داخل iframe
    document.getElementById("modalDetails").innerHTML = `<iframe src="${reportUrl}" class="w-full h-96 bg-white"></iframe>`;

    document.getElementById("reportModal").classList.remove("hidden");
}


  // إغلاق المودل عند الضغط على زر الإغلاق
  function closeModal() {
      document.getElementById("reportModal").classList.add("hidden");
  }

  // إغلاق المودل عند النقر خارج النافذة
  document.getElementById("reportModal").addEventListener("click", function(event) {
      if (event.target === this) {
          closeModal();
      }
  });


  function downloadReport(event, filename) {
  event.preventDefault();  // منع إعادة تحميل الصفحة

  let username = "{{ username }}";  // جلب اسم المستخدم
  let sanitizedFilename = filename.replace(`uploads/${username}/reports_whitebox/`, ""); // تنظيف المسار

  let downloadUrl = `/download_report?report_path=uploads/${username}/reports_whitebox/${encodeURIComponent(sanitizedFilename)}`;

  // إنشاء `<a>` ديناميكيًا لتنزيل الملف فقط دون عرضه
  let downloadLink = document.createElement("a");
  downloadLink.href = downloadUrl;
  downloadLink.download = sanitizedFilename;
  document.body.appendChild(downloadLink);
  downloadLink.click();
  document.body.removeChild(downloadLink);

  // إغلاق الـ Modal مباشرة بعد الضغط على الحفظ
  closeModal();
}





  function deleteReport(event, username, reportType, filePath) {
  event.preventDefault();  // منع إعادة تحميل الصفحة
  event.stopPropagation();  // منع تأثيرات أخرى

  // استخراج اسم الملف فقط من المسار
  let filename = filePath.split('/').pop();  

  fetch(`/delete-report/${username}/${reportType}/${encodeURIComponent(filename)}`, {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json'
      }
  }).then(response => response.json())  // تحويل الاستجابة إلى JSON
  .then(data => {
      if (data.success) {
          // حذف العنصر من الواجهة فورًا
          const reportItem = event.target.closest('li');
          if (reportItem) {
              reportItem.remove();
          }
      } else {
          console.error("Failed to delete report:", data.message);
      }
  }).catch(error => console.error("Error deleting report:", error));
}

function viewProject(event, username, filePath) {
  event.preventDefault();

  // تنظيف المسار وإزالة "uploads/username/projects/"
  let filename = filePath.replace(`uploads/${username}/projects/`, '');

  fetch(`/view-project/${username}/${encodeURIComponent(filename)}`)
      .then(response => response.json())
      .then(data => {
          if (data.error) {
              alert("Error: " + data.error);
          } else {
              document.getElementById('modalProjectTitle').textContent = data.filename;
              document.getElementById('modalProjectContent').textContent = data.content;
              document.getElementById('projectModal').classList.remove('hidden');
          }
      })
      .catch(error => console.error("Error fetching file:", error));
}

function closeProjectModal() {
  document.getElementById('projectModal').classList.add('hidden');
}
// إغلاق المودل عند الضغط خارج النافذة
document.getElementById('projectModal').addEventListener('click', function(event) {
  if (event.target === this) {
      closeProjectModal();
  }
});

function deleteProject(event, projectId, element) {
  event.preventDefault();  // منع تحديث الصفحة

  fetch(`/delete_project/${projectId}`, { method: 'POST' })
  .then(response => response.json())
  .then(data => {
      if (data.success) {
          // إزالة العنصر من الصفحة فورًا بعد الحذف
          let projectCard = element.closest('.bg-gray-900');
          if (projectCard) {
              projectCard.remove();
          }
      }
  })
  .catch(error => console.error("Error deleting project:", error));
}


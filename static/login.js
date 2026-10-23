let setupMode = false;

async function checkAuthMode() {
  const res = await fetch("/api/auth/status");
  const data = await res.json();
  if (data.authenticated) {
    window.location.href = "/";
    return;
  }
  setupMode = Boolean(data.setup_required);
  if (setupMode) {
    document.getElementById("setupBanner").classList.remove("hidden");
    document.getElementById("confirmWrap").classList.remove("hidden");
    document.getElementById("authPassConfirm").required = true;
    document.getElementById("authSubmitBtn").textContent = "Yönetici Hesabını Oluştur ve Başla";
  }
}

document.getElementById("authForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errEl = document.getElementById("authError");
  errEl.classList.add("hidden");

  const username = document.getElementById("authUser").value.trim();
  const password = document.getElementById("authPass").value;

  if (setupMode) {
    const confirmPass = document.getElementById("authPassConfirm").value;
    if (password !== confirmPass) {
      errEl.textContent = "Girilen şifreler birbiriyle eşleşmiyor.";
      errEl.classList.remove("hidden");
      return;
    }
  }

  const endpoint = setupMode ? "/api/auth/setup" : "/api/auth/login";
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  const data = await res.json();
  if (!res.ok) {
    errEl.textContent = data.detail || "İşlem başarısız oldu.";
    errEl.classList.remove("hidden");
    return;
  }

  window.location.href = "/";
});

checkAuthMode();

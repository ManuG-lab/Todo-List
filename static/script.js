// Fade‑out delete animation + confirm
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".delete-btn").forEach(btn => {
    btn.addEventListener("click", e => {
      e.preventDefault();
      if (!confirm("Delete this task?")) return;
      const href = btn.getAttribute("href");
      const li   = btn.closest("li");
      li.classList.add("opacity-0");        // fade
      setTimeout(() => { window.location.href = href; }, 300);
    });
  });
});

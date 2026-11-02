/**
 * NetShield-NIDS - Global Client Application JavaScript
 * Handles Theme Management (Dark/Light), Mobile Navigation,
 * Toast Notifications, and Global Telemetry Polling.
 */

document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initMobileNav();
    pollGlobalMonitoringStatus();
    setInterval(pollGlobalMonitoringStatus, 5000);
});

/* ==========================================================================
   Theme Management (Persisted in localStorage)
   ========================================================================== */
function initTheme() {
    const savedTheme = localStorage.getItem("netshield_theme") || "dark";
    applyTheme(savedTheme);

    const themeToggleBtn = document.getElementById("theme-toggle-btn");
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener("click", () => {
            const currentTheme = document.body.classList.contains("light-theme") ? "light" : "dark";
            const newTheme = currentTheme === "dark" ? "light" : "dark";
            applyTheme(newTheme);
            localStorage.setItem("netshield_theme", newTheme);
            window.dispatchEvent(new CustomEvent("netshield:themechange", { detail: { theme: newTheme } }));
        });
    }
}

function applyTheme(theme) {
    const toggleIcon = document.getElementById("theme-icon");
    if (theme === "light") {
        document.body.classList.add("light-theme");
        if (toggleIcon) {
            toggleIcon.classList.remove("bi-moon-stars-fill");
            toggleIcon.classList.add("bi-sun-fill");
        }
    } else {
        document.body.classList.remove("light-theme");
        if (toggleIcon) {
            toggleIcon.classList.remove("bi-sun-fill");
            toggleIcon.classList.add("bi-moon-stars-fill");
        }
    }
}

/* ==========================================================================
   Mobile Sidebar Navigation Drawer
   ========================================================================== */
function initMobileNav() {
    const mobileToggle = document.getElementById("mobile-menu-toggle");
    const sidebar = document.getElementById("app-sidebar");
    
    if (mobileToggle && sidebar) {
        mobileToggle.addEventListener("click", () => {
            sidebar.classList.toggle("open");
        });

        document.addEventListener("click", (e) => {
            if (sidebar.classList.contains("open") &&
                !sidebar.contains(e.target) &&
                !mobileToggle.contains(e.target)) {
                sidebar.classList.remove("open");
            }
        });
    }
}

/* ==========================================================================
   Global Toast Notification System
   ========================================================================== */
function showToast(message, type = "info") {
    let container = document.getElementById("toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "toast-container";
        document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `soc-toast ${type}`;
    
    let iconClass = "bi-info-circle-fill text-info";
    if (type === "success") iconClass = "bi-check-circle-fill text-success";
    if (type === "error") iconClass = "bi-x-circle-fill text-danger";
    if (type === "warning") iconClass = "bi-exclamation-triangle-fill text-warning";

    toast.innerHTML = `
        <i class="bi ${iconClass}"></i>
        <div class="toast-message">${escapeHtml(message)}</div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(100%)";
        toast.style.transition = "all 0.3s ease";
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

/* ==========================================================================
   Global Topbar Monitoring Status Polling
   ========================================================================== */
async function pollGlobalMonitoringStatus() {
    try {
        const res = await fetch("/api/monitoring/status");
        if (!res.ok) return;
        const json = await res.json();
        const data = json.data;

        const indicator = document.getElementById("global-status-indicator");
        const statusText = document.getElementById("global-status-text");

        if (!indicator || !statusText) return;

        indicator.classList.remove("active", "simulation");

        if (data.is_running) {
            if (data.mode === "simulation") {
                indicator.classList.add("simulation");
                statusText.innerText = "Simulation (Lab Mode)";
                statusText.style.color = "var(--accent-purple)";
            } else if (data.mode === "live") {
                indicator.classList.add("active");
                statusText.innerText = `Live (${data.interface || 'Default'})`;
                statusText.style.color = "var(--accent-green)";
            } else if (data.mode === "pcap") {
                indicator.classList.add("simulation");
                statusText.innerText = "PCAP File Ingestion";
                statusText.style.color = "var(--accent-cyan)";
            }
        } else {
            statusText.innerText = "Monitor Stopped";
            statusText.style.color = "var(--accent-red)";
        }
    } catch (e) {
        // Silently tolerate background polling errors
    }
}

/* ==========================================================================
   Utilities
   ========================================================================== */
function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function formatDate(isoStr) {
    if (!isoStr) return "N/A";
    try {
        const d = new Date(isoStr);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + 
               " " + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
        return isoStr;
    }
}


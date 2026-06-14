/* Premium Page Loader — shared script (stable rewrite)
 * - Mounts immediately when the script runs (works whether placed in <head> or before </body>).
 * - Hides reliably after window 'load' OR after a safety timeout, whichever comes first.
 * - Honors a configurable minimum display time so it doesn't flash.
 *
 * Config (set BEFORE this script):
 *   window.PL_CONFIG = { title:'...', subtitle:'...', brand:'...', min:800, max:6000 };
 *
 * Programmatic API:
 *   showLoader(title, subtitle)
 *   hideLoader()
 */
(function () {
  if (window.__pl_installed) return;
  window.__pl_installed = true;

  var cfg = window.PL_CONFIG || {};
  var title    = cfg.title    || 'Loading';
  var subtitle = cfg.subtitle || 'Preparing your experience…';
  var brand    = cfg.brand    || 'Chathuranga Classes';
  var minMs    = typeof cfg.min === 'number' ? cfg.min : 600;
  var maxMs    = typeof cfg.max === 'number' ? cfg.max : 5000; // safety cap

  var overlay = null;
  var shownAt = Date.now();
  var hideTimer = null;
  var safetyTimer = null;

  function build() {
    var el = document.createElement('div');
    el.className = 'pl-overlay';
    el.id = 'pl-overlay';
    el.setAttribute('role', 'status');
    el.setAttribute('aria-live', 'polite');
    el.innerHTML =
      '<div class="pl-brand">' + brand + '</div>' +
      '<div class="pl-stage">' +
        '<div class="pl-loader">' +
          '<div class="pl-ring"></div>' +
          '<div class="pl-ring r2"></div>' +
          '<div class="pl-ring r3"></div>' +
          '<div class="pl-core">C</div>' +
        '</div>' +
        '<h1 class="pl-title" id="pl-title">' + title + '</h1>' +
        '<p class="pl-sub" id="pl-sub">' + subtitle + '</p>' +
        '<div class="pl-bar"><i></i></div>' +
        '<div class="pl-dots"><span></span><span></span><span></span></div>' +
      '</div>';
    return el;
  }

  function mount() {
    if (overlay) return;
    overlay = build();
    var host = document.body || document.documentElement;
    host.appendChild(overlay);
    // Lock scroll while visible to avoid jank
    try { document.documentElement.style.overflow = 'hidden'; } catch (_) {}
  }

  function reallyHide() {
    if (!overlay) return;
    overlay.classList.add('pl-hide');
    try { document.documentElement.style.overflow = ''; } catch (_) {}
    // Remove from DOM after the fade so it stops painting (perf win on mobile)
    setTimeout(function () {
      if (overlay && overlay.parentNode) overlay.parentNode.removeChild(overlay);
      overlay = null;
    }, 700);
  }

  function hideLoader() {
    if (!overlay) return;
    if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
    var elapsed = Date.now() - shownAt;
    var wait = Math.max(0, minMs - elapsed);
    hideTimer = setTimeout(reallyHide, wait);
  }

  function showLoader(t, s) {
    mount();
    var tEl = document.getElementById('pl-title');
    var sEl = document.getElementById('pl-sub');
    if (t && tEl) tEl.textContent = t;
    if (s && sEl) sEl.textContent = s;
    overlay.classList.remove('pl-hide');
    shownAt = Date.now();
    armSafety();
  }

  function armSafety() {
    if (safetyTimer) clearTimeout(safetyTimer);
    safetyTimer = setTimeout(function () { reallyHide(); }, maxMs);
  }

  window.showLoader = showLoader;
  window.hideLoader = hideLoader;

  // ----- Initial mount -----
  if (document.body) {
    mount();
  } else {
    document.addEventListener('DOMContentLoaded', mount, { once: true });
  }
  armSafety();

  // ----- Auto-hide trigger -----
  function scheduleHide() { setTimeout(hideLoader, 80); }

  if (document.readyState === 'complete') {
    scheduleHide();
  } else {
    window.addEventListener('load', scheduleHide, { once: true });
    // Fallback: many mobile browsers delay 'load' for trackers / fonts; also hide on DOMContentLoaded + small delay
    document.addEventListener('DOMContentLoaded', function () {
      setTimeout(hideLoader, 400);
    }, { once: true });
  }

  // Hide when tab becomes visible again (handles bfcache restore on mobile)
  window.addEventListener('pageshow', function (e) {
    if (e.persisted) reallyHide();
  });

  // ----- Show loader on internal navigations -----
  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest && e.target.closest('a');
    if (!a) return;
    var href = a.getAttribute('href');
    if (!href) return;
    if (a.target === '_blank' || a.hasAttribute('download')) return;
    if (/^(mailto:|tel:|javascript:|#)/i.test(href)) return;
    try {
      var u = new URL(a.href, window.location.href);
      if (u.origin !== window.location.origin) return;
      if (u.pathname === window.location.pathname && u.hash) return; // same-page anchor
    } catch (_) { return; }
    showLoader('Loading page', 'Please wait a moment…');
  }, true);

  // ----- Show loader on auth form submits -----
  document.addEventListener('submit', function (e) {
    var f = e.target;
    if (!f) return;
    if (f.id === 'loginForm' || f.id === 'adminForm' || f.id === 'registerForm') {
      var msg = f.id === 'registerForm'
        ? { t: 'Creating your account', s: 'Securely registering you with our system…' }
        : f.id === 'adminForm'
          ? { t: 'Signing in as admin', s: 'Verifying credentials…' }
          : { t: 'Signing you in', s: 'Authenticating with our secure server…' };
      showLoader(msg.t, msg.s);
    }
  }, true);
})();

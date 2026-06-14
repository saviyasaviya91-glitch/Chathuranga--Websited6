/* =============================================================
 * Chathuranga Classes — App Logic (cleaned + hardened)
 *
 * Backend: Firebase Auth + Firestore (compat SDK v10).
 *   Collections: students, papers, scores
 *
 * Hardening pass:
 *   1. Passwords are NEVER written to Firestore / Local / Session
 *      storage. Firebase Auth is the single source of truth.
 *   2. Student result lookup queries Firestore directly (case &
 *      whitespace tolerant) and falls back to Auth UID lookup.
 *   3. Scores live in Firestore (collection: scores). LocalStorage
 *      is no longer the source of truth for any business data.
 *   4. All user-generated strings rendered into the DOM are
 *      HTML-escaped via `esc()` to prevent XSS.
 *
 * `db` and `firebase` are initialized inline in each HTML page
 * before this script is loaded.
 * ============================================================= */

/* ---------- XSS-safe HTML escape ---------- */
function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/* ---------- Lightweight session cache (NO secrets) ----------
 * Only non-sensitive UI hints (username, expiry text). Never
 * passwords, never tokens — Firebase Auth owns the session. */
const UI_CACHE_KEY = 'currentUser';

/* =============================================================
 * AUTH — Student registration / login
 * ============================================================= */

async function registerStudentFirebase({ fullName, username, email, password, monthsPaid }) {
  try {
    if (!email || !password || !username) {
      return { ok: false, message: 'කරුණාකර සියලුම විස්තර නිවැරදිව ඇතුලත් කරන්න.' };
    }

    const userCredential = await firebase.auth().createUserWithEmailAndPassword(email, password);
    const userId = userCredential.user.uid;

    const paidUntilDate = new Date();
    paidUntilDate.setMonth(paidUntilDate.getMonth() + (monthsPaid || 1));

    // SECURITY: do NOT persist the password anywhere — Firebase Auth
    // already manages credentials. Firestore stores profile data only.
    const uname = (username || '').trim();
    const unameLower = uname.toLowerCase();

    await db.collection('students').doc(userId).set({
      fullName,
      username: uname,
      usernameLower: unameLower,
      email: (email || '').toLowerCase().trim(),
      paidUntil: firebase.firestore.Timestamp.fromDate(paidUntilDate),
      isActive: true,
      createdAt: firebase.firestore.FieldValue.serverTimestamp(),
    });

    // PUBLIC lookup doc — contains ONLY non-sensitive fields so
    // result lookup works without requiring login. Doc id = usernameLower
    // for fast, unique reads.
    try {
      await db.collection('studentLookup').doc(unameLower).set({
        usernameLower: unameLower,
        studentId: userId,
        displayName: fullName || uname,
      });
    } catch (e) {
      console.warn('studentLookup write failed:', e);
    }

    return { ok: true };
  } catch (error) {
    console.error('Firebase registration error:', error);
    let errMsg = error.message;
    if (error.code === 'auth/email-already-in-use') {
      errMsg = 'මේ Email ලිපිනයෙන් කලින් කෙනෙක් ලියාපදිංචි වී ඇත.';
    } else if (error.code === 'auth/weak-password') {
      errMsg = 'Password එකට අවම වශයෙන් අකුරු 6ක්වත් තිබිය යුතුය.';
    }
    return { ok: false, message: errMsg };
  }
}

async function loginStudentFirebase(email, password, rememberMe) {
  try {
    if (!email || !password) {
      return { ok: false, message: 'කරුණාකර ඊමේල් සහ මුරපදය ඇතුලත් කරන්න.' };
    }

    const persistence = rememberMe
      ? firebase.auth.Auth.Persistence.LOCAL
      : firebase.auth.Auth.Persistence.SESSION;
    await firebase.auth().setPersistence(persistence);

    const { user } = await firebase.auth()
      .signInWithEmailAndPassword(email.toLowerCase().trim(), password);

    const studentDoc = await db.collection('students').doc(user.uid).get();
    if (!studentDoc.exists) {
      await firebase.auth().signOut();
      return { ok: false, message: 'ඔබගේ ගිණුම් විස්තර සොයාගැනීමට නොහැක!' };
    }

    const sData = studentDoc.data();

    if (sData.paidUntil && sData.paidUntil.toDate() < new Date()) {
      await firebase.auth().signOut();
      return {
        ok: false,
        message: 'ඔබගේ මාසික දායකත්වය (Subscription) අවසන් වී ඇත! කරුණාකර ඇඩ්මින් සම්බන්ධ කරගන්න.',
      };
    }

    localStorage.removeItem(UI_CACHE_KEY);
    sessionStorage.removeItem(UI_CACHE_KEY);

    const expText = sData.paidUntil
      ? sData.paidUntil.toDate().toLocaleDateString('en-GB')
      : 'No Date';

    // NOTE: no password / token here. UI hint only.
    const studentData = {
      studentId: user.uid,
      username: sData.username || 'Student',
      email: user.email,
      exp: expText,
      isRemembered: !!rememberMe,
    };

    localStorage.setItem(UI_CACHE_KEY, JSON.stringify(studentData));
    return { ok: true, student: studentData };
  } catch (error) {
    console.error('Login error:', error);
    if (
      error.code === 'auth/user-not-found' ||
      error.code === 'auth/wrong-password' ||
      error.code === 'auth/invalid-credential'
    ) {
      return { ok: false, message: 'ඇතුලත් කළ ඊමේල් ලිපිනය හෝ මුරපදය වැරදියි!' };
    }
    return { ok: false, message: 'Login failed: ' + error.message };
  }
}

/* =============================================================
 * AUTH — Admin
 * ============================================================= */

async function loginAdmin(email, password) {
  try {
    await firebase.auth().signInWithEmailAndPassword(email, password);
    sessionStorage.setItem('adminSession', '1');
    return { ok: true };
  } catch (error) {
    console.error('Admin login error:', error);
    return { ok: false, message: error.message };
  }
}

function isAdmin() {
  return sessionStorage.getItem('adminSession') === '1';
}

async function logoutAdmin() {
  try {
    await firebase.auth().signOut();
    sessionStorage.removeItem('adminSession');
    window.location.href = 'login.html';
  } catch (error) {
    console.error('Logout error:', error);
    alert('Logout failed!');
  }
}

/* =============================================================
 * PAPERS (Firestore)
 * ============================================================= */

async function addPaper({ title, subject, date, link }) {
  try {
    await db.collection('papers').add({
      title,
      subject,
      date,
      link: link || '#',
      createdAt: firebase.firestore.FieldValue.serverTimestamp(),
    });
    alert('Paper saved to Cloud successfully!');
  } catch (error) {
    console.error('Error adding paper:', error);
    alert('Error: ' + error.message);
  }
}

async function deletePaper(id) {
  try {
    await db.collection('papers').doc(id).delete();

    const scoresRef = await db.collection('scores').where('paperId', '==', id).get();
    const batch = db.batch();
    scoresRef.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();

    alert('Paper and associated scores deleted!');
    location.reload();
  } catch (error) {
    console.error('Error deleting paper:', error);
  }
}

async function renderPapers(targetId, admin = false) {
  const root = document.getElementById(targetId);
  if (!root) return;

  try {
    const snapshot = await db.collection('papers').orderBy('createdAt', 'desc').get();
    const papers = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));

    if (!papers.length) {
      root.innerHTML = '<p class="empty">No papers yet.</p>';
      return;
    }

    root.innerHTML = papers.map((p) => `
      <div class="paper-card glass">
        <span class="paper-tag">${esc(p.subject)}</span>
        <h4>${esc(p.title)}</h4>
        <p class="meta"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg> ${esc(formatDate(p.date))}</p>
        <div class="paper-actions">
          <a class="btn btn-outline btn-sm" onclick="viewPdf('${esc(p.link)}')"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> View</a>
          <a class="btn btn-gold-fill btn-sm" href="${esc(p.link)}" download="${esc(p.title)}.pdf"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Download</a>
          ${admin
            ? `<button class="btn btn-danger btn-sm full-row"
                       onclick="if(confirm('Delete this paper?')){deletePaper('${esc(p.id)}');}"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-2 14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg> Delete Paper</button>`
            : ''}
        </div>
      </div>
    `).join('');
  } catch (error) {
    console.error('Error rendering papers:', error);
    root.innerHTML = '<p class="empty">Error loading papers.</p>';
  }
}

/* =============================================================
 * SCORES (Firestore — single source of truth)
 *
 * Document id convention: `${studentId}__${paperId}` so we can
 * upsert idempotently without an extra query.
 * ============================================================= */

function _scoreDocId(studentId, paperId) {
  return `${studentId}__${paperId}`;
}

async function addScore(studentId, paperId, marks) {
  if (!studentId || !paperId) {
    alert('Please select a student and a paper.');
    return;
  }
  try {
    await db.collection('scores').doc(_scoreDocId(studentId, paperId)).set({
      studentId,
      paperId,
      marks: Number(marks) || 0,
      addedAt: firebase.firestore.FieldValue.serverTimestamp(),
    });
  } catch (error) {
    console.error('Error adding score:', error);
    alert('Error saving score: ' + error.message);
  }
}

async function deleteScore(studentId, paperId) {
  try {
    await db.collection('scores').doc(_scoreDocId(studentId, paperId)).delete();
  } catch (error) {
    console.error('Error deleting score:', error);
    alert('Error deleting score: ' + error.message);
  }
}

function gradeFor(m) {
  if (m >= 75) return { g: 'A', cls: 'g-A', status: 'Pass' };
  if (m >= 65) return { g: 'B', cls: 'g-B', status: 'Pass' };
  if (m >= 50) return { g: 'C', cls: 'g-C', status: 'Pass' };
  if (m >= 35) return { g: 'S', cls: 'g-C', status: 'Pass' };
  return         { g: 'F', cls: 'g-F', status: 'Fail' };
}

/* =============================================================
 * RESULT LOOKUP (Firestore)
 *
 * Accepts: Firebase Auth UID, username, or email — trims & is
 * case-insensitive. Renders user content via esc() for XSS safety.
 * ============================================================= */
async function searchStudent() {
  const input = document.getElementById('studentSearch');
  const out   = document.getElementById('searchResult');
  if (!out) return;

  const raw = (input?.value || '').trim();
  if (!raw) { out.innerHTML = ''; return; }

  out.innerHTML = '<p class="empty">⏳ Searching...</p>';

  const q = raw.toLowerCase();

  try {
    let studentId = null;
    let studentData = null;

    // 1) Public studentLookup by usernameLower (NO login required).
    try {
      const lookup = await db.collection('studentLookup').doc(q).get();
      if (lookup.exists) {
        const ld = lookup.data();
        studentId = ld.studentId;
        studentData = {
          fullName: ld.displayName || '',
          username: ld.usernameLower || '',
          email: '',
        };
      }
    } catch (e) {
      console.warn('studentLookup read failed:', e);
    }

    // 2) Direct doc-id (Firebase Auth UID) — needs login.
    if (!studentData) {
      try {
        const byId = await db.collection('students').doc(raw).get();
        if (byId.exists) {
          studentId = byId.id;
          studentData = byId.data();
        }
      } catch (e) { /* permission denied if not signed-in */ }
    }

    // 3) studentLookup query by usernameLower (covers doc-id mismatches).
    if (!studentData) {
      try {
        const byLookup = await db.collection('studentLookup')
          .where('usernameLower', '==', q).limit(1).get();
        if (!byLookup.empty) {
          const ld = byLookup.docs[0].data();
          studentId = ld.studentId;
          studentData = {
            fullName: ld.displayName || '',
            username: ld.usernameLower || '',
            email: '',
          };
        }
      } catch (e) {
        console.warn('studentLookup query failed:', e);
      }
    }

    // 4) Last resort: students usernameLower (admin only — silent if denied).
    if (!studentData) {
      try {
        const byUser = await db.collection('students')
          .where('usernameLower', '==', q).limit(1).get();
        if (!byUser.empty) {
          studentId = byUser.docs[0].id;
          studentData = byUser.docs[0].data();
        }
      } catch (e) { /* permission denied if not signed-in or not admin */ }
    }


    if (!studentData) {
      out.innerHTML = `<div class="glass pad empty">❌ No student found for ID <b>${esc(raw)}</b></div>`;
      return;
    }

    // Load papers + scores from Firestore.
    const [papersSnap, scoresSnap] = await Promise.all([
      db.collection('papers').get(),
      db.collection('scores').where('studentId', '==', studentId).get(),
    ]);

    const papers = {};
    papersSnap.forEach((d) => { papers[d.id] = d.data(); });

    const enriched = scoresSnap.docs.map((d) => {
      const s = d.data();
      return {
        ...s,
        paper: papers[s.paperId] || { title: '(deleted)', subject: '-', date: '-' },
      };
    });

    const marks = enriched.map((s) => Number(s.marks) || 0);
    const avg   = marks.length ? (marks.reduce((a, b) => a + b, 0) / marks.length).toFixed(1) : '—';
    const high  = marks.length ? Math.max(...marks) : '—';

    const fullName    = studentData.fullName || studentData.username || 'Student';
    const displayId   = (studentId || '').substring(0, 8).toUpperCase();
    const displayMail = studentData.email || '';

    out.innerHTML = `
      <div class="glass profile-head">
        <div class="avatar">${esc(fullName.charAt(0).toUpperCase())}</div>
        <div>
          <h3>${esc(fullName)}</h3>
          <p class="muted" style="margin:0">${esc(displayId)} · ${esc(displayMail)}</p>
        </div>
      </div>
      <div class="summary-grid">
        <div class="glass"><h3>${enriched.length}</h3><p>Papers Done</p></div>
        <div class="glass"><h3>${esc(avg)}</h3><p>Average</p></div>
        <div class="glass"><h3>${esc(high)}</h3><p>Highest</p></div>
      </div>
      <div class="table-wrap glass">
        <table>
          <thead>
            <tr><th>Paper</th><th>Subject</th><th>Date</th><th>Marks</th><th>Grade</th><th>Status</th></tr>
          </thead>
          <tbody>
            ${enriched.length ? enriched.map((s) => {
              const g = gradeFor(Number(s.marks) || 0);
              return `<tr>
                <td>${esc(s.paper.title)}</td>
                <td>${esc(s.paper.subject)}</td>
                <td>${esc(formatDate(s.paper.date))}</td>
                <td><b>${esc(s.marks)}</b></td>
                <td><span class="grade ${g.cls}">${g.g}</span></td>
                <td>${g.status}</td>
              </tr>`;
            }).join('') : `<tr><td colspan="6" class="empty">No scores recorded yet.</td></tr>`}
          </tbody>
        </table>
      </div>`;
  } catch (error) {
    console.error('searchStudent error:', error);
    out.innerHTML = `<div class="glass pad empty">⚠️ Error searching: ${esc(error.message || 'Unknown error')}</div>`;
  }
}

/* =============================================================
 * ADMIN RENDERERS (all Firestore-backed)
 * ============================================================= */

async function renderAdminStats() {
  const el = document.getElementById('adminStats');
  if (!el) return;

  try {
    const [studentsSnap, papersSnap, scoresSnap] = await Promise.all([
      db.collection('students').get(),
      db.collection('papers').get(),
      db.collection('scores').get(),
    ]);

    const marks = scoresSnap.docs.map((d) => Number(d.data().marks) || 0);
    const avg   = marks.length ? (marks.reduce((a, b) => a + b, 0) / marks.length).toFixed(1) : 0;
    const high  = marks.length ? Math.max(...marks) : 0;

    el.innerHTML = `
      <div class="stat glass">
        <div class="stat-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div>
        <h2>${studentsSnap.size}</h2><p>Total Students</p>
      </div>
      <div class="stat glass">
        <div class="stat-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg></div>
        <h2>${papersSnap.size}</h2><p>Total Papers</p>
      </div>
      <div class="stat glass">
        <div class="stat-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg></div>
        <h2>${esc(avg)}</h2><p>Average Score</p>
      </div>
      <div class="stat glass">
        <div class="stat-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="7"/><polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88"/></svg></div>
        <h2>${esc(high)}</h2><p>Highest Score</p>
      </div>`;
  } catch (error) {
    console.error('renderAdminStats failed:', error);
  }
}

async function renderStudentTable() {
  const tbody = document.querySelector('#studentTable tbody');
  if (!tbody) return;

  const q = (document.getElementById('studentSearchAdmin')?.value || '').trim().toLowerCase();

  try {
    const snapshot = await db.collection('students').orderBy('createdAt', 'desc').get();
    let html = '';

    snapshot.forEach((doc) => {
      const s = doc.data();
      const id = doc.id;

      const matches = !q
        || (s.fullName || '').toLowerCase().includes(q)
        || (s.email    || '').toLowerCase().includes(q)
        || (s.username || '').toLowerCase().includes(q);
      if (!matches) return;

      let statusText = 'No Date';
      if (s.paidUntil) {
        const paidDate = s.paidUntil.toDate();
        const daysLeft = Math.ceil((paidDate - new Date()) / (1000 * 3600 * 24));
        statusText = daysLeft < 0
          ? `<span class="status-pill expired"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg> Expired</span>`
          : `<span class="status-pill ok"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> ${daysLeft} Days</span>`;
      } else {
        statusText = `<span class="status-pill none">No Date</span>`;
      }

      html += `
        <tr>
          <td><b class="gold">${esc(id.substring(0, 5).toUpperCase())}</b></td>
          <td>${esc(s.fullName)}</td>
          <td>${esc(s.username)}</td>
          <td>${esc(s.email)}</td>
          <td>${statusText}</td>
          <td>
            <div class="row-actions">
              <button class="icon-btn edit" onclick="editStudent('${esc(id)}')"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg> Edit</button>
              <button class="icon-btn danger" onclick="deleteStudent('${esc(id)}')"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-2 14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg> Delete</button>
            </div>
          </td>
        </tr>`;
    });

    tbody.innerHTML = html || `<tr><td colspan="6" class="empty">No students found.</td></tr>`;
  } catch (error) {
    console.error('renderStudentTable error:', error);
  }
}

async function deleteStudent(id) {
  if (!confirm('Are you sure you want to delete this student?')) return;
  try {
    // Find lookup doc for this student to remove it too.
    const lookupSnap = await db.collection('studentLookup')
      .where('studentId', '==', id).get();

    await db.collection('students').doc(id).delete();

    const batch = db.batch();
    lookupSnap.forEach((d) => batch.delete(d.ref));
    if (!lookupSnap.empty) await batch.commit();

    alert('Student record deleted from Firestore.');
    if (typeof refreshAll === 'function') refreshAll();
  } catch (error) {
    alert('Error: ' + error.message);
  }
}

async function editStudent(id) {
  try {
    const doc = await db.collection('students').doc(id).get();
    if (!doc.exists) { alert('Student not found'); return; }
    const s = doc.data() || {};

    const modal = document.getElementById('editStudentModal');
    const form  = document.getElementById('editStudentForm');
    if (!modal || !form) {
      // Fallback to prompt if modal markup missing
      const newName = prompt('Full Name:', s.fullName || '');
      if (newName === null) return;
      await db.collection('students').doc(id).update({ fullName: newName.trim() });
      if (typeof refreshAll === 'function') refreshAll();
      return;
    }

    form.studentId.value    = id;
    form.fullName.value     = s.fullName || '';
    form.username.value     = s.username || '';
    form.email.value        = s.email || '';
    form.extendMonths.value = '';
    form.isActive.checked   = s.isActive !== false;

    if (s.paidUntil && typeof s.paidUntil.toDate === 'function') {
      const d = s.paidUntil.toDate();
      const iso = new Date(d.getTime() - d.getTimezoneOffset()*60000).toISOString().slice(0,10);
      form.paidUntil.value = iso;
    } else {
      form.paidUntil.value = '';
    }

    const av  = document.getElementById('esAvatar');
    const sub = document.getElementById('esSub');
    if (av)  av.textContent  = (s.fullName || s.username || 'S').charAt(0).toUpperCase();
    if (sub) sub.textContent = `${(s.fullName || s.username || 'Student')} · ID ${id.substring(0,6).toUpperCase()}`;

    modal.style.display = 'flex';
    requestAnimationFrame(() => modal.classList.add('es-show'));
    document.body.style.overflow = 'hidden';
  } catch (error) {
    alert('Open editor failed: ' + error.message);
  }
}

function closeEditStudent() {
  const modal = document.getElementById('editStudentModal');
  if (!modal) return;
  modal.classList.remove('es-show');
  setTimeout(() => { modal.style.display = 'none'; }, 200);
  document.body.style.overflow = '';
}
window.closeEditStudent = closeEditStudent;

async function saveStudentEdit({ studentId, fullName, username, email, paidUntil, extendMonths, isActive }) {
  try {
    if (!studentId) return { ok: false, message: 'Missing student id' };
    const uname      = (username || '').trim();
    const unameLower = uname.toLowerCase();
    const cleanEmail = (email || '').trim().toLowerCase();
    const cleanName  = (fullName || '').trim();

    const update = {
      fullName: cleanName,
      username: uname,
      usernameLower: unameLower,
      email: cleanEmail,
      isActive: !!isActive,
      updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
    };

    // Determine paidUntil: start from explicit date (if set), else existing,
    // then add extendMonths on top.
    const existing = await db.collection('students').doc(studentId).get();
    const ex = existing.exists ? existing.data() : {};
    let base = null;
    if (paidUntil) {
      base = new Date(paidUntil + 'T00:00:00');
    } else if (ex.paidUntil && typeof ex.paidUntil.toDate === 'function') {
      base = ex.paidUntil.toDate();
    } else {
      base = new Date();
    }
    const addM = parseInt(extendMonths, 10);
    if (!isNaN(addM) && addM > 0) base.setMonth(base.getMonth() + addM);
    update.paidUntil = firebase.firestore.Timestamp.fromDate(base);

    await db.collection('students').doc(studentId).update(update);

    // Sync / rebuild studentLookup. If usernameLower changed, the old
    // lookup doc must be removed so old usernames can't resolve.
    try {
      const lookupSnap = await db.collection('studentLookup')
        .where('studentId', '==', studentId).get();
      const batch = db.batch();
      lookupSnap.forEach((d) => {
        if (d.id !== unameLower) batch.delete(d.ref);
      });
      if (unameLower) {
        batch.set(db.collection('studentLookup').doc(unameLower), {
          usernameLower: unameLower,
          studentId,
          displayName: cleanName || uname || 'Student',
        }, { merge: true });
      }
      await batch.commit();
    } catch (e) {
      console.warn('studentLookup sync failed:', e);
    }

    return { ok: true };
  } catch (error) {
    console.error('saveStudentEdit error:', error);
    return { ok: false, message: error.message };
  }
}
window.saveStudentEdit = saveStudentEdit;

/* =============================================================
 * ONE-TIME BACKFILL (admin only)
 *
 * Run once from the browser console while logged in as ADMIN:
 *   backfillStudentLookup()
 * Creates studentLookup docs for all existing students that
 * registered before the public-lookup collection existed.
 * ============================================================= */
async function backfillStudentLookup() {
  if (!isAdmin()) {
    alert('Admin login required.');
    return;
  }
  try {
    const snap = await db.collection('students').get();
    let created = 0, skipped = 0;
    for (const doc of snap.docs) {
      const s = doc.data() || {};
      const uname = (s.username || '').trim();
      const unameLower = (s.usernameLower || uname.toLowerCase()).trim();
      if (!unameLower) { skipped++; continue; }
      await db.collection('studentLookup').doc(unameLower).set({
        usernameLower: unameLower,
        studentId: doc.id,
        displayName: s.fullName || uname || 'Student',
      }, { merge: true });
      created++;
    }
    alert(`Backfill done. Created/updated: ${created}, skipped: ${skipped}.`);
  } catch (e) {
    console.error('backfillStudentLookup error:', e);
    alert('Backfill failed: ' + e.message);
  }
}
window.backfillStudentLookup = backfillStudentLookup;

async function populateScoreSelects() {
  const sSel = document.getElementById('scoreStudent');
  const pSel = document.getElementById('scorePaper');
  if (!sSel || !pSel) return;

  try {
    const [studentsSnap, papersSnap] = await Promise.all([
      db.collection('students').orderBy('createdAt', 'desc').get(),
      db.collection('papers').orderBy('createdAt', 'desc').get(),
    ]);

    const studentOpts = studentsSnap.docs.map((d) => {
      const s = d.data();
      const label = `${(d.id || '').substring(0, 6).toUpperCase()} — ${s.fullName || s.username || ''}`;
      return `<option value="${esc(d.id)}">${esc(label)}</option>`;
    }).join('');

    const paperOpts = papersSnap.docs.map((d) => {
      const p = d.data();
      return `<option value="${esc(d.id)}">${esc(p.title || d.id)}</option>`;
    }).join('');

    sSel.innerHTML = '<option value="">Select Student...</option>' + studentOpts;
    pSel.innerHTML = '<option value="">Select Paper...</option>'   + paperOpts;
  } catch (error) {
    console.error('populateScoreSelects error:', error);
  }
}

async function renderScoreTable() {
  const tbody = document.querySelector('#scoreTable tbody');
  if (!tbody) return;

  try {
    const [studentsSnap, papersSnap, scoresSnap] = await Promise.all([
      db.collection('students').get(),
      db.collection('papers').get(),
      db.collection('scores').orderBy('addedAt', 'desc').get(),
    ]);

    const students = {};
    studentsSnap.forEach((d) => { students[d.id] = d.data(); });
    const papers = {};
    papersSnap.forEach((d) => { papers[d.id] = d.data(); });

    const rows = scoresSnap.docs.map((d) => {
      const sc = d.data();
      const st = students[sc.studentId];
      const p  = papers[sc.paperId];
      const g  = gradeFor(Number(sc.marks) || 0);
      const stLabel = st ? `${(sc.studentId || '').substring(0,6).toUpperCase()} — ${st.fullName || st.username || ''}` : sc.studentId;
      const pLabel  = p ? p.title : sc.paperId;
      return `<tr>
        <td>${esc(stLabel)}</td>
        <td>${esc(pLabel)}</td>
        <td><b>${esc(sc.marks)}</b></td>
        <td><span class="grade ${g.cls}">${g.g}</span></td>
        <td>${g.status}</td>
        <td>
          <button class="icon-btn danger"
            onclick="if(confirm('Delete this score?')){deleteScore('${esc(sc.studentId)}','${esc(sc.paperId)}').then(()=>{renderScoreTable();renderAdminStats();});}">
            <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-2 14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg> Delete
          </button>
        </td>
      </tr>`;
    }).join('');

    tbody.innerHTML = rows || `<tr><td colspan="6" class="empty">No scores yet.</td></tr>`;
  } catch (error) {
    console.error('renderScoreTable error:', error);
  }
}

/* =============================================================
 * UI HELPERS
 * ============================================================= */

function togglePw(id, btn) {
  const el = document.getElementById(id);
  el.type = el.type === 'password' ? 'text' : 'password';
  btn.textContent = el.type === 'password' ? '👁' : '🙈';
}

function showAlert(msg, type = 'error') {
  const el = document.getElementById('alert');
  if (!el) return;
  el.className = `alert ${type} show`;
  el.textContent = msg; // textContent is XSS-safe.
}

function formatDate(d) {
  if (!d || d === '-') return d || '-';
  try {
    return new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
  } catch {
    return d;
  }
}

/* -------- PDF preview modal -------- */
function viewPdf(url) {
  const modal = document.getElementById('pdfModal');
  const iframe = document.getElementById('pdfFrame');
  if (!modal || !iframe) return;

  let finalUrl = url;
  if (url && url.includes('drive.google.com')) {
    finalUrl = url
      .replace(/\/view.*$/,        '/preview')
      .replace(/\/edit.*$/,        '/preview')
      .replace(/\/usp=sharing.*$/, '/preview');
  } else if (url) {
    finalUrl = `https://docs.google.com/viewer?url=${encodeURIComponent(url)}&embedded=true`;
  }

  iframe.src = finalUrl;
  modal.style.display = 'block';
  document.body.style.overflow = 'hidden';
}

function closePdf() {
  const modal = document.getElementById('pdfModal');
  const iframe = document.getElementById('pdfFrame');
  if (!modal || !iframe) return;
  iframe.src = '';
  modal.style.display = 'none';
  document.body.style.overflow = 'auto';
}

window.addEventListener('click', (event) => {
  const modal = document.getElementById('pdfModal');
  if (modal && event.target === modal) closePdf();
});

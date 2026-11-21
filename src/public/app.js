// vaultpass front-end.
//
// Sign in, and the API hands back a signed access token. The UI keeps it in
// sessionStorage and sends it as `Authorization: Bearer <token>` on every call.
//
// The "Admin console" is only DRAWN for accounts whose role is `admin` — but
// that is just presentation. What the server lets you do is decided by the
// token you send, so look at the token (Burp Proxy / Repeater, or any JWT
// decoder) and at what the admin routes believe about it.
//
// All dynamic text is written with textContent, so the UI itself adds no XSS.
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const KEY = 'vaultpass.session';
let session = null; // { token, user: { id, username, displayName, role } }

function save(s) {
  session = s;
  sessionStorage.setItem(KEY, JSON.stringify(s));
}

function load() {
  try {
    return JSON.parse(sessionStorage.getItem(KEY));
  } catch {
    return null;
  }
}

async function api(path, options = {}) {
  const headers = { 'content-type': 'application/json' };
  if (session?.token) headers.authorization = `Bearer ${session.token}`;
  const res = await fetch(path, { ...options, headers });
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body };
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function kv(k, v) {
  const row = el('div', 'kv');
  row.append(el('span', 'k', k), el('span', 'v', v));
  return row;
}

// ---------- credential cards ----------
function card(c) {
  const node = el('article', `cred ${c.visibility}`);
  const title = el('h3', '', c.name);
  title.appendChild(el('span', `badge ${c.visibility}`, c.visibility));
  node.appendChild(title);
  node.appendChild(kv('user', c.username));

  const secret = kv('secret', '••••••••••');
  const value = secret.querySelector('.v');
  const reveal = el('button', 'reveal', 'Reveal secret');
  reveal.type = 'button';
  reveal.addEventListener('click', () => {
    const hidden = value.dataset.shown !== '1';
    value.textContent = hidden ? c.secret : '••••••••••';
    value.dataset.shown = hidden ? '1' : '0';
    reveal.textContent = hidden ? 'Hide secret' : 'Reveal secret';
  });
  node.append(secret, reveal);
  if (c.notes) node.appendChild(el('p', 'note', c.notes));
  return node;
}

function renderCards(target, list, emptyText) {
  if (!list.length) {
    target.replaceChildren(el('p', 'empty', emptyText));
    return;
  }
  target.replaceChildren(...list.map(card));
}

async function loadTeam() {
  const { status, body } = await api('/api/vault');
  if (status === 401) return signOut();
  renderCards($('#team-grid'), body.credentials ?? [], 'Nothing shared with the team yet.');
}

async function loadPersonal() {
  const { status, body } = await api('/api/vault/personal');
  if (status === 401) return signOut();
  renderCards($('#personal-grid'), body.credentials ?? [], 'You have no personal items.');
}

// ---------- admin console ----------
function table(headers, rows) {
  const t = el('table');
  const head = el('tr');
  headers.forEach((h) => head.appendChild(el('th', '', h)));
  t.appendChild(el('thead')).appendChild(head);
  const body = el('tbody');
  rows.forEach((r) => {
    const tr = el('tr');
    r.forEach((cell) => tr.appendChild(el('td', '', String(cell))));
    body.appendChild(tr);
  });
  t.appendChild(body);
  return t;
}

async function loadAdmin(tab) {
  const err = $('#admin-error');
  const out = $('#admin-body');
  err.textContent = '';
  out.replaceChildren();

  const route = { users: 'users', all: 'credentials', audit: 'audit' }[tab];
  const { status, body } = await api(`/api/admin/${route}`);
  if (status !== 200) {
    err.textContent = body.message || `request failed (${status})`;
    return;
  }

  if (tab === 'users') {
    out.appendChild(
      table(
        ['id', 'username', 'name', 'role'],
        body.users.map((u) => [u.id, u.username, u.displayName, u.role]),
      ),
    );
  } else if (tab === 'all') {
    const g = el('div', 'grid');
    renderCards(g, body.credentials, 'The vault is empty.');
    out.appendChild(g);
  } else {
    out.appendChild(
      table(
        ['#', 'when', 'actor', 'action', 'target'],
        body.events.map((e) => [
          e.id,
          new Date(e.at).toISOString().slice(0, 16).replace('T', ' '),
          e.actor,
          e.action,
          e.target,
        ]),
      ),
    );
  }
}

// ---------- navigation ----------
function show(view) {
  $$('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  $$('.view').forEach((v) => v.classList.toggle('hidden', v.id !== `view-${view}`));
  if (view === 'team') loadTeam();
  if (view === 'personal') loadPersonal();
  if (view === 'admin') loadAdmin($('.tab.active').dataset.tab);
}

function enter(user) {
  $('#login-view').classList.add('hidden');
  $('#app-view').classList.remove('hidden');
  $('#who-name').textContent = user.displayName || user.username;
  const role = $('#who-role');
  role.textContent = user.role;
  role.className = `role ${user.role}`;
  // UI-only: the console entry is drawn for administrators.
  $('#nav-admin').classList.toggle('hidden', user.role !== 'admin');
  show('team');
}

function signOut() {
  sessionStorage.removeItem(KEY);
  location.reload();
}

$$('.nav-item').forEach((b) => b.addEventListener('click', () => show(b.dataset.view)));
$$('.tab').forEach((b) =>
  b.addEventListener('click', () => {
    $$('.tab').forEach((t) => t.classList.toggle('active', t === b));
    loadAdmin(b.dataset.tab);
  }),
);
$('#logout').addEventListener('click', signOut);

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#login-error').textContent = '';
  const f = e.target;
  const { status, body } = await api('/api/login', {
    method: 'POST',
    body: JSON.stringify({ username: f.username.value, password: f.password.value }),
  });
  if (status !== 200) {
    $('#login-error').textContent = body.message || 'sign in failed';
    return;
  }
  save({ token: body.token, user: body.user });
  enter(body.user);
});

// Resume a previous session in this tab.
(async () => {
  const saved = load();
  if (!saved?.token) return;
  session = saved;
  const me = await api('/api/me');
  if (me.status === 200) enter(saved.user);
  else signOut();
})();

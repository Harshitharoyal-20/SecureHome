import { useCallback, useEffect, useMemo, useState } from 'react';
import './App.css';
import AdminAccessPanel from './AdminAccessPanel';

const API =
  import.meta.env.VITE_API_URL !== undefined
    ? import.meta.env.VITE_API_URL
    : typeof window !== 'undefined' &&
       (window.location.hostname === 'localhost' ||
        window.location.hostname === '127.0.0.1')
      ? ''
      : 'https://securehome-jv2h.onrender.com';

const PAGE_SIZE = 2;
const TIME_ZONE = 'Asia/Kolkata';

const PRIVILEGED_EMAILS = [
  'sivakumar6413@gmail.com',
  'harshitha0064@gmail.com',
  'pranawii0713@gmail.com'
];

const SECURITY_EMAILS = [
  'mahesh0562@gmail.com'
];

const ALERTS_DENIED_MESSAGE =
  "You can't view this, only administrators can view.";

function normalize(value) {
  return String(value ?? '').trim().toLowerCase();
}

function parseUtcDate(value) {
  if (!value) return null;
  const text = String(value).trim();
  const normalized = text.includes('T') ? text : text.replace(' ', 'T');
  const hasTimezone = /(?:Z|[+-]\d{2}:\d{2})$/i.test(normalized);
  return new Date(hasTimezone ? normalized : `${normalized}Z`);
}

function formatDate(value) {
  const date = parseUtcDate(value);
  if (!date || Number.isNaN(date.getTime())) return 'Not set';
  return new Intl.DateTimeFormat('en-IN', {
    timeZone: TIME_ZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
  }).format(date);
}

function getCurrentStatus(permission) {
  const active =
    permission.active ??
    permission.isActive ??
    permission.is_active ??
    false;
  if (active !== true && active !== 1 && active !== '1') return 'Revoked';

  const start = parseUtcDate(permission.validFrom ?? permission.valid_from);
  const end = parseUtcDate(permission.validUntil ?? permission.valid_until);

  if (!start || !end || Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
    return 'Active';
  }

  const now = Date.now();
  if (now < start.getTime()) return 'Scheduled';
  if (now > end.getTime()) return 'Expired';
  return 'Active';
}

function getAuthorities(authorities = []) {
  if (!Array.isArray(authorities)) return [];

  return authorities.map((item) => {
    if (typeof item === 'string') {
      return item.trim().toUpperCase();
    }

    return String(
      item?.authority ?? item?.name ?? item?.role ?? ''
    ).trim().toUpperCase();
  });
}

function hasAdminRole(authorities) {
  return getAuthorities(authorities).some(
    (role) => role === 'ROLE_ADMIN' || role === 'ADMIN'
  );
}

function isPrivilegedAccount(username) {
  return PRIVILEGED_EMAILS.includes(normalize(username));
}

function isSecurityAccount(username, authorities = []) {
  if (SECURITY_EMAILS.includes(normalize(username))) return true;
  return getAuthorities(authorities).some((role) =>
    role.includes('SECURITY')
  );
}

async function readResponse(response) {
  if (response.status === 204) return null;

  const text = await response.text();

  if (!text) return null;

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function responseMessage(body, fallback) {
  if (typeof body === 'string' && body.trim()) {
    return body;
  }

  return (
    body?.detail ||
    body?.message ||
    body?.error ||
    body?.title ||
    fallback
  );
}

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [credentials, setCredentials] = useState(null);
  const [passwordVerified, setPasswordVerified] = useState(false);
  const [verifyingPassword, setVerifyingPassword] = useState(false);

  const [lockers, setLockers] = useState([]);
  const [accessEvents, setAccessEvents] = useState([]);
  const [securityAlerts, setSecurityAlerts] = useState([]);
  const [myPermissions, setMyPermissions] = useState([]);

  const [lockerError, setLockerError] = useState('');
  const [accessError, setAccessError] = useState('');
  const [alertError, setAlertError] = useState('');
  const [loginError, setLoginError] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [page, setPage] = useState(1);
  const [activeSection, setActiveSection] = useState('dashboard');
  const [editingId, setEditingId] = useState(null);

  const [form, setForm] = useState({
    assetName: '',
    assetType: 'LOCKER',
    locationDescription: 'Private Room',
    ownerUserId: '1',
    status: 'ACTIVE'
  });

  const isAdmin =
    credentials?.isAdmin ??
    (hasAdminRole(credentials?.authorities) ||
      isPrivilegedAccount(credentials?.username) ||
      isPrivilegedAccount(credentials?.email));

  const isSecurity =
    credentials?.isSecurity ??
    isSecurityAccount(credentials?.username || credentials?.email, credentials?.authorities);

  const isGithubUser =
    credentials?.isGithub ??
    (credentials?.oauthAuthenticated === true);

  const apiFetch = useCallback(async (path, auth, options = {}) => {
    if (auth?.type !== 'session') {
      throw new Error('Please sign in first.');
    }

    const headers = {
      Accept: 'application/json',
      ...(options.body
        ? { 'Content-Type': 'application/json' }
        : {}),
      ...options.headers
    };

    const response = await fetch(`${API}${path}`, {
      ...options,
      credentials: 'include',
      headers
    });

    const body = await readResponse(response);

    if (response.status === 401) {
      const err = new Error(
        'Your session has expired. Please sign in again.'
      );
      err.status = 401;
      throw err;
    }

    if (response.status === 403) {
      const err = new Error(
        responseMessage(
          body,
          "You can't access this resource with this account."
        )
      );
      err.status = 403;
      throw err;
    }

    if (!response.ok) {
      const err = new Error(
        responseMessage(body, `Request failed (${response.status}).`)
      );
      err.status = response.status;
      throw err;
    }

    return body;
  }, []);

  const checkSession = useCallback(async () => {
    try {
      const response = await fetch(`${API}/api/me`, {
        credentials: 'include',
        headers: { Accept: 'application/json' }
      });

      if (!response.ok) return null;

      const user = await response.json();

      if (user.authenticated !== true) return null;

      const oauthAuthenticated = user.oauthAuthenticated === true;
      const verified =
        oauthAuthenticated || user.passwordVerified === true;

      return {
        type: 'session',
        username: user.username || user.email || '',
        email: user.email || '',
        fullName: user.fullName || '',
        userId: user.userId,
        role: user.role || '',
        isAdmin: user.isAdmin,
        isSecurity: user.isSecurity,
        isGithub: user.isGithub,
        authorities: user.authorities || [],
        passwordVerified: verified,
        oauthAuthenticated
      };
    } catch {
      return null;
    }
  }, []);

  const loadDashboard = useCallback(async (auth) => {
    if (auth?.type !== 'session') return;

    setLoading(true);
    setLockerError('');
    setAccessError('');
    setAlertError('');

    try {
      const results = await Promise.allSettled([
        apiFetch('/api/lockers', auth),
        apiFetch('/api/access-events', auth),
        apiFetch('/api/security-alerts', auth),
        apiFetch('/api/admin/permissions/my', auth)
      ]);

      if (results[0].status === 'fulfilled') {
        setLockers(
          Array.isArray(results[0].value)
            ? results[0].value
            : []
        );
      } else {
        setLockers([]);
        setLockerError(
          results[0].reason?.message ||
          'Unable to load lockers.'
        );
      }

      if (results[1].status === 'fulfilled') {
        setAccessEvents(
          Array.isArray(results[1].value)
            ? results[1].value
            : []
        );
      } else {
        setAccessEvents([]);
        setAccessError(
          results[1].reason?.message ||
          'Unable to load access history.'
        );
      }

      if (results[2].status === 'fulfilled') {
        setSecurityAlerts(
          Array.isArray(results[2].value)
            ? results[2].value
            : []
        );
      } else {
        setSecurityAlerts([]);

        const alertRequestError = results[2].reason;
        const status = alertRequestError?.status;

        setAlertError(
          status === 403
            ? ALERTS_DENIED_MESSAGE
            : alertRequestError?.message ||
              'Unable to load security alerts.'
        );
      }

      if (results[3].status === 'fulfilled') {
        setMyPermissions(
          Array.isArray(results[3].value)
            ? results[3].value
            : []
        );
      } else {
        setMyPermissions([]);
      }
    } finally {
      setLoading(false);
    }
  }, [apiFetch]);

  useEffect(() => {
    let active = true;

    async function restoreSession() {
      const user = await checkSession();

      if (!active) return;

      if (user) {
        setCredentials(user);

        const verified =
          user.oauthAuthenticated === true ||
          user.passwordVerified === true;

        setPasswordVerified(verified);

        if (verified) {
          await loadDashboard(user);
        }
      } else {
        setCredentials(null);
        setPasswordVerified(false);
      }

      if (active) {
        window.history.replaceState({}, document.title, '/');
      }
    }

    restoreSession();

    return () => {
      active = false;
    };
  }, [checkSession, loadDashboard]);

  async function handleEmailLogin(event) {
    event.preventDefault();
    setLoginError('');
    setVerifyingPassword(true);

    try {
      const response = await fetch(`${API}/api/auth/login`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify({
          email: email.trim(),
          password
        })
      });

      const result = await readResponse(response);

      if (!response.ok) {
        throw new Error(
          responseMessage(result, 'Email/password login failed.')
        );
      }

      const sessionUser = await checkSession();

      const user = sessionUser
        ? { ...sessionUser, passwordVerified: true }
        : {
            type: 'session',
            username: result?.username || email.trim(),
            authorities: result?.authorities || [],
            passwordVerified: true,
            oauthAuthenticated: false
          };

      setCredentials(user);
      setPasswordVerified(true);
      setPassword('');
      await loadDashboard(user);
    } catch (err) {
      setLoginError(
        err instanceof TypeError
          ? 'Unable to connect. Check the backend and CORS settings.'
          : err.message
      );
    } finally {
      setVerifyingPassword(false);
    }
  }

  function handleGitHubLogin() {
    setLoginError('');
    window.location.assign(
      `${API}/oauth2/authorization/github`
    );
  }

  async function logout() {
    try {
      await fetch(`${API}/logout`, {
        method: 'POST',
        credentials: 'include'
      });
    } catch {
      // Clear the interface even if the logout request fails.
    }

    setCredentials(null);
    setPasswordVerified(false);
    setVerifyingPassword(false);
    setPassword('');
    setEmail('');
    setLockers([]);
    setAccessEvents([]);
    setSecurityAlerts([]);
    setMyPermissions([]);
    setLockerError('');
    setAccessError('');
    setAlertError('');
    setError('');
    setMessage('');
    setLoginError('');
    setEditingId(null);
    setActiveSection('dashboard');
    window.history.replaceState({}, document.title, '/');
  }

  function resetLockerForm() {
    setEditingId(null);
    setForm({
      assetName: '',
      assetType: 'LOCKER',
      locationDescription: 'Private Room',
      ownerUserId: '1',
      status: 'ACTIVE'
    });
  }

  function startCreate() {
    setError('');
    setMessage('');

    if (!isAdmin) {
      setError('Only authorized administrators can create lockers.');
      return;
    }

    resetLockerForm();
  }

  function startEdit(asset) {
    if (!isAdmin) {
      setError('Only authorized administrators can edit lockers.');
      return;
    }

    setEditingId(asset.assetId);
    setForm({
      assetName: asset.assetName || '',
      assetType: asset.assetType || 'LOCKER',
      locationDescription: asset.locationDescription || '',
      ownerUserId: String(asset.ownerUserId ?? ''),
      status: asset.status || 'ACTIVE'
    });

    setError('');
    setMessage('');
  }

  async function saveLocker(event) {
    event.preventDefault();
    setError('');
    setMessage('');

    if (!isAdmin) {
      setError('Only authorized administrators can manage lockers.');
      return;
    }

    const name = form.assetName.trim();
    const location = form.locationDescription.trim();
    const owner = Number(form.ownerUserId);

    if (
      !name ||
      !location ||
      !Number.isInteger(owner) ||
      owner <= 0
    ) {
      setError(
        'Enter an asset name, location, and valid owner user ID.'
      );
      return;
    }

    const payload = {
      assetName: name,
      assetType: form.assetType,
      locationDescription: location,
      ownerUserId: owner,
      status: form.status
    };

    try {
      await apiFetch(
        editingId === null
          ? '/api/lockers'
          : `/api/lockers/${editingId}`,
        credentials,
        {
          method: editingId === null ? 'POST' : 'PUT',
          body: JSON.stringify(payload)
        }
      );

      setMessage(
        editingId === null
          ? 'Locker created.'
          : 'Locker updated.'
      );

      resetLockerForm();
      await loadDashboard(credentials);
    } catch (err) {
      setError(err.message);
    }
  }

  async function deleteLocker(asset) {
    if (!isAdmin) {
      setError('Only authorized administrators can delete lockers.');
      return;
    }

    if (!window.confirm(`Delete "${asset.assetName}"?`)) return;

    setError('');
    setMessage('');

    try {
      await apiFetch(
        `/api/lockers/${asset.assetId}`,
        credentials,
        { method: 'DELETE' }
      );

      setMessage('Locker deleted.');
      await loadDashboard(credentials);
    } catch (err) {
      setError(err.message);
    }
  }

  const filteredLockers = useMemo(() => {
    const term = normalize(search);

    return lockers.filter((locker) =>
      normalize(locker.assetName).includes(term) &&
      (typeFilter === 'ALL' ||
        locker.assetType === typeFilter) &&
      (statusFilter === 'ALL' ||
        locker.status === statusFilter)
    );
  }, [lockers, search, typeFilter, statusFilter]);

  const totalPages = Math.max(
    1,
    Math.ceil(filteredLockers.length / PAGE_SIZE)
  );

  const safePage = Math.min(page, totalPages);

  const visibleLockers = filteredLockers.slice(
    (safePage - 1) * PAGE_SIZE,
    safePage * PAGE_SIZE
  );

  if (!credentials || !passwordVerified) {
    return (
      <main className="login-page">
        <section className="login-card">
          <h1>SecureHome</h1>
          <p>Private Room Security System</p>

          <form onSubmit={handleEmailLogin}>
            <h2>Sign in with Email</h2>

            <label htmlFor="login-email">Email</label>
            <input
              id="login-email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />

            <label htmlFor="login-password">Password</label>
            <input
              id="login-password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />

            {loginError && (
              <p className="error" role="alert">
                {loginError}
              </p>
            )}

            <button type="submit" disabled={verifyingPassword}>
              {verifyingPassword
                ? 'Signing in...'
                : 'Sign in with Email'}
            </button>
          </form>

          <p>Or continue using GitHub</p>

          <button type="button" onClick={handleGitHubLogin}>
            Sign in with GitHub
          </button>
        </section>
      </main>
    );
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <h2>SecureHome</h2>
        <p className="side-subtitle">SMART SECURITY SYSTEM</p>

        <nav>
          <a
            href="#dashboard"
            onClick={() => setActiveSection('dashboard')}
          >
            Dashboard
          </a>

          <a
            href="#lockers"
            onClick={() => setActiveSection('lockers')}
          >
            My Lockers
          </a>

          {!isAdmin && (
            <a
              href="#my-permissions"
              onClick={() => setActiveSection('my-permissions')}
            >
              My Permissions
            </a>
          )}

          <a
            href="#access"
            onClick={() => setActiveSection('access')}
          >
            Access History
          </a>

          <a
            href="#alerts"
            onClick={() => setActiveSection('alerts')}
          >
            Security Alerts
          </a>

          {isAdmin && (
            <a
              href="#admin-permissions"
              onClick={() => setActiveSection('admin-permissions')}
            >
              Admin Permissions
            </a>
          )}
        </nav>

        <div className="sidebar-bottom">
          {isAdmin
            ? 'Administrator & Family Access'
            : isSecurity
              ? 'Security Staff Access'
              : 'GitHub User Access'}
        </div>
      </aside>

      <main className="main" id="dashboard">
        <header className="topbar">
          <div>
            <p className="eyebrow">PRIVATE ROOM PROTECTION</p>
            <h1>Security Dashboard</h1>
            <p className="muted">
              Monitor your private room and smart lockers.
            </p>
            <p className="muted">
              Signed in as: {credentials.fullName ? `${credentials.fullName} (${credentials.username})` : credentials.username}
            </p>
            <p className="muted">
              Account type:{' '}
              {isAdmin
                ? 'Administrator & Family Member Access'
                : isSecurity
                  ? 'Security Staff Access'
                  : 'GitHub User Access'}
            </p>
          </div>

          <button type="button" onClick={logout}>
            Log Out
          </button>
        </header>

        <section className="welcome">
          <div>
            <p className="eyebrow">WELCOME BACK</p>
            <h2>Your space. Your security.</h2>
            <p>
              {isAdmin
                ? 'Manage secure assets, user access permissions, and security alerts.'
                : isSecurity
                  ? 'Monitor secure lockers and track premises access events.'
                  : 'View secure assets authorized for your account and check your active permissions.'}
            </p>
          </div>

          <div className="shield">◆</div>
        </section>

        <section className="stats">
          <article className="stat-card">
            <p>Accessible Secure Assets</p>
            <h2>{lockers.length}</h2>
          </article>

          <article className="stat-card">
            <p>Active Assets</p>
            <h2>
              {lockers.filter(
                (asset) => asset.status === 'ACTIVE'
              ).length}
            </h2>
          </article>

          <article className="stat-card">
            <p>Protected Location</p>
            <h2>Private Room</h2>
          </article>
        </section>

        <section className="panel" id="lockers">
          <div className="section-heading">
            <div>
              <h2>My Secure Assets</h2>
              <p className="muted">
                Locker records available to your account.
              </p>
            </div>

            <div className="action-row">
              <button
                type="button"
                disabled={loading}
                onClick={() => loadDashboard(credentials)}
              >
                {loading ? 'Loading...' : 'Refresh'}
              </button>

              {isAdmin && (
                <button type="button" onClick={startCreate}>
                  Add Locker
                </button>
              )}
            </div>
          </div>

          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}

          {message && (
            <p className="success" role="status">
              {message}
            </p>
          )}

          {lockerError && (
            <p className="error" role="alert">
              {lockerError}
            </p>
          )}

          {isAdmin && (
            <form className="locker-form" onSubmit={saveLocker}>
              <h3>
                {editingId === null
                  ? 'Add a Locker'
                  : `Edit Locker #${editingId}`}
              </h3>

              <label htmlFor="assetName">Asset name</label>
              <input
                id="assetName"
                required
                maxLength={100}
                value={form.assetName}
                onChange={(event) =>
                  setForm({
                    ...form,
                    assetName: event.target.value
                  })
                }
              />

              <label htmlFor="assetType">Asset type</label>
              <select
                id="assetType"
                value={form.assetType}
                onChange={(event) =>
                  setForm({
                    ...form,
                    assetType: event.target.value
                  })
                }
              >
                <option value="LOCKER">Locker</option>
                <option value="SAFE">Safe</option>
              </select>

              <label htmlFor="location">Location</label>
              <input
                id="location"
                required
                maxLength={255}
                value={form.locationDescription}
                onChange={(event) =>
                  setForm({
                    ...form,
                    locationDescription: event.target.value
                  })
                }
              />

              <label htmlFor="owner">Owner user ID</label>
              <input
                id="owner"
                type="number"
                min="1"
                step="1"
                required
                value={form.ownerUserId}
                onChange={(event) =>
                  setForm({
                    ...form,
                    ownerUserId: event.target.value
                  })
                }
              />

              <label htmlFor="status">Status</label>
              <select
                id="status"
                value={form.status}
                onChange={(event) =>
                  setForm({
                    ...form,
                    status: event.target.value
                  })
                }
              >
                <option value="ACTIVE">Active</option>
                <option value="INACTIVE">Inactive</option>
              </select>

              <div className="action-row">
                <button type="submit">
                  {editingId === null
                    ? 'Create'
                    : 'Save Changes'}
                </button>

                {editingId !== null && (
                  <button
                    type="button"
                    onClick={resetLockerForm}
                  >
                    Cancel Edit
                  </button>
                )}
              </div>
            </form>
          )}

          {!isAdmin && (
            <p className="muted">
              View-only access. Locker management is restricted to
              authorized accounts.
            </p>
          )}

          <div className="locker-controls">
            <input
              type="search"
              placeholder="Search by locker name..."
              aria-label="Search lockers"
              value={search}
              onChange={(event) => {
                setSearch(event.target.value);
                setPage(1);
              }}
            />

            <select
              aria-label="Filter by type"
              value={typeFilter}
              onChange={(event) => {
                setTypeFilter(event.target.value);
                setPage(1);
              }}
            >
              <option value="ALL">All Types</option>
              <option value="LOCKER">Lockers</option>
              <option value="SAFE">Safes</option>
            </select>

            <select
              aria-label="Filter by status"
              value={statusFilter}
              onChange={(event) => {
                setStatusFilter(event.target.value);
                setPage(1);
              }}
            >
              <option value="ALL">All Statuses</option>
              <option value="ACTIVE">Active</option>
              <option value="INACTIVE">Inactive</option>
            </select>
          </div>

          <p>{filteredLockers.length} matching asset(s)</p>

          <div className="asset-grid">
            {visibleLockers.map((locker) => (
              <article
                className="asset-card"
                key={locker.assetId}
              >
                <div className="asset-top">
                  <span>
                    {locker.assetType === 'SAFE' ? '▤' : '▣'}
                  </span>

                  <span
                    className={`active-badge ${normalize(locker.status)}`}
                  >
                    {locker.status}
                  </span>
                </div>

                <h3>{locker.assetName}</h3>
                <p className="muted">{locker.assetType}</p>
                <p>{locker.locationDescription}</p>
                <p>
                  Asset ID: {locker.assetId} · Owner:{' '}
                  {locker.ownerUserId}
                </p>

                {isAdmin && (
                  <div className="action-row">
                    <button
                      type="button"
                      onClick={() => startEdit(locker)}
                    >
                      Edit
                    </button>

                    <button
                      type="button"
                      onClick={() => deleteLocker(locker)}
                    >
                      Delete
                    </button>
                  </div>
                )}
              </article>
            ))}
          </div>

          {visibleLockers.length === 0 && (
            <p role={lockerError ? 'alert' : 'status'}>
              {lockerError
                ? lockerError
                : loading
                  ? 'Loading your permitted lockers...'
                  : 'No accessible lockers found. Check that your permission is active, assigned to your account, and within its validity period.'}
            </p>
          )}

          <div className="pagination">
            <button
              type="button"
              disabled={safePage <= 1}
              onClick={() =>
                setPage((current) => Math.max(1, current - 1))
              }
            >
              Previous
            </button>

            <span>
              Page {safePage} of {totalPages}
            </span>

            <button
              type="button"
              disabled={safePage >= totalPages}
              onClick={() =>
                setPage((current) =>
                  Math.min(totalPages, current + 1)
                )
              }
            >
              Next
            </button>
          </div>
        </section>

        {!isAdmin && (
          <section className="panel" id="my-permissions">
            <div className="section-heading">
              <div>
                <h2>My Granted Permissions</h2>
                <p className="muted">
                  Lockers and safe access permissions granted to your account by administrators and family members.
                </p>
              </div>
              <button
                type="button"
                disabled={loading}
                onClick={() => loadDashboard(credentials)}
              >
                {loading ? 'Refreshing...' : 'Refresh'}
              </button>
            </div>

            {myPermissions.length > 0 ? (
              <div className="permission-cards-grid">
                {myPermissions.map((perm, idx) => {
                  const permId = perm.permissionId ?? perm.permission_id ?? idx;
                  const assetName = perm.assetName ?? perm.asset_name ?? 'Locker';
                  const assetType = perm.assetType ?? perm.asset_type ?? 'LOCKER';
                  const location = perm.location ?? perm.location_description ?? 'Private Room';
                  const from = formatDate(perm.validFrom ?? perm.valid_from);
                  const until = formatDate(perm.validUntil ?? perm.valid_until);
                  const status = getCurrentStatus(perm);

                  return (
                    <div className="granted-perm-card" key={permId}>
                      <div className="perm-header">
                        <span className="perm-icon">{assetType === 'SAFE' ? '▤' : '▣'}</span>
                        <span className={`perm-badge ${status.toLowerCase()}`}>{status}</span>
                      </div>
                      <h3>{assetName}</h3>
                      <p className="muted">{assetType} · {location}</p>
                      <div className="perm-timing">
                        <p><strong>Starts (IST):</strong> {from}</p>
                        <p><strong>Expires (IST):</strong> {until}</p>
                      </div>
                      <div className="perm-level">
                        <span className="perm-tag">✓ Authorized Access</span>
                        <span className="perm-note">Approved by Administrator</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="muted">
                {loading
                  ? 'Loading your granted permissions...'
                  : 'No active locker permissions have been granted to your account yet. Contact an administrator (Sivakumar, Harshitha, or Pranawii) to request access.'}
              </p>
            )}
          </section>
        )}

        {isAdmin && (
          <section className="panel" id="admin-permissions">
            <h2>Admin Permission Management</h2>
            <p className="muted">
              Grant or revoke locker access for GitHub users and family members for specific time windows.
            </p>

            <AdminAccessPanel
              apiFetch={apiFetch}
              credentials={credentials}
            />
          </section>
        )}

        <section className="lower-grid">
          <article className="panel" id="access">
            <div className="section-heading">
              <div>
                <h2>Access History</h2>
                <p className="muted">
                  {isAdmin
                    ? 'All system access and biometric verification logs.'
                    : isSecurity
                      ? 'Security monitoring: Viewing all locker access logs.'
                      : 'Showing your respective access history records.'}
                </p>
              </div>
            </div>

            {accessError && (
              <p className="error" role="alert">
                {accessError}
              </p>
            )}

            {accessEvents.map((event, index) => {
              const decision =
                event.decision ??
                event.access_decision ??
                'UNKNOWN';

              const eventId =
                event.eventId ?? event.event_id ?? 'N/A';

              const eventTime =
                event.eventTime ?? event.event_time;

              return (
                <div
                  className="access-item"
                  key={eventId === 'N/A' ? index : eventId}
                >
                  <div>
                    <strong>Event #{eventId}</strong>
                    <p>
                      User: {event.userId ?? event.user_id ?? 'Unknown'}
                      {' · '}
                      Asset: {event.assetId ?? event.asset_id ?? 'N/A'}
                    </p>
                    <p>Decision: {decision}</p>
                    <p>
                      Reason: {event.reason ?? 'Not specified'}
                    </p>
                    <small>
                      {eventTime
                        ? new Date(eventTime).toLocaleString()
                        : 'Time unavailable'}
                    </small>
                  </div>

                  <span
                    className={`status-badge ${normalize(decision)}`}
                  >
                    {decision}
                  </span>
                </div>
              );
            })}

            {accessEvents.length === 0 && (
              <p role={accessError ? 'alert' : 'status'}>
                {loading
                  ? 'Loading access history...'
                  : accessError ||
                    (isAdmin || isSecurity
                      ? 'No access history recorded yet.'
                      : 'No access history available for your account.')}
              </p>
            )}
          </article>

          <article className="panel" id="alerts">
            <h2>Security Alerts</h2>

            {!isAdmin ? (
              <div className="alert-restriction-card" role="alert">
                <span className="restriction-icon">🔒</span>
                <h3>Restricted Access</h3>
                <p className="restriction-text">
                  You can't view this, only administrators can view.
                </p>
              </div>
            ) : (
              <>
                {alertError && (
                  <p className="error" role="alert">
                    {alertError}
                  </p>
                )}

                {securityAlerts.map((alert, index) => {
                  const alertId =
                    alert.alertId ?? alert.alert_id ?? index;

                  const severity = alert.severity ?? 'UNKNOWN';

                  return (
                    <div className="access-item" key={alertId}>
                      <div>
                        <strong>Alert #{alertId}</strong>
                        <p>Severity: {severity}</p>
                        <p>
                          {alert.message ??
                            alert.alertMessage ??
                            alert.alert_message ??
                            'No message provided'}
                        </p>
                        <p>
                          Event ID: {alert.eventId ?? alert.event_id ?? 'N/A'}
                          {' · '}
                          Recipient:{' '}
                          {alert.recipientUserId ??
                            alert.recipient_user_id ??
                            'N/A'}
                        </p>
                        <p>Status: {alert.status ?? 'N/A'}</p>
                      </div>

                      <span
                        className={`status-badge ${normalize(severity)}`}
                      >
                        {severity}
                      </span>
                    </div>
                  );
                })}

                {securityAlerts.length === 0 && (
                  <p role={alertError ? 'alert' : 'status'}>
                    {alertError
                      ? alertError
                      : loading
                        ? 'Loading security alerts...'
                        : 'No security alerts available for this account.'}
                  </p>
                )}
              </>
            )}

            <p className="muted">
              Security alerts are available only to authorized
              administrators. Other accounts cannot access alert records.
            </p>
          </article>
        </section>

        <footer>
          SecureHome · Context-Aware Biometric Private Room and Smart
          Locker Security System
        </footer>
      </main>
    </div>
  );
}

export default App;

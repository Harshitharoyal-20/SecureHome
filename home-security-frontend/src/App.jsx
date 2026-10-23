
import { useEffect, useMemo, useState } from 'react';
import './App.css';

const API = 'https://securehome-jv2h.onrender.com';
const PAGE_SIZE = 2;
const MAHESH_EMAIL = 'mahesh0562@gmail.com';

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [credentials, setCredentials] = useState(null);
  const [passwordVerified, setPasswordVerified] = useState(false);
  const [verifyingPassword, setVerifyingPassword] = useState(false);

  const [lockers, setLockers] = useState([]);
  const [accessEvents, setAccessEvents] = useState([]);
  const [accessError, setAccessError] = useState('');
  const [securityAlerts, setSecurityAlerts] = useState([]);

  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [page, setPage] = useState(1);

  const [editingId, setEditingId] = useState(null);
  const [form, setForm] = useState({
    assetName: '',
    assetType: 'LOCKER',
    locationDescription: 'Private Room',
    ownerUserId: '1',
    status: 'ACTIVE'
  });

  const [loginError, setLoginError] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

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
    if (typeof body === 'string') return body;
    return body?.detail || body?.message || body?.error || fallback;
  }

  async function checkSession() {
    try {
      const response = await fetch(`${API}/api/me`, {
        credentials: 'include',
        headers: { Accept: 'application/json' }
      });

      if (!response.ok) return null;

      const user = await response.json();

      if (user.authenticated !== true) return null;

      const oauthAuthenticated =
        user.oauthAuthenticated === true;

      const verified =
        oauthAuthenticated || user.passwordVerified === true;

      return {
        type: 'session',
        username: user.username,
        authorities: user.authorities || [],
        passwordVerified: verified,
        oauthAuthenticated
      };
    } catch {
      return null;
    }
  }

  useEffect(() => {
    let active = true;

    async function restoreSession() {
      const user = await checkSession();

      if (!active) return;

      if (user) {
        setCredentials(user);
        setPasswordVerified(
          user.oauthAuthenticated === true ||
          user.passwordVerified === true
        );
        setPassword('');

        if (
          user.oauthAuthenticated === true ||
          user.passwordVerified === true
        ) {
          await loadDashboard(user);
        }
      } else {
        setCredentials(null);
        setPasswordVerified(false);
      }

      window.history.replaceState({}, document.title, '/');
    }

    restoreSession();

    return () => {
      active = false;
    };
  }, []);

  async function apiFetch(path, auth, options = {}) {
    if (auth?.type !== 'session') {
      throw new Error('Please sign in first.');
    }

    const headers = {
      Accept: 'application/json',
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...options.headers
    };

    const response = await fetch(`${API}${path}`, {
      ...options,
      credentials: 'include',
      headers
    });

    const body = await readResponse(response);

    if (response.status === 401) {
      throw new Error('Your session has expired. Please sign in again.');
    }

    if (response.status === 403) {
      throw new Error(
        responseMessage(
          body,
          'Access denied. Check your account permissions.'
        )
      );
    }

    if (!response.ok) {
      throw new Error(
        responseMessage(body, `Request failed (${response.status}).`)
      );
    }

    return body;
  }

  async function loadDashboard(auth) {
    if (auth?.type !== 'session') return;

    setLoading(true);
    setError('');

    try {
      const results = await Promise.allSettled([
        apiFetch('/api/lockers', auth),
        apiFetch('/api/access-events', auth),
        apiFetch('/api/security-alerts', auth)
      ]);

      const errors = [];

      if (results[0].status === 'fulfilled') {
        setLockers(
          Array.isArray(results[0].value) ? results[0].value : []
        );
      } else {
        setLockers([]);
        errors.push(`Lockers: ${results[0].reason.message}`);
      }

      if (results[1].status === 'fulfilled') {
        setAccessEvents(
          Array.isArray(results[1].value) ? results[1].value : []
        );
        setAccessError('');
      } else {
        setAccessEvents([]);

        const statusMessage = results[1].reason?.message || '';
        const isForbidden =
          statusMessage.includes('403') ||
          statusMessage.toLowerCase().includes('forbidden') ||
          statusMessage.toLowerCase().includes('access denied');

        const signedInEmail = String(auth.username || '')
          .trim()
          .toLowerCase();

        if (signedInEmail === MAHESH_EMAIL && isForbidden) {
          setAccessError(
            "You can't access the access history because you don't have permission."
          );
        } else {
          setAccessError('');
        }

        errors.push(`Access History: ${results[1].reason.message}`);
      }

      if (results[2].status === 'fulfilled') {
        setSecurityAlerts(
          Array.isArray(results[2].value) ? results[2].value : []
        );
      } else {
        setSecurityAlerts([]);
        errors.push(`Security Alerts: ${results[2].reason.message}`);
      }

      if (errors.length) {
        setError(errors.join(' | '));
      }
    } finally {
      setLoading(false);
    }
  }

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

      const user = await checkSession();

      if (user) {
        const verifiedUser = {
          ...user,
          passwordVerified: true
        };

        setCredentials(verifiedUser);
        setPasswordVerified(true);
        setPassword('');
        await loadDashboard(verifiedUser);
      } else {
        const fallbackUser = {
          type: 'session',
          username: result.username || email.trim(),
          authorities: result.authorities || [],
          passwordVerified: true,
          oauthAuthenticated: false
        };

        setCredentials(fallbackUser);
        setPasswordVerified(true);
        setPassword('');
        await loadDashboard(fallbackUser);
      }
    } catch (err) {
      setLoginError(
        err instanceof TypeError
          ? 'Unable to connect to SecureHome. Check the backend and CORS configuration.'
          : err.message
      );
    } finally {
      setVerifyingPassword(false);
    }
  }

  function handleGitHubLogin() {
    setLoginError('');
    window.location.assign(`${API}/oauth2/authorization/github`);
  }

  async function logout() {
    try {
      await fetch(`${API}/logout`, {
        method: 'POST',
        credentials: 'include'
      });
    } catch {}

    setCredentials(null);
    setPasswordVerified(false);
    setVerifyingPassword(false);
    setPassword('');
    setEmail('');
    setLockers([]);
    setAccessEvents([]);
    setAccessError('');
    setSecurityAlerts([]);
    setError('');
    setMessage('');
    setLoginError('');
    setEditingId(null);

    window.history.replaceState({}, document.title, '/');
  }

  function startCreate() {
    setEditingId(null);
    setForm({
      assetName: '',
      assetType: 'LOCKER',
      locationDescription: 'Private Room',
      ownerUserId: '1',
      status: 'ACTIVE'
    });
    setError('');
    setMessage('');
  }

  function startEdit(asset) {
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

    const name = form.assetName.trim();
    const location = form.locationDescription.trim();
    const owner = Number(form.ownerUserId);

    if (!name || !location || !Number.isInteger(owner) || owner <= 0) {
      setError('Enter an asset name, location, and valid owner ID.');
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
        editingId === null ? 'Locker created.' : 'Locker updated.'
      );

      startCreate();
      await loadDashboard(credentials);
    } catch (err) {
      setError(err.message);
    }
  }

  async function deleteLocker(asset) {
    if (!window.confirm(`Delete "${asset.assetName}"?`)) return;

    setError('');
    setMessage('');

    try {
      await apiFetch(`/api/lockers/${asset.assetId}`, credentials, {
        method: 'DELETE'
      });

      setMessage('Locker deleted.');
      await loadDashboard(credentials);
    } catch (err) {
      setError(err.message);
    }
  }

  const filteredLockers = useMemo(() => {
    return lockers.filter((locker) => {
      const term = search.toLowerCase();

      return (
        (locker.assetName || '').toLowerCase().includes(term) &&
        (typeFilter === 'ALL' || locker.assetType === typeFilter) &&
        (statusFilter === 'ALL' || locker.status === statusFilter)
      );
    });
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
              <p className="error" role="alert">{loginError}</p>
            )}

            <button type="submit" disabled={verifyingPassword}>
              {verifyingPassword ? 'Signing in...' : 'Sign in with Email'}
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
          <a href="#dashboard">Dashboard</a>
          <a href="#lockers">My Lockers</a>
          <a href="#access">Access History</a>
          <a href="#alerts">Security Alerts</a>
        </nav>

        <div className="sidebar-bottom">Context-Aware Security</div>
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
              Signed in as: {credentials.username}
            </p>
          </div>

          <button type="button" onClick={logout}>Log Out</button>
        </header>

        <section className="welcome">
          <div>
            <p className="eyebrow">WELCOME BACK</p>
            <h2>Your space. Your security.</h2>
            <p>Manage your secure assets from one place.</p>
          </div>
          <div className="shield">◆</div>
        </section>

        <section className="stats">
          <article className="stat-card">
            <p>Total Secure Assets</p>
            <h2>{lockers.length}</h2>
          </article>

          <article className="stat-card">
            <p>Active Assets</p>
            <h2>
              {lockers.filter((asset) => asset.status === 'ACTIVE').length}
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
              <p className="muted">Locker records from MySQL.</p>
            </div>

            <div className="action-row">
              <button
                type="button"
                disabled={loading}
                onClick={() => loadDashboard(credentials)}
              >
                {loading ? 'Loading...' : 'Refresh'}
              </button>
              <button type="button" onClick={startCreate}>Add Locker</button>
            </div>
          </div>

          {error && <p className="error" role="alert">{error}</p>}
          {message && <p className="success" role="status">{message}</p>}

          <form className="locker-form" onSubmit={saveLocker}>
            <h3>
              {editingId === null ? 'Add a Locker' : `Edit Locker #${editingId}`}
            </h3>

            <label htmlFor="assetName">Asset name</label>
            <input
              id="assetName"
              required
              maxLength={100}
              value={form.assetName}
              onChange={(event) =>
                setForm({ ...form, assetName: event.target.value })
              }
            />

            <label htmlFor="assetType">Asset type</label>
            <select
              id="assetType"
              value={form.assetType}
              onChange={(event) =>
                setForm({ ...form, assetType: event.target.value })
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
                setForm({ ...form, locationDescription: event.target.value })
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
                setForm({ ...form, ownerUserId: event.target.value })
              }
            />

            <label htmlFor="status">Status</label>
            <select
              id="status"
              value={form.status}
              onChange={(event) =>
                setForm({ ...form, status: event.target.value })
              }
            >
              <option value="ACTIVE">Active</option>
              <option value="INACTIVE">Inactive</option>
            </select>

            <div className="action-row">
              <button type="submit">
                {editingId === null ? 'Create' : 'Save Changes'}
              </button>

              {editingId !== null && (
                <button type="button" onClick={startCreate}>
                  Cancel Edit
                </button>
              )}
            </div>
          </form>

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
              <article className="asset-card" key={locker.assetId}>
                <div className="asset-top">
                  <span>{locker.assetType === 'SAFE' ? '▤' : '▣'}</span>
                  <span
                    className={`active-badge ${String(
                      locker.status || ''
                    ).toLowerCase()}`}
                  >
                    {locker.status}
                  </span>
                </div>

                <h3>{locker.assetName}</h3>
                <p className="muted">{locker.assetType}</p>
                <p>{locker.locationDescription}</p>
                <p>
                  Asset ID: {locker.assetId} · Owner: {locker.ownerUserId}
                </p>

                <div className="action-row">
                  <button type="button" onClick={() => startEdit(locker)}>
                    Edit
                  </button>
                  <button type="button" onClick={() => deleteLocker(locker)}>
                    Delete
                  </button>
                </div>
              </article>
            ))}
          </div>

          {visibleLockers.length === 0 && <p>No matching lockers found.</p>}

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

            <span>Page {safePage} of {totalPages}</span>

            <button
              type="button"
              disabled={safePage >= totalPages}
              onClick={() =>
                setPage((current) => Math.min(totalPages, current + 1))
              }
            >
              Next
            </button>
          </div>
        </section>

        <section className="lower-grid">
          <article className="panel" id="access">
            <h2>Access History</h2>

            {accessEvents.map((event, index) => (
              <div
                className="access-item"
                key={event.eventId ?? event.event_id ?? index}
              >
                <div>
                  <strong>
                    Event #{event.eventId ?? event.event_id ?? 'N/A'}
                  </strong>
                  <p>
                    User: {event.userId ?? event.user_id ?? 'Unknown'} · Asset:{' '}
                    {event.assetId ?? event.asset_id ?? 'N/A'}
                  </p>
                  <p>
                    Decision: {event.decision ?? event.access_decision ?? 'N/A'}
                  </p>
                  <p>Reason: {event.reason ?? 'Not specified'}</p>
                  <small>
                    {event.eventTime || event.event_time
                      ? new Date(
                          event.eventTime ?? event.event_time
                        ).toLocaleString()
                      : 'Time unavailable'}
                  </small>
                </div>

                <span
                  className={`status-badge ${String(
                    event.decision ?? event.access_decision ?? ''
                  ).toLowerCase()}`}
                >
                  {event.decision ?? event.access_decision ?? 'UNKNOWN'}
                </span>
              </div>
            ))}

            {accessEvents.length === 0 && (
              <p role={accessError ? 'alert' : 'status'}>
                {loading
                  ? 'Loading access history...'
                  : accessError ||
                    (String(credentials.username || '').trim().toLowerCase() === MAHESH_EMAIL
                      ? "You can't access the access history because you don't have permission."
                      : 'No access history available. Check the API response if records exist in MySQL.')}
              </p>
            )}
          </article>

          <article className="panel" id="alerts">
            <h2>Security Alerts</h2>

            {securityAlerts.map((alert, index) => (
              <div
                className="access-item"
                key={alert.alertId ?? alert.alert_id ?? index}
              >
                <div>
                  <strong>
                    Alert #{alert.alertId ?? alert.alert_id ?? 'N/A'}
                  </strong>
                  <p>Severity: {alert.severity ?? 'N/A'}</p>
                  <p>
                    {alert.message ?? alert.alert_message ?? 'No message provided'}
                  </p>
                  <p>
                    Event ID: {alert.eventId ?? alert.event_id ?? 'N/A'} ·
                    Recipient: {alert.recipientUserId ?? alert.recipient_user_id ?? 'N/A'}
                  </p>
                  <p>Status: {alert.status ?? 'N/A'}</p>
                </div>

                <span
                  className={`status-badge ${String(
                    alert.severity || ''
                  ).toLowerCase()}`}
                >
                  {alert.severity ?? 'UNKNOWN'}
                </span>
              </div>
            ))}

            {securityAlerts.length === 0 && (
              <p>
                {loading
                  ? 'Loading security alerts...'
                  : 'No security alerts available. Check the API response if records exist in MySQL.'}
              </p>
            )}
          </article>
        </section>

        <footer>
          SecureHome · Context-Aware Biometric Private Room and Smart Locker Security System
        </footer>
      </main>
    </div>
  );
}

export default App;

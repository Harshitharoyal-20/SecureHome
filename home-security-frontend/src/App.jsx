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
  const [showPassword, setShowPassword] = useState(false);
  const [credentials, setCredentials] = useState(null);
  const [passwordVerified, setPasswordVerified] = useState(false);
  const [verifyingPassword, setVerifyingPassword] = useState(false);

  const [lockers, setLockers] = useState([]);
  const [accessEvents, setAccessEvents] = useState([]);
  const [activeAccessList, setActiveAccessList] = useState([]);
  const [githubNotifications, setGithubNotifications] = useState([]);
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
  const [permPage, setPermPage] = useState(1);
  const PERM_PAGE_SIZE = 4;
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

    const isUserAdmin =
      auth.isAdmin ??
      (hasAdminRole(auth.authorities) ||
        isPrivilegedAccount(auth.username) ||
        isPrivilegedAccount(auth.email));

    try {
      const promises = [
        apiFetch('/api/lockers', auth),
        apiFetch('/api/access-events', auth),
        apiFetch('/api/security-alerts', auth),
        apiFetch('/api/admin/permissions/my', auth),
        apiFetch('/api/access-events/active-now', auth).catch(() => [])
      ];

      if (isUserAdmin) {
        promises.push(
          apiFetch('/api/admin/github-notifications', auth).catch(() => [])
        );
      }

      const results = await Promise.allSettled(promises);

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

      if (results[4]?.status === 'fulfilled') {
        setActiveAccessList(
          Array.isArray(results[4].value)
            ? results[4].value
            : []
        );
      } else {
        setActiveAccessList([]);
      }

      if (isUserAdmin && results[5]?.status === 'fulfilled') {
        setGithubNotifications(
          Array.isArray(results[5].value)
            ? results[5].value
            : []
        );
      }
    } finally {
      setLoading(false);
    }
  }, [apiFetch]);

  const dismissGithubNotification = useCallback(
    async (id) => {
      setGithubNotifications((prev) => prev.filter((n) => n.id !== id));
      if (credentials) {
        try {
          await apiFetch(`/api/admin/github-notifications/${id}/dismiss`, credentials, {
            method: 'POST'
          });
        } catch {
          // optimistic dismissal
        }
      }
    },
    [apiFetch, credentials]
  );

  useEffect(() => {
    if (!credentials || !passwordVerified || !isAdmin) return;

    const interval = setInterval(async () => {
      try {
        const notifs = await apiFetch('/api/admin/github-notifications', credentials);
        if (Array.isArray(notifs)) {
          setGithubNotifications(notifs);
        }
      } catch {
        // silent background poll
      }
    }, 15000);

    return () => clearInterval(interval);
  }, [credentials, passwordVerified, isAdmin, apiFetch]);

  useEffect(() => {
    let active = true;

    async function restoreSession() {
      const params = new URLSearchParams(window.location.search);
      if (params.get('oauth') === 'error') {
        const errorMsg = params.get('error') || 'GitHub sign-in could not be completed.';
        setLoginError(errorMsg);
      }

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

  const totalPermPages = Math.max(
    1,
    Math.ceil(myPermissions.length / PERM_PAGE_SIZE)
  );

  const safePermPage = Math.min(permPage, totalPermPages);

  const visibleMyPermissions = myPermissions.slice(
    (safePermPage - 1) * PERM_PAGE_SIZE,
    safePermPage * PERM_PAGE_SIZE
  );

  const currentlyActiveAccess = useMemo(() => {
    if (activeAccessList && activeAccessList.length > 0) {
      return activeAccessList;
    }
    if (!isAdmin && myPermissions && myPermissions.length > 0) {
      return myPermissions
        .filter((p) => getCurrentStatus(p) === 'Active')
        .map((p) => ({
          assetId: p.assetId ?? p.asset_id,
          assetName: p.assetName ?? p.asset_name,
          assetType: p.assetType ?? p.asset_type ?? 'LOCKER',
          location: p.location ?? p.location_description ?? 'Private Room',
          validFrom: p.validFrom ?? p.valid_from,
          validUntil: p.validUntil ?? p.valid_until,
          activeNow: 1
        }));
    }
    if (isAdmin && lockers && lockers.length > 0) {
      return lockers.map((l) => ({
        assetId: l.assetId,
        assetName: l.assetName,
        assetType: l.assetType,
        location: l.locationDescription,
        validFrom: null,
        validUntil: null,
        activeNow: 1
      }));
    }
    return [];
  }, [activeAccessList, myPermissions, isAdmin, lockers]);

  const displayedAccessEvents = useMemo(() => {
    if (accessEvents && accessEvents.length > 0) {
      return accessEvents;
    }
    if (!isAdmin && myPermissions && myPermissions.length > 0) {
      return myPermissions.map((p, idx) => ({
        eventId: `P-${p.permissionId ?? p.permission_id ?? idx + 1}`,
        assetId: p.assetId ?? p.asset_id,
        assetName: p.assetName ?? p.asset_name ?? 'Locker',
        assetType: p.assetType ?? p.asset_type ?? 'LOCKER',
        location: p.location ?? p.location_description ?? 'Private Room',
        decision: getCurrentStatus(p) === 'Active' ? 'ALLOWED' : (getCurrentStatus(p) === 'Revoked' ? 'REVOKED' : 'EXPIRED'),
        reason: 'Authorized Locker Access (Approved by Administrator)',
        eventTime: p.validFrom ?? p.valid_from ?? new Date().toISOString(),
        validFrom: p.validFrom ?? p.valid_from,
        validUntil: p.validUntil ?? p.valid_until,
        activeNow: getCurrentStatus(p) === 'Active' ? 1 : 0
      }));
    }
    return [];
  }, [accessEvents, myPermissions, isAdmin]);

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
            <div className="password-input-wrapper">
              <input
                id="login-password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
              <button
                type="button"
                className="password-toggle-btn"
                onClick={() => setShowPassword((prev) => !prev)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                title={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                    <line x1="1" y1="1" x2="23" y2="23"></line>
                  </svg>
                ) : (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                    <circle cx="12" cy="12" r="3"></circle>
                  </svg>
                )}
              </button>
            </div>

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
        {isAdmin && githubNotifications.length > 0 && (
          <aside className="github-popup-wrapper" role="region" aria-label="GitHub Access Notifications">
            {githubNotifications.map((notif) => (
              <div className="github-popup-banner" key={notif.id}>
                <div className="popup-left">
                  <div className="popup-badge">
                    <span className="popup-pulse"></span>
                    <svg className="github-svg-icon" width="22" height="22" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                      <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
                    </svg>
                  </div>
                  <div className="popup-info">
                    <strong className="popup-username">
                      {notif.githubUsername || 'A GitHub user'} is trying to access
                    </strong>
                    <span className="popup-time">
                      GitHub login attempt · {notif.accessTime ? formatDate(notif.accessTime) : 'Just now'}
                    </span>
                  </div>
                </div>
                <button
                  type="button"
                  className="popup-close-button"
                  onClick={() => dismissGithubNotification(notif.id)}
                  aria-label="Remove notification"
                  title="Dismiss notification"
                >
                  ✕
                </button>
              </div>
            ))}
          </aside>
        )}

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
              <>
                <div className="permission-cards-grid">
                  {visibleMyPermissions.map((perm, idx) => {
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

                {myPermissions.length > PERM_PAGE_SIZE && (
                  <div className="pagination">
                    <button
                      type="button"
                      disabled={safePermPage <= 1}
                      onClick={() => setPermPage((curr) => Math.max(1, curr - 1))}
                    >
                      Previous
                    </button>
                    <span>
                      Page {safePermPage} of {totalPermPages} ({myPermissions.length} total)
                    </span>
                    <button
                      type="button"
                      disabled={safePermPage >= totalPermPages}
                      onClick={() => setPermPage((curr) => Math.min(totalPermPages, curr + 1))}
                    >
                      Next
                    </button>
                  </div>
                )}
              </>
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
          <article className="panel access-history-panel" id="access">
            <div className="access-history-header">
              <div className="access-history-title-wrap">
                <h2>Access History</h2>
                <p className="muted">
                  {isAdmin
                    ? 'All system access and biometric verification logs.'
                    : isSecurity
                      ? 'Security staff: Showing your personal access records and active locker authorization.'
                      : 'Showing your respective personal access records and active locker authorization.'}
                </p>
              </div>
              <button
                type="button"
                className="access-refresh-btn"
                disabled={loading}
                onClick={() => loadDashboard(credentials)}
              >
                {loading ? 'Refreshing...' : 'Refresh'}
              </button>
            </div>

            {/* Currently Accessing Section */}
            <div className="currently-accessing-box">
              <div className="box-title-row">
                <span className="live-dot" aria-hidden="true"></span>
                <h3>Currently Accessing (Active in Your Account)</h3>
              </div>
              {currentlyActiveAccess.length > 0 ? (
                <div className="currently-active-grid">
                  {currentlyActiveAccess.map((asset, idx) => (
                    <div className="active-access-chip" key={asset.assetId || idx}>
                      <span className="chip-icon">{asset.assetType === 'SAFE' ? '▤' : '▣'}</span>
                      <div className="chip-details">
                        <strong className="chip-name">{asset.assetName || `Locker #${asset.assetId}`}</strong>
                        <span className="chip-loc">{asset.assetType || 'LOCKER'} · {asset.location || 'Private Room'}</span>
                        <span className="chip-period">
                          {asset.validFrom && asset.validUntil
                            ? `Valid Window: ${formatDate(asset.validFrom)} – ${formatDate(asset.validUntil)}`
                            : 'Status: Live Access Window Open'}
                        </span>
                      </div>
                      <span className="chip-active-badge">Active Now</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="muted no-active-text">
                  No locker or safe is currently within an active access window for this account.
                </p>
              )}
            </div>

            {/* Access Events & History */}
            {accessError && (
              <p className="error" role="alert">
                {accessError}
              </p>
            )}

            {displayedAccessEvents.length > 0 && (
              <div className="access-events-section">
                <div className="access-cards-list">
                  {displayedAccessEvents.map((event, index) => {
                    const decision =
                      event.decision ??
                      event.access_decision ??
                      'UNKNOWN';
                    const isAllowed = decision === 'ALLOWED';

                    const eventId =
                      event.eventId ?? event.event_id ?? index;

                    const eventTime =
                      event.eventTime ?? event.event_time;

                    const assetName =
                      event.assetName ?? `Locker #${event.assetId ?? event.asset_id ?? 'N/A'}`;

                    const assetType =
                      event.assetType ?? 'LOCKER';

                    const location =
                      event.location ?? 'Private Room';

                    const userName =
                      event.userName ?? (event.userEmail ? event.userEmail : `User #${event.userId}`);

                    const isCurrentlyActive =
                      event.activeNow === 1 || event.activeNow === true;

                    return (
                      <div
                        className={`access-event-card ${isAllowed ? 'event-allowed' : 'event-denied'}`}
                        key={eventId}
                      >
                        <div className="event-card-header">
                          <div className="event-asset-info">
                            <span className="event-type-icon">
                              {assetType === 'SAFE' ? '▤' : '▣'}
                            </span>
                            <div>
                              <h4 className="event-asset-title">{assetName}</h4>
                              <span className="event-asset-subtitle">
                                {assetType} · {location}
                              </span>
                            </div>
                          </div>

                          <div className="event-badges">
                            {isCurrentlyActive && (
                              <span className="active-now-tag">Active Right Now</span>
                            )}
                            <span className={`status-badge ${normalize(decision)}`}>
                              {isAllowed ? '✓ ALLOWED' : '✕ DENIED'}
                            </span>
                          </div>
                        </div>

                        <div className="event-card-body">
                          <div className="event-info-grid">
                            <div className="info-item">
                              <span className="info-label">Access Time (IST)</span>
                              <span className="info-value">
                                {eventTime ? formatDate(eventTime) : 'Time unavailable'}
                              </span>
                            </div>

                            {(event.validFrom || event.validUntil) && (
                              <div className="info-item">
                                <span className="info-label">Permitted Window</span>
                                <span className="info-value">
                                  {formatDate(event.validFrom)} – {formatDate(event.validUntil)}
                                </span>
                              </div>
                            )}

                            {isAdmin && (
                              <div className="info-item">
                                <span className="info-label">Account User</span>
                                <span className="info-value">{userName}</span>
                              </div>
                            )}

                            <div className="info-item full-width">
                              <span className="info-label">Verification Reason</span>
                              <span className="info-value reason-value">
                                {event.reason || 'Verification record processed'}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </article>

          <article className="panel" id="alerts">
            <h2>Security Alerts</h2>

            {!isAdmin && !isSecurity ? (
              <div className="alert-restriction-card" role="alert">
                <span className="restriction-icon">🔒</span>
                <h3>Restricted Access</h3>
                <p className="restriction-text">
                  You can't view this, only administrators can view.
                </p>
              </div>
            ) : (
              <>
                {isSecurity && (
                  <p className="security-notice">
                    🚨 High-Risk Security Alerts · Monitored by Security Staff
                  </p>
                )}

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
                        : isSecurity
                          ? 'No high-risk security alerts recorded.'
                          : 'No security alerts available.'}
                  </p>
                )}
              </>
            )}

            <p className="muted">
              {isAdmin
                ? 'Security alerts are available only to authorized administrators.'
                : isSecurity
                  ? 'Security monitoring: Showing high-risk security alerts on premises.'
                  : 'Security alerts are available only to authorized administrators.'}
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

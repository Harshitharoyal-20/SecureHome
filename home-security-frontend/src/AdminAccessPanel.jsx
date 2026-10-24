
import { useCallback, useEffect, useMemo, useState } from 'react';

const BASE = '/api/admin/permissions';
const TIME_ZONE = 'Asia/Kolkata';

function getUserId(user) {
  return user.userId ?? user.user_id;
}

function getAssetId(asset) {
  return asset.assetId ?? asset.asset_id;
}

function getPermissionId(permission) {
  return permission.permissionId ?? permission.permission_id;
}

function getUserLabel(user) {
  const name = user.fullName ?? user.full_name ?? '';
  const email = user.email ?? '';
  const id = getUserId(user);
  const isGithub = user.isGithub === true || user.isGithub === 1 || user.isGithub === '1';
  const tag = isGithub ? ' [GitHub User]' : '';

  if (name && email) return `${name} — ${email}${tag}`;
  return `${name || email || `User ${id}`}${tag}`;
}

function getAssetName(asset) {
  return asset.assetName ?? asset.asset_name ?? 'Unnamed asset';
}

function getPermissionAssetName(permission) {
  return permission.assetName ?? permission.asset_name ?? 'Unknown asset';
}

function getPermissionEmail(permission) {
  return permission.email ?? 'Unknown user';
}

function getPermissionName(permission) {
  return permission.fullName ?? permission.full_name ?? '';
}

function getValidFrom(permission) {
  return permission.validFrom ?? permission.valid_from ?? null;
}

function getValidUntil(permission) {
  return permission.validUntil ?? permission.valid_until ?? null;
}

function isPermissionActive(permission) {
  const value =
    permission.active ??
    permission.isActive ??
    permission.is_active ??
    false;

  return value === true || value === 1 || value === '1';
}

function parseUtcDate(value) {
  if (!value) return null;

  const text = String(value).trim();
  const normalized = text.includes('T') ? text : text.replace(' ', 'T');
  const hasTimezone = /(?:Z|[+-]\d{2}:\d{2})$/i.test(normalized);

  return new Date(hasTimezone ? normalized : `${normalized}Z`);
}

function localDateTimeToUtc(value) {
  if (!value) return '';

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    throw new Error('Please enter a valid start and end time.');
  }

  return date.toISOString().slice(0, 19);
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
  if (!isPermissionActive(permission)) return 'Revoked';

  const start = parseUtcDate(getValidFrom(permission));
  const end = parseUtcDate(getValidUntil(permission));

  if (
    !start ||
    !end ||
    Number.isNaN(start.getTime()) ||
    Number.isNaN(end.getTime())
  ) {
    return 'Invalid dates';
  }

  const now = Date.now();

  if (now < start.getTime()) return 'Scheduled';
  if (now > end.getTime()) return 'Expired';

  return 'Active';
}

export default function AdminAccessPanel({ apiFetch, credentials }) {
  const [users, setUsers] = useState([]);
  const [lockers, setLockers] = useState([]);
  const [permissions, setPermissions] = useState([]);
  const [userId, setUserId] = useState('');
  const [assetId, setAssetId] = useState('');
  const [validFrom, setValidFrom] = useState('');
  const [validUntil, setValidUntil] = useState('');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 4;

  const load = useCallback(async () => {
    setLoading(true);
    setError('');

    try {
      const [userData, assetData, permissionData] = await Promise.all([
        apiFetch(`${BASE}/users`, credentials),
        apiFetch(`${BASE}/assets`, credentials),
        apiFetch(BASE, credentials)
      ]);

      setUsers(Array.isArray(userData) ? userData : []);
      setLockers(Array.isArray(assetData) ? assetData : []);
      setPermissions(Array.isArray(permissionData) ? permissionData : []);
    } catch (err) {
      setError(err.message || 'Could not load permission data.');
    } finally {
      setLoading(false);
    }
  }, [apiFetch, credentials]);

  useEffect(() => {
    load();
  }, [load]);

  async function grant(event) {
    event.preventDefault();
    setError('');
    setMessage('');

    if (!userId || !assetId || !validFrom || !validUntil) {
      setError('Select a user, locker, start time, and expiry time.');
      return;
    }

    const startDate = new Date(validFrom);
    const expiryDate = new Date(validUntil);

    if (
      Number.isNaN(startDate.getTime()) ||
      Number.isNaN(expiryDate.getTime()) ||
      expiryDate <= startDate
    ) {
      setError('Expiry must be later than the start date.');
      return;
    }

    setBusy(true);

    try {
      await apiFetch(BASE, credentials, {
        method: 'POST',
        body: JSON.stringify({
          userId: Number(userId),
          assetId: Number(assetId),
          validFrom: localDateTimeToUtc(validFrom),
          validUntil: localDateTimeToUtc(validUntil)
        })
      });

      setMessage('View-only permission saved successfully.');
      setValidFrom('');
      setValidUntil('');
      await load();
    } catch (err) {
      setError(err.message || 'Could not grant permission.');
    } finally {
      setBusy(false);
    }
  }

  async function revoke(permission) {
    const permissionId = getPermissionId(permission);

    if (permissionId == null) {
      setError('Permission ID is missing. Cannot revoke this record.');
      return;
    }

    if (!window.confirm(
      `Revoke access to ${getPermissionAssetName(permission)} for ${getPermissionEmail(permission)}?`
    )) {
      return;
    }

    setError('');
    setMessage('');
    setBusy(true);

    try {
      await apiFetch(`${BASE}/${permissionId}`, credentials, {
        method: 'DELETE'
      });

      setMessage('Permission revoked successfully.');
      await load();
    } catch (err) {
      setError(err.message || 'Could not revoke permission.');
    } finally {
      setBusy(false);
    }
  }

  const userMap = useMemo(() => {
    const map = new Map();
    users.forEach((u) => {
      map.set(Number(getUserId(u)), u);
    });
    return map;
  }, [users]);

  return (
    <section className="admin-access-panel" id="manage-access">
      <div className="section-heading">
        <div>
          <h2>Manage Access</h2>
          <p className="muted">
            Grant, view, or revoke time-limited access for GitHub users and family members.
          </p>
          <p className="muted">
            Times are displayed in India Standard Time (IST). Any administrator can grant or revoke permissions.
          </p>
        </div>
        <button type="button" onClick={load} disabled={busy || loading}>
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {error && <p className="error" role="alert">{error}</p>}
      {message && <p className="success" role="status">{message}</p>}

      <form className="locker-form" onSubmit={grant}>
        <h3>Grant Locker Permission</h3>

        <label htmlFor="permission-user">Select User (GitHub visitors or registered family)</label>
        <select
          id="permission-user"
          value={userId}
          onChange={event => setUserId(event.target.value)}
          required
          disabled={busy || loading}
        >
          <option value="">Select a user</option>
          {users.map(user => {
            const id = getUserId(user);
            return <option key={id} value={id}>{getUserLabel(user)}</option>;
          })}
        </select>

        <label htmlFor="permission-locker">Locker or safe</label>
        <select
          id="permission-locker"
          value={assetId}
          onChange={event => setAssetId(event.target.value)}
          required
          disabled={busy || loading}
        >
          <option value="">Select a locker</option>
          {lockers.map(locker => {
            const id = getAssetId(locker);
            return (
              <option key={id} value={id}>
                {getAssetName(locker)} (ID {id})
              </option>
            );
          })}
        </select>

        <label htmlFor="permission-start">Access starts (IST)</label>
        <input
          id="permission-start"
          type="datetime-local"
          value={validFrom}
          onChange={event => setValidFrom(event.target.value)}
          required
          disabled={busy}
        />

        <label htmlFor="permission-expiry">Access expires (IST)</label>
        <input
          id="permission-expiry"
          type="datetime-local"
          value={validUntil}
          onChange={event => setValidUntil(event.target.value)}
          required
          disabled={busy}
        />

        <p className="muted">
          <strong>Permission level:</strong> View locker details only.
          This does not grant create, edit, delete, or physical unlock
          privileges.
        </p>

        <button type="submit" disabled={busy || loading}>
          {busy ? 'Saving...' : 'Grant / Update Permission'}
        </button>
      </form>

      <h3>Permission Records</h3>
      {loading && <p>Loading permission records...</p>}

      {(() => {
        const totalPages = Math.max(1, Math.ceil(permissions.length / pageSize));
        const safePage = Math.min(page, totalPages);
        const visiblePermissions = permissions.slice(
          (safePage - 1) * pageSize,
          safePage * pageSize
        );

        return (
          <>
            <div className="permission-table-wrap">
              <table className="permission-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Locker</th>
                    <th>Starts (IST)</th>
                    <th>Expires (IST)</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {visiblePermissions.map((permission, index) => {
                    const id = getPermissionId(permission);
                    const fullName = getPermissionName(permission);
                    const email = getPermissionEmail(permission);
                    const targetUserId = Number(permission.userId ?? permission.user_id);
                    const linkedUser = userMap.get(targetUserId);
                    const isGithub = linkedUser?.isGithub === true || linkedUser?.isGithub === 1 || linkedUser?.isGithub === '1';

                    return (
                      <tr key={id ?? index}>
                        <td>
                          {fullName && <>{fullName}<br /></>}
                          <span>{email}</span>
                          {isGithub && <span className="github-tag" title="User accessed through GitHub">GitHub</span>}
                        </td>
                        <td>{getPermissionAssetName(permission)}</td>
                        <td>{formatDate(getValidFrom(permission))}</td>
                        <td>{formatDate(getValidUntil(permission))}</td>
                        <td>{getCurrentStatus(permission)}</td>
                        <td>
                          {isPermissionActive(permission) && (
                            <button
                              type="button"
                              disabled={busy || loading}
                              onClick={() => revoke(permission)}
                            >
                              Revoke
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {permissions.length > pageSize && (
              <div className="pagination">
                <button
                  type="button"
                  disabled={safePage <= 1}
                  onClick={() => setPage(curr => Math.max(1, curr - 1))}
                >
                  Previous
                </button>
                <span>
                  Page {safePage} of {totalPages} ({permissions.length} total records)
                </span>
                <button
                  type="button"
                  disabled={safePage >= totalPages}
                  onClick={() => setPage(curr => Math.min(totalPages, curr + 1))}
                >
                  Next
                </button>
              </div>
            )}
          </>
        );
      })()}

      {!loading && permissions.length === 0 && (
        <p>No permission records found.</p>
      )}
      {users.length === 0 && !loading && (
        <p className="muted">No registered users were returned by the server.</p>
      )}
      {lockers.length === 0 && !loading && (
        <p className="muted">No lockers were returned by the server.</p>
      )}
    </section>
  );
}

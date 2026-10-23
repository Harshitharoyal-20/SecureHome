
import { useCallback, useEffect, useState } from 'react';

const BASE = '/api/admin/permissions';

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

  if (name && email) return `${name} — ${email}`;
  return name || email || `User ${id}`;
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

function formatDate(value) {
  if (!value) return 'Not set';

  return String(value).replace('T', ' ').slice(0, 19);
}

function getCurrentStatus(permission) {
  if (!isPermissionActive(permission)) return 'Revoked';

  const fromValue = getValidFrom(permission);
  const untilValue = getValidUntil(permission);
  const now = new Date();

  if (!fromValue || !untilValue) return 'Invalid dates';

  const start = new Date(fromValue);
  const end = new Date(untilValue);

  if (
    Number.isNaN(start.getTime()) ||
    Number.isNaN(end.getTime())
  ) {
    return 'Invalid dates';
  }

  if (now < start) return 'Scheduled';
  if (now > end) return 'Expired';

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
      setPermissions(
        Array.isArray(permissionData) ? permissionData : []
      );
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
      setError('Select a user, locker, start date, and expiry date.');
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
          validFrom,
          validUntil
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

    const lockerName = getPermissionAssetName(permission);
    const userEmail = getPermissionEmail(permission);

    if (
      !window.confirm(
        `Revoke access to ${lockerName} for ${userEmail}?`
      )
    ) {
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

  return (
    <section className="admin-access-panel" id="manage-access">
      <div className="section-heading">
        <div>
          <h2>Manage Access</h2>
          <p className="muted">
            Grant, view, or revoke time-limited access to a locker or safe.
          </p>
        </div>

        <button
          type="button"
          onClick={load}
          disabled={busy || loading}
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
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

      <form className="locker-form" onSubmit={grant}>
        <h3>Grant Locker Permission</h3>

        <label htmlFor="permission-user">Registered user</label>
        <select
          id="permission-user"
          value={userId}
          onChange={(event) => setUserId(event.target.value)}
          required
          disabled={busy || loading}
        >
          <option value="">Select a user</option>
          {users.map((user) => {
            const id = getUserId(user);

            return (
              <option key={id} value={id}>
                {getUserLabel(user)}
              </option>
            );
          })}
        </select>

        <label htmlFor="permission-locker">Locker or safe</label>
        <select
          id="permission-locker"
          value={assetId}
          onChange={(event) => setAssetId(event.target.value)}
          required
          disabled={busy || loading}
        >
          <option value="">Select a locker</option>
          {lockers.map((locker) => {
            const id = getAssetId(locker);

            return (
              <option key={id} value={id}>
                {getAssetName(locker)} (ID {id})
              </option>
            );
          })}
        </select>

        <label htmlFor="permission-start">Access starts</label>
        <input
          id="permission-start"
          type="datetime-local"
          value={validFrom}
          onChange={(event) => setValidFrom(event.target.value)}
          required
          disabled={busy}
        />

        <label htmlFor="permission-expiry">Access expires</label>
        <input
          id="permission-expiry"
          type="datetime-local"
          value={validUntil}
          onChange={(event) => setValidUntil(event.target.value)}
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

      <div className="permission-table-wrap">
        <table className="permission-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Locker</th>
              <th>Starts</th>
              <th>Expires</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>

          <tbody>
            {permissions.map((permission, index) => {
              const id = getPermissionId(permission);
              const status = getCurrentStatus(permission);
              const fullName = getPermissionName(permission);
              const email = getPermissionEmail(permission);

              return (
                <tr key={id ?? index}>
                  <td>
                    {fullName && (
                      <>
                        {fullName}
                        <br />
                      </>
                    )}
                    {email}
                  </td>

                  <td>{getPermissionAssetName(permission)}</td>
                  <td>{formatDate(getValidFrom(permission))}</td>
                  <td>{formatDate(getValidUntil(permission))}</td>
                  <td>{status}</td>

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

      {!loading && permissions.length === 0 && (
        <p>No permission records found.</p>
      )}

      {users.length === 0 && !loading && (
        <p className="muted">
          No registered users were returned by the server.
        </p>
      )}

      {lockers.length === 0 && !loading && (
        <p className="muted">
          No lockers were returned by the server.
        </p>
      )}
    </section>
  );
}


import { useCallback, useEffect, useState } from 'react';

export default function AdminAccessPanel({ apiFetch, credentials }) {
  const [users, setUsers] = useState([]);
  const [lockers, setLockers] = useState([]);
  const [permissions, setPermissions] = useState([]);

  const [userId, setUserId] = useState('');
  const [assetId, setAssetId] = useState('');
  const [validFrom, setValidFrom] = useState('');
  const [validUntil, setValidUntil] = useState('');

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const base = '/api/admin/permissions';

  const load = useCallback(async () => {
    setError('');

    try {
      const [userData, assetData, permissionData] = await Promise.all([
        apiFetch(`${base}/users`, credentials),
        apiFetch(`${base}/assets`, credentials),
        apiFetch(base, credentials)
      ]);

      setUsers(Array.isArray(userData) ? userData : []);
      setLockers(Array.isArray(assetData) ? assetData : []);
      setPermissions(
        Array.isArray(permissionData) ? permissionData : []
      );
    } catch (err) {
      setError(err.message || 'Could not load permission data.');
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
      setError('Select a user, locker, start time and expiry time.');
      return;
    }

    const startDate = new Date(validFrom);
    const expiryDate = new Date(validUntil);

    if (
      Number.isNaN(startDate.getTime()) ||
      Number.isNaN(expiryDate.getTime()) ||
      expiryDate <= startDate
    ) {
      setError('Expiry must be later than the start time.');
      return;
    }

    setBusy(true);

    try {
      await apiFetch(base, credentials, {
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
    const permissionId =
      permission.permissionId ??
      permission.permission_id;

    if (!permissionId) {
      setError('Permission ID is missing. Cannot revoke this record.');
      return;
    }

    const lockerName =
      permission.assetName ??
      permission.asset_name ??
      'this locker';

    const userEmail =
      permission.email ??
      'this user';

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
      await apiFetch(`${base}/${permissionId}`, credentials, {
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

  function formatDate(value) {
    if (!value) return 'Not set';

    const text = String(value);

    if (text.includes('T')) {
      return text.replace('T', ' ').slice(0, 16);
    }

    return text;
  }

  function getPermissionActive(permission) {
    return (
      permission.active ??
      permission.isActive ??
      permission.is_active ??
      false
    );
  }

  function getPermissionId(permission) {
    return permission.permissionId ?? permission.permission_id;
  }

  function getAssetName(permission) {
    return permission.assetName ?? permission.asset_name ?? 'Unknown asset';
  }

  function getEmail(permission) {
    return permission.email ?? 'Unknown user';
  }

  function getFullName(permission) {
    return permission.fullName ?? permission.full_name ?? '';
  }

  function getValidFrom(permission) {
    return permission.validFrom ?? permission.valid_from ?? null;
  }

  function getValidUntil(permission) {
    return permission.validUntil ?? permission.valid_until ?? null;
  }

  function getUserId(user) {
    return user.userId ?? user.user_id;
  }

  function getAssetId(asset) {
    return asset.assetId ?? asset.asset_id;
  }

  function getUserLabel(user) {
    const name = user.fullName ?? user.full_name ?? '';
    const email = user.email ?? '';

    if (name && email) return `${name} — ${email}`;

    return name || email || `User ${getUserId(user)}`;
  }

  function getAssetLabel(asset) {
    const name = asset.assetName ?? asset.asset_name ?? 'Unnamed asset';
    const id = getAssetId(asset);

    return `${name} (ID ${id})`;
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
          disabled={busy}
        >
          Refresh
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
        <h3>Grant or Update Permission</h3>

        <label htmlFor="permission-user">
          Registered user
        </label>

        <select
          id="permission-user"
          value={userId}
          onChange={(event) => setUserId(event.target.value)}
          required
          disabled={busy}
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

        <label htmlFor="permission-locker">
          Locker or safe
        </label>

        <select
          id="permission-locker"
          value={assetId}
          onChange={(event) => setAssetId(event.target.value)}
          required
          disabled={busy}
        >
          <option value="">Select a locker</option>

          {lockers.map((locker) => {
            const id = getAssetId(locker);

            return (
              <option key={id} value={id}>
                {getAssetLabel(locker)}
              </option>
            );
          })}
        </select>

        <label htmlFor="permission-start">
          Access starts
        </label>

        <input
          id="permission-start"
          type="datetime-local"
          value={validFrom}
          onChange={(event) => setValidFrom(event.target.value)}
          required
          disabled={busy}
        />

        <label htmlFor="permission-expiry">
          Access expires
        </label>

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
          This permission does not grant create, edit, delete, or physical
          unlock privileges.
        </p>

        <button type="submit" disabled={busy}>
          {busy ? 'Saving...' : 'Grant / Update Permission'}
        </button>
      </form>

      <h3>Permission Records</h3>

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
              const permissionId = getPermissionId(permission);
              const isActive = Boolean(
                getPermissionActive(permission)
              );

              const validFromValue = getValidFrom(permission);
              const validUntilValue = getValidUntil(permission);

              const start = validFromValue
                ? new Date(validFromValue)
                : null;

              const end = validUntilValue
                ? new Date(validUntilValue)
                : null;

              const now = new Date();

              const withinTimeWindow =
                (!start ||
                  (!Number.isNaN(start.getTime()) && now >= start)) &&
                (!end ||
                  (!Number.isNaN(end.getTime()) && now <= end));

              const status = !isActive
                ? 'Revoked'
                : withinTimeWindow
                  ? 'Active'
                  : 'Scheduled / Expired';

              const fullName = getFullName(permission);
              const email = getEmail(permission);

              return (
                <tr
                  key={permissionId ?? index}
                >
                  <td>
                    {fullName && (
                      <>
                        {fullName}
                        <br />
                      </>
                    )}
                    {email}
                  </td>

                  <td>{getAssetName(permission)}</td>

                  <td>{formatDate(validFromValue)}</td>

                  <td>{formatDate(validUntilValue)}</td>

                  <td>{status}</td>

                  <td>
                    {isActive && (
                      <button
                        type="button"
                        disabled={busy}
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

      {permissions.length === 0 && (
        <p>No permission records found.</p>
      )}
    </section>
  );
}

import React, { useEffect, useState } from 'react';
import axios from 'axios';
import Toast from '../../components/Toast';
import { useAuth } from '../../contexts/AuthContext';

export default function PendingMedicines() {
  const { token } = useAuth();
  const [pending, setPending] = useState([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState('');
  const [processingId, setProcessingId] = useState(null);

  // Fetch pending medicines when token changes
  useEffect(() => {
    const fetchPending = async () => {
      setLoading(true);
      try {
        const res = await axios.get('http://localhost:5000/api/medicines?status=pending', {
          headers: { Authorization: `Bearer ${token}` },
        });
        setPending(res.data);
      } catch (error) {
        setToast(error.response?.data?.message || 'Failed to load pending medicines');
      }
      setLoading(false);
    };

    if (token) {
      fetchPending();
    } else {
      setPending([]);
      setLoading(false);
    }
  }, [token]);

  // Auto-clear toast after 3 seconds
  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(''), 3000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  const handleAction = async (id, action) => {
    setProcessingId(id);
    try {
      await axios.put(`http://localhost:5000/api/medicines/${id}/${action}`, {}, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setToast(`Medicine ${action}d!`);
      // Refresh pending list after action
      const res = await axios.get('http://localhost:5000/api/medicines?status=pending', {
        headers: { Authorization: `Bearer ${token}` },
      });
      setPending(res.data);
    } catch (error) {
      setToast(error.response?.data?.message || `Failed to ${action} medicine`);
    }
    setProcessingId(null);
  };

  if (loading) 
    // Replace below div with your Loader component if available
    return <div style={{ padding: 24, textAlign: 'center' }}>Loading pending medicines...</div>;

  return (
    <div
      style={{
        maxWidth: 900,
        margin: 'auto',
        padding: 24,
        fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
      }}
    >
      <Toast message={toast} clear={() => setToast('')} />
      <h2>Admin Panel — Pending Medicines</h2>

      {pending.length === 0 ? (
        <div style={{ fontStyle: 'italic', color: '#555', marginTop: 20 }}>
          No pending medicines.
        </div>
      ) : (
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 16,
            marginTop: 20,
          }}
        >
          {pending.map((med) => (
            <div
              key={med._id}
              style={{
                width: 280,
                borderRadius: 10,
                boxShadow: '0 2px 8px rgba(0,0,0,0.12)',
                border: '1px solid #ddd',
                padding: 16,
                backgroundColor: '#fff',
                userSelect: 'none',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
              }}
            >
              <div>
                <h3 style={{ marginTop: 0, fontWeight: 'bold' }}>{med.name}</h3>
                <p>
                  Expiry: <b>{new Date(med.expiryDate).toLocaleDateString()}</b>
                </p>
                <p>
                  Quantity: <b>{med.quantity}</b>
                </p>
                <p>Donor: {med.donor?.name || med.donor?.email || 'Unknown'}</p>
                {med.photoUrl && (
                  <img
                    src={med.photoUrl.startsWith('http') ? med.photoUrl : `http://localhost:5000${med.photoUrl}`}
                    alt={med.name}
                    style={{ width: '100%', maxHeight: 140, objectFit: 'cover', borderRadius: 6, marginBottom: 10 }}
                    draggable={false}
                  />
                )}
              </div>

              <div style={{ display: 'flex', gap: 10 }}>
                <button
                  onClick={() => handleAction(med._id, 'approve')}
                  disabled={processingId === med._id}
                  aria-label={`Approve medicine ${med.name}`}
                  style={{
                    backgroundColor: processingId === med._id ? '#81c784' : '#2e7d32',
                    color: 'white',
                    border: 'none',
                    borderRadius: 6,
                    padding: '7px 15px',
                    cursor: processingId === med._id ? 'not-allowed' : 'pointer',
                    flex: 1,
                    transition: 'background-color 0.25s',
                  }}
                  onMouseOver={(e) =>
                    processingId !== med._id && (e.currentTarget.style.backgroundColor = '#27632a')
                  }
                  onMouseOut={(e) =>
                    processingId !== med._id && (e.currentTarget.style.backgroundColor = '#2e7d32')
                  }
                  type="button"
                >
                  Approve
                </button>

                <button
                  onClick={() => handleAction(med._id, 'reject')}
                  disabled={processingId === med._id}
                  aria-label={`Reject medicine ${med.name}`}
                  style={{
                    backgroundColor: processingId === med._id ? '#ef9a9a' : '#c62828',
                    color: 'white',
                    border: 'none',
                    borderRadius: 6,
                    padding: '7px 15px',
                    cursor: processingId === med._id ? 'not-allowed' : 'pointer',
                    flex: 1,
                    transition: 'background-color 0.25s',
                  }}
                  onMouseOver={(e) => processingId !== med._id && (e.currentTarget.style.backgroundColor = '#9a2222')}
                  onMouseOut={(e) => processingId !== med._id && (e.currentTarget.style.backgroundColor = '#c62828')}
                  type="button"
                >
                  Reject
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

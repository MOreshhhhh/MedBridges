import React, { useEffect, useState } from 'react';
import axios from 'axios';
import Toast from '../../components/Toast';
import { useAuth } from '../../contexts/AuthContext';

export default function NGODashboard() {
  const { token } = useAuth();
  const [medicines, setMedicines] = useState([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState('');

  useEffect(() => {
    fetchApproved();
  }, []);

  const fetchApproved = async () => {
    setLoading(true);
    try {
      const res = await axios.get('http://localhost:5000/api/medicines?status=approved', {
        headers: { Authorization: `Bearer ${token}` },
      });
      setMedicines(res.data);
    } catch {
      setToast('Failed to load medicines');
    }
    setLoading(false);
  };

  const handleClaim = async (id) => {
    try {
      await axios.post(`http://localhost:5000/api/medicines/claim/${id}`, {}, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setToast('Medicine claimed!');
      fetchApproved();
    } catch {
      setToast('Claim failed');
    }
  };

  if (loading) {
    return (
      <div style={{
        padding: 24,
        fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
        color: '#1976d2',
        fontWeight: '600',
        fontSize: 18,
        textAlign: 'center',
        userSelect: 'none',
      }}>
        Loading medicines...
      </div>
    );
  }

  return (
    <div style={{
      maxWidth: 900,
      margin: 'auto',
      padding: 24,
      fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
    }}>
      <Toast message={toast} clear={() => setToast('')} />
      <h2 style={{ marginBottom: 24, color: '#1976d2', userSelect: 'none' }}>
        NGO Dashboard — Available Medicines
      </h2>

      {medicines.length === 0 ? (
        <div style={{ textAlign: 'center', fontStyle: 'italic', color: '#666', userSelect: 'none' }}>
          No approved medicines available at the moment.
        </div>
      ) : (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16 }}>
          {medicines.map(med => (
            <div
              key={med._id}
              tabIndex={0}
              role="group"
              aria-label={`Medicine ${med.name}, expires on ${new Date(med.expiryDate).toLocaleDateString()}, quantity ${med.quantity}`}
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
                cursor: 'pointer',
                transition: 'transform 0.25s ease, box-shadow 0.25s ease',
              }}
              onMouseOver={e => {
                e.currentTarget.style.transform = 'translateY(-4px)';
                e.currentTarget.style.boxShadow = '0 12px 32px rgba(25, 118, 210, 0.3)';
              }}
              onMouseOut={e => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = '0 2px 8px rgba(0,0,0,0.12)';
              }}
              onFocus={e => {
                e.currentTarget.style.boxShadow = '0 0 0 3px rgba(25, 118, 210, 0.5)';
                e.currentTarget.style.outline = 'none';
              }}
              onBlur={e => {
                e.currentTarget.style.boxShadow = '0 2px 8px rgba(172, 133, 133, 0.12)';
              }}
            >
              <div>
                <h3 style={{ marginTop: 0, fontWeight: '700', marginBottom: 12 }}>{med.name}</h3>
                <p style={{ margin: '4px 0' }}>Expiry: <b>{new Date(med.expiryDate).toLocaleDateString()}</b></p>
                <p style={{ margin: '4px 0 12px' }}>Quantity: <b>{med.quantity}</b></p>
                {med.photoUrl && (
                  <img
                    src={med.photoUrl.startsWith('http') ? med.photoUrl : `http://localhost:5000${med.photoUrl}`}
                    alt={med.name}
                    style={{
                      width: '100%',
                      maxHeight: 140,
                      objectFit: 'cover',
                      borderRadius: 6,
                      marginBottom: 10,
                      userSelect: 'none',
                    }}
                    draggable={false}
                  />
                )}
              </div>

              <button
                onClick={() => handleClaim(med._id)}
                style={{
                  backgroundColor: '#1976d2',
                  color: 'white',
                  border: 'none',
                  borderRadius: 6,
                  padding: '10px 0',
                  cursor: 'pointer',
                  fontWeight: '600',
                  fontSize: 16,
                  width: '100%',
                  userSelect: 'none',
                  transition: 'background-color 0.3s ease, transform 0.2s ease',
                }}
                onMouseOver={e => {
                  e.currentTarget.style.backgroundColor = '#155a9f';
                  e.currentTarget.style.transform = 'scale(1.05)';
                }}
                onMouseOut={e => {
                  e.currentTarget.style.backgroundColor = '#1976d2';
                  e.currentTarget.style.transform = 'scale(1)';
                }}
                aria-label={`Claim medicine ${med.name}`}
                type="button"
              >
                Claim Medicine
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

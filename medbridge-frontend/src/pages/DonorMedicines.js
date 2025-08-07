import React, { useEffect, useState } from "react";
import axios from "axios";
import { useAuth } from "../contexts/AuthContext";

const statusColors = {
  pending: "#f9a825",
  approved: "#388e3c",
  rejected: "#d32f2f",
  claimed: "#1976d2",
  picked_up: "#0288d1",
  delivered: "#2e7d32",
};

const DonorMedicines = () => {
  const { token } = useAuth();
  const [myMeds, setMyMeds] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) return;
    setLoading(true);
    axios
      .get("http://localhost:5000/api/medicines/my", {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => setMyMeds(res.data))
      .catch(() => setMyMeds([]))
      .finally(() => setLoading(false));
  }, [token]);

  return (
    <div
      style={{
        maxWidth: 900,
        margin: "32px auto",
        padding: "0 16px",
        fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
      }}
    >
      <h2 style={{ color: "#1976d2", marginBottom: 24 }}>My Donations</h2>

      {loading ? (
        <div
          style={{ color: "#666", fontStyle: "italic", textAlign: "center" }}
          role="status"
          aria-live="polite"
        >
          Loading medicines...
        </div>
      ) : myMeds.length === 0 ? (
        <div
          style={{
            color: "#857f7f",
            fontStyle: "italic",
            textAlign: "center",
            padding: 20,
            userSelect: "none",
          }}
        >
          You have not donated any medicines yet.
        </div>
      ) : (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 24,
            justifyContent: "flex-start",
          }}
        >
          {myMeds.map((med) => (
            <div
              key={med._id}
              style={{
                flex: "1 0 280px",
                backgroundColor: "#fafafa",
                borderRadius: 12,
                boxShadow: "0 2px 10px rgba(0,0,0,0.08)",
                padding: 16,
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                userSelect: "none",
                cursor: "default",
              }}
              tabIndex={0}
              aria-label={`Medicine ${med.name}, quantity ${med.quantity}, status ${med.status}`}
              role="group"
            >
              <div
                style={{
                  fontWeight: "700",
                  fontSize: 20,
                  marginBottom: 6,
                  textAlign: "center",
                  color: "#222",
                }}
              >
                {med.name}
              </div>

              <div style={{ fontSize: 14, color: "#444", marginBottom: 6 }}>
                Quantity: <b>{med.quantity}</b>
              </div>

              <div style={{ fontSize: 14, color: "#444", marginBottom: 12 }}>
                Expiry Date: <b>{new Date(med.expiryDate).toLocaleDateString()}</b>
              </div>

              {med.photoUrl ? (
                <img
                  src={
                    med.photoUrl.startsWith("http")
                      ? med.photoUrl
                      : `http://localhost:5000${med.photoUrl}`
                  }
                  alt={`${med.name}`}
                  style={{
                    width: "100%",
                    maxHeight: 120,
                    objectFit: "cover",
                    borderRadius: 8,
                    marginBottom: 12,
                    userSelect: "none",
                    pointerEvents: "none",
                  }}
                  draggable={false}
                />
              ) : (
                <div
                  style={{
                    width: "100%",
                    height: 120,
                    backgroundColor: "#ddd",
                    borderRadius: 8,
                    display: "flex",
                    justifyContent: "center",
                    alignItems: "center",
                    marginBottom: 12,
                    color: "#777",
                    fontStyle: "italic",
                    userSelect: "none",
                  }}
                >
                  No photo available
                </div>
              )}

              <div
                style={{
                  padding: "6px 14px",
                  borderRadius: 20,
                  backgroundColor: statusColors[med.status] || "#555",
                  color: "#fff",
                  fontWeight: "600",
                  textTransform: "capitalize",
                  fontSize: 14,
                  userSelect: "none",
                  minWidth: 90,
                  textAlign: "center",
                  boxShadow: `0 2px 8px ${
                    statusColors[med.status]
                      ? statusColors[med.status] + "99"
                      : "#00000066"
                  }`,
                }}
                aria-label={`Status: ${med.status}`}
              >
                {med.status.replace(/_/g, " ")}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default DonorMedicines;

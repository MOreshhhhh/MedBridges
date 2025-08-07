// src/pages/MedicinesList.js
import React, { useEffect, useState } from "react";
import axios from "axios";
import Modal from "react-modal";

// Loader component with spinner and text for better UX
const Loader = () => (
  <div
    style={{
      textAlign: "center",
      padding: "3em",
      fontSize: 18,
      color: "#1976d2",
      userSelect: "none",
      fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
    }}
    aria-live="polite"
    role="status"
  >
    <div
      aria-hidden="true"
      style={{
        margin: "0 auto 18px",
        width: 48,
        height: 48,
        border: "6px solid #cfd0d1",
        borderTopColor: "#1976d2",
        borderRadius: "50%",
        animation: "spin 1.2s linear infinite",
      }}
    />
    Loading...
    <style>{`
      @keyframes spin {
        0% { transform: rotate(0deg);}
        100% { transform: rotate(360deg);}
      }
    `}</style>
  </div>
);

Modal.setAppElement("#root"); // For accessibility

const getToken = () => localStorage.getItem("token");
const getRole = () => {
  const token = getToken();
  if (!token) return null;
  try {
    const base64Url = token.split(".")[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split("")
        .map((c) => {
          return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
        })
        .join("")
    );
    return JSON.parse(jsonPayload).role;
  } catch {
    return null;
  }
};

const MedicinesList = () => {
  const [meds, setMeds] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [message, setMessage] = useState("");
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    setLoading(true);
    axios
      .get("http://localhost:5000/api/medicines/")
      .then((res) => setMeds(res.data))
      .catch(() => setMeds([]))
      .finally(() => setLoading(false));
  }, []);

  // Handle claiming medicine (for NGO role)
  const handleClaim = async (med) => {
    const token = getToken();
    try {
      await axios.post(
        `http://localhost:5000/api/medicines/claim/${med._id}`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );
      // Update status locally in list and modal
      setMeds(
        meds.map((m) =>
          m._id === med._id ? { ...m, status: "claimed" } : m
        )
      );
      setMessage("Medicine claimed!");
      setTimeout(() => setMessage(""), 2000);
      if (selected && selected._id === med._id)
        setSelected({ ...med, status: "claimed" });
    } catch (err) {
      setMessage(err.response?.data?.error || "Claim failed");
      setTimeout(() => setMessage(""), 2000);
    }
  };

  if (loading) return <Loader />;

  return (
    <div
      style={{
        maxWidth: 940,
        margin: "40px auto",
        padding: "0 20px 40px",
        fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
        userSelect: "none",
      }}
    >
      <h2
        style={{
          color: "#1976d2",
          fontWeight: "700",
          marginBottom: 24,
          userSelect: "none",
          fontSize: 32,
          textAlign: "center",
        }}
      >
        Available Medicines
      </h2>

      {message && (
        <div
          style={{
            backgroundColor: "#e3f2fd",
            border: "1.5px solid #90caf9",
            color: "#1565c0",
            borderRadius: 6,
            padding: "12px 20px",
            marginBottom: 20,
            fontWeight: "600",
            textAlign: "center",
            boxShadow: "0 3px 8px rgba(25, 118, 210, 0.2)",
            userSelect: "none",
            animation: "slideFadeIn 0.4s ease forwards",
          }}
          role="alert"
          aria-live="assertive"
        >
          {message}
          <style>{`
            @keyframes slideFadeIn {
              0% {
                opacity: 0;
                transform: translateY(-16px);
              }
              100% {
                opacity: 1;
                transform: translateY(0);
              }
            }
          `}</style>
        </div>
      )}

      <input
        aria-label="Search medicines"
        placeholder="Search medicine..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        style={{
          marginBottom: 25,
          padding: "12px 18px",
          fontSize: 16,
          width: "100%",
          maxWidth: 460,
          borderRadius: 10,
          border: "1.5px solid #bbb",
          transition: "border-color 0.3s ease, box-shadow 0.3s ease",
          outlineOffset: "2px",
          outline: "none",
          userSelect: "text",
          display: "block",
          marginLeft: "auto",
          marginRight: "auto",
        }}
        onFocus={(e) => {
          e.currentTarget.style.borderColor = "#1976d2";
          e.currentTarget.style.boxShadow = "0 0 8px #1976d2aa";
          e.currentTarget.style.outline = "2px solid #1976d2";
        }}
        onBlur={(e) => {
          e.currentTarget.style.borderColor = "#bbb";
          e.currentTarget.style.boxShadow = "none";
          e.currentTarget.style.outline = "none";
        }}
      />

      {meds.filter(med => med.name.toLowerCase().includes(search.toLowerCase())).length === 0 ? (
        <div
          style={{
            textAlign: "center",
            fontStyle: "italic",
            color: "#666",
            marginTop: 40,
            fontSize: 18,
          }}
        >
          No medicines match your search.
        </div>
      ) : (
        <ul
          style={{
            listStyle: "none",
            padding: 0,
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill,minmax(280px,1fr))",
            gap: 24,
            userSelect: "none",
          }}
        >
          {meds
            .filter((med) => med.name.toLowerCase().includes(search.toLowerCase()))
            .map((med, idx) => (
              <li
                tabIndex={0}
                key={med._id}
                onClick={() => setSelected(med)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setSelected(med);
                  }
                }}
                role="button"
                aria-pressed="false"
                style={{
                  cursor: "pointer",
                  borderRadius: 12,
                  boxShadow: "0 6px 22px rgb(0 0 0 / 0.13)",
                  border: "1px solid #dcdcdc",
                  padding: 16,
                  backgroundColor: "#fff",
                  display: "flex",
                  flexDirection: "column",
                  userSelect: "none",
                  outline: "none",
                  transition: "transform 0.3s cubic-bezier(0.4, 0, 0.2, 1), box-shadow 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
                  animation: `fadeSlideUp 0.5s ease forwards`,
                  animationDelay: `${idx * 0.07}s`,
                }}
                onMouseOver={(e) => {
                  e.currentTarget.style.transform = "scale(1.03) translateY(-4px)";
                  e.currentTarget.style.boxShadow = "0 16px 48px rgba(25, 118, 210, 0.32)";
                }}
                onMouseOut={(e) => {
                  e.currentTarget.style.transform = "scale(1) translateY(0)";
                  e.currentTarget.style.boxShadow = "0 6px 22px rgb(0 0 0 / 0.13)";
                }}
                onFocus={(e) => {
                  e.currentTarget.style.boxShadow = "0 0 0 3px rgba(25, 118, 210, 0.6)";
                }}
                onBlur={(e) => {
                  e.currentTarget.style.boxShadow = "0 6px 22px rgb(0 0 0 / 0.13)";
                }}
              >
                <div style={{ fontWeight: "700", fontSize: 20, marginBottom: 6, color: "#1b2733" }}>
                  {med.name}
                </div>
                <div style={{ fontSize: 14, color: "#555", marginBottom: 5 }}>
                  Expiry: <strong>{new Date(med.expiryDate).toLocaleDateString()}</strong>
                </div>
                <div style={{ fontSize: 14, color: "#555", marginBottom: 12 }}>
                  Quantity: <strong>{med.quantity}</strong>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  {med.photoUrl ? (
                    <img
                      src={
                        med.photoUrl.startsWith("http")
                          ? med.photoUrl
                          : `http://localhost:5000${med.photoUrl}`
                      }
                      alt={med.name}
                      style={{
                        width: 90,
                        height: 90,
                        objectFit: "cover",
                        borderRadius: 8,
                        border: "1.5px solid #ccc",
                        boxShadow: "0 2px 6px rgba(0,0,0,0.1)",
                        transition: "transform 0.3s ease",
                        userSelect: "none",
                      }}
                      draggable={false}
                      onMouseOver={e => e.currentTarget.style.transform = "scale(1.1)"}
                      onMouseOut={e => e.currentTarget.style.transform = "scale(1)"}
                    />
                  ) : (
                    <div
                      style={{
                        width: 90,
                        height: 90,
                        borderRadius: 8,
                        border: "1.5px solid #ccc",
                        backgroundColor: "#f0f0f0",
                        color: "#999",
                        fontSize: 13,
                        fontStyle: "italic",
                        display: "flex",
                        justifyContent: "center",
                        alignItems: "center",
                        userSelect: "none",
                      }}
                    >
                      No Image
                    </div>
                  )}
                  {med.status === "claimed" && (
                    <span
                      style={{
                        marginLeft: 12,
                        color: "crimson",
                        fontWeight: "700",
                        fontSize: 16,
                        userSelect: "none",
                      }}
                      aria-label="Claimed status"
                    >
                      Claimed
                    </span>
                  )}
                </div>
              </li>
            ))}
        </ul>
      )}

      {/* Modal for selected medicine details */}
      <Modal
        isOpen={!!selected}
        onRequestClose={() => setSelected(null)}
        contentLabel="Medicine Details"
        style={{
          overlay: {
            backgroundColor: "rgba(0, 0, 0, 0.3)",
            zIndex: 9999,
          },
          content: {
            maxWidth: 440,
            margin: "auto",
            borderRadius: 14,
            padding: 28,
            fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
            boxShadow: "0 8px 30px rgba(25, 118, 210, 0.25)",
          },
        }}
      >
        {selected && (
          <div>
            <h3
              style={{
                marginTop: 0,
                marginBottom: 16,
                fontWeight: "700",
                color: "#1976d2",
                fontSize: 26,
                userSelect: "none",
              }}
            >
              {selected.name}
            </h3>
            <div style={{ fontSize: 16, marginBottom: 14, color: "#222", userSelect: "none" }}>
              <b>Expiry:</b> {new Date(selected.expiryDate).toLocaleDateString()}
              <br />
              <b>Quantity:</b> {selected.quantity}
              <br />
              <b>Status:</b>{" "}
              {selected.status === "claimed" ? (
                <span style={{ color: "crimson", fontWeight: "700" }}>Claimed</span>
              ) : (
                <span style={{ color: "#388e3c", fontWeight: "700" }}>Available</span>
              )}
            </div>
            {selected.photoUrl && (
              <img
                src={
                  selected.photoUrl.startsWith("http")
                    ? selected.photoUrl
                    : `http://localhost:5000${selected.photoUrl}`
                }
                alt={selected.name}
                style={{
                  width: "100%",
                  maxWidth: 360,
                  borderRadius: 10,
                  boxShadow: "0 4px 15px rgba(25, 118, 210, 0.3)",
                  marginBottom: 16,
                  userSelect: "none",
                }}
                draggable={false}
              />
            )}
            {getRole() === "ngo" && selected.status === "available" && (
              <button
                onClick={() => handleClaim(selected)}
                style={{
                  background: "#1976d2",
                  color: "#fff",
                  border: "none",
                  borderRadius: 7,
                  padding: "10px 22px",
                  cursor: "pointer",
                  fontWeight: "600",
                  fontSize: 16,
                  userSelect: "none",
                  boxShadow: "0 4px 14px #1565c051",
                  marginRight: 10,
                  transition: "background-color 0.3s, transform 0.2s ease",
                }}
                onMouseOver={(e) => {
                  e.currentTarget.style.backgroundColor = "#115293";
                  e.currentTarget.style.transform = "scale(1.05)";
                }}
                onMouseOut={(e) => {
                  e.currentTarget.style.backgroundColor = "#1976d2";
                  e.currentTarget.style.transform = "scale(1)";
                }}
                aria-label={`Claim medicine ${selected.name}`}
                type="button"
              >
                Claim
              </button>
            )}
            <button
              onClick={() => setSelected(null)}
              style={{
                background: "#ccc",
                border: "none",
                borderRadius: 7,
                padding: "10px 18px",
                cursor: "pointer",
                fontWeight: "600",
                fontSize: 16,
                userSelect: "none",
                boxShadow: "0 2px 10px #99999966",
                transition: "background-color 0.25s, transform 0.2s ease",
              }}
              onMouseOver={(e) => {
                e.currentTarget.style.backgroundColor = "#bbb";
                e.currentTarget.style.transform = "scale(1.05)";
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.backgroundColor = "#ccc";
                e.currentTarget.style.transform = "scale(1)";
              }}
              aria-label="Close modal"
              type="button"
            >
              Close
            </button>
          </div>
        )}
      </Modal>

      {/* Global keyframe for fadeSlideUp */}
      <style>{`
        @keyframes fadeSlideUp {
          0% {
            opacity: 0;
            transform: translateY(12px);
          }
          100% {
            opacity: 1;
            transform: translateY(0);
          }
        }
      `}</style>
    </div>
  );
};

export default MedicinesList;

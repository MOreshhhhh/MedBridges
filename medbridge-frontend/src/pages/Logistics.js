import React, { useEffect, useState } from "react";
import axios from "axios";
import { useAuth } from "../contexts/AuthContext";

const statusColors = {
  pending: "#f9a825",
  approved: "#388e3c",
  claimed: "#1976d2",
  picked: "#0288d1",
  delivered: "#2e7d32",
  rejected: "#d32f2f",
};

const Logistics = () => {
  const { token } = useAuth();
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [updatingId, setUpdatingId] = useState(null);

  // Fetch tasks on mount and token changes
  useEffect(() => {
    if (!token) return;
    setLoading(true);
    setError("");
    axios
      .get("http://localhost:5000/api/logistics/my", {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => setTasks(res.data))
      .catch(() => setError("Failed to load logistics tasks."))
      .finally(() => setLoading(false));
  }, [token]);

  const markDelivered = async (medicineId) => {
    if (updatingId) return; // Prevent multiple clicks

    setUpdatingId(medicineId);
    try {
      await axios.post(
        `http://localhost:5000/api/logistics/deliver/${medicineId}`,
        {},
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      setTasks((prevTasks) =>
        prevTasks.map((t) =>
          t.medicine._id === medicineId ? { ...t, status: "delivered" } : t
        )
      );
    } catch {
      alert("Failed to mark as delivered. Please try again.");
    } finally {
      setUpdatingId(null);
    }
  };

  return (
    <div
      style={{
        maxWidth: 960,
        margin: "36px auto",
        padding: "0 18px",
        fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
      }}
      aria-label="Logistics tasks dashboard"
    >
      <h2 style={{ color: "#1976d2", marginBottom: 24, userSelect: "none" }}>
        My Logistics Tasks
      </h2>

      {loading ? (
        <p style={{ fontStyle: "italic", color: "#666", textAlign: "center" }}>
          Loading tasks...
        </p>
      ) : error ? (
        <p
          style={{
            color: "#d32f2f",
            fontWeight: "bold",
            textAlign: "center",
            userSelect: "none",
          }}
        >
          {error}
        </p>
      ) : tasks.length === 0 ? (
        <p
          style={{
            color: "#666",
            fontStyle: "italic",
            textAlign: "center",
            userSelect: "none",
          }}
        >
          You have no logistics tasks assigned at the moment.
        </p>
      ) : (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 20,
            justifyContent: "center",
          }}
        >
          {tasks.map((task, index) => (
            <div
              key={task._id}
              tabIndex={0}
              aria-label={`Task for medicine ${task.medicine.name} with status ${task.status}`}
              role="button"
              style={{
                backgroundColor: "#fafafa",
                border: "1px solid #ddd",
                boxShadow: "0 2px 12px rgba(0,0,0,0.05)",
                borderRadius: 10,
                width: 320,
                padding: 18,
                display: "flex",
                flexDirection: "column",
                justifyContent: "space-between",
                userSelect: "none",
                transition: "transform 0.3s ease, box-shadow 0.3s ease",
                cursor: "pointer",
                animation: "fadeSlideUp 0.5s ease forwards",
                animationDelay: `${index * 0.1}s`,
              }}
              onMouseOver={(e) => {
                e.currentTarget.style.transform = "scale(1.04)";
                e.currentTarget.style.boxShadow =
                  "0 8px 32px rgba(25, 118, 210, 0.2)";
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.transform = "scale(1)";
                e.currentTarget.style.boxShadow = "0 2px 12px rgba(0,0,0,0.05)";
              }}
              onFocus={(e) => {
                e.currentTarget.style.boxShadow =
                  "0 0 0 3px rgba(25, 118, 210, 0.5)";
              }}
              onBlur={(e) => {
                e.currentTarget.style.boxShadow = "0 2px 12px rgba(0,0,0,0.05)";
              }}
            >
              <div>
                <h3
                  style={{
                    marginTop: 0,
                    marginBottom: 12,
                    color: "#222",
                    fontWeight: "700",
                    fontSize: 20,
                    overflowWrap: "break-word",
                  }}
                >
                  {task.medicine.name}
                </h3>

                <div style={{ marginBottom: 10, fontSize: 14, color: "#444" }}>
                  <b>Quantity:</b> {task.medicine.quantity}
                </div>

                <div style={{ marginBottom: 10, fontSize: 14, color: "#444" }}>
                  <b>Expiry:</b>{" "}
                  {new Date(task.medicine.expiryDate).toLocaleDateString()}
                </div>

                <div>
                  <b>Status: </b>
                  <span
                    style={{
                      padding: "5px 14px",
                      backgroundColor: statusColors[task.status] || "#555",
                      color: "#fff",
                      borderRadius: 20,
                      fontWeight: "600",
                      textTransform: "capitalize",
                      fontSize: 14,
                      userSelect: "none",
                      boxShadow: `0 2px 6px ${
                        statusColors[task.status]
                          ? statusColors[task.status] + "aa"
                          : "#00000066"
                      }`,
                      minWidth: 80,
                      textAlign: "center",
                      display: "inline-block",
                    }}
                    aria-label={`Status: ${task.status}`}
                  >
                    {task.status}
                  </span>
                </div>
              </div>

              {task.status === "picked" && (
                <button
                  onClick={() => markDelivered(task.medicine._id)}
                  disabled={updatingId === task.medicine._id}
                  style={{
                    marginTop: 18,
                    padding: "10px 0",
                    backgroundColor:
                      updatingId === task.medicine._id ? "#999" : "#1976d2",
                    color: "#fff",
                    border: "none",
                    borderRadius: 8,
                    fontWeight: "600",
                    fontSize: 16,
                    cursor:
                      updatingId === task.medicine._id ? "not-allowed" : "pointer",
                    transition: "background-color 0.25s ease, transform 0.2s ease",
                    userSelect: "none",
                  }}
                  onMouseOver={(e) => {
                    if (!e.currentTarget.disabled) {
                      e.currentTarget.style.backgroundColor = "#155a9f";
                      e.currentTarget.style.transform = "scale(1.05)";
                    }
                  }}
                  onMouseOut={(e) => {
                    if (!e.currentTarget.disabled) {
                      e.currentTarget.style.backgroundColor = "#1976d2";
                      e.currentTarget.style.transform = "scale(1)";
                    }
                  }}
                  aria-label={`Mark medicine ${task.medicine.name} as delivered`}
                  type="button"
                >
                  {updatingId === task.medicine._id
                    ? "Processing..."
                    : "Mark as Delivered"}
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Animation keyframes */}
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

export default Logistics;

import React from "react";

const Dashboard = () => (
  <div
    style={{
      maxWidth: 800,
      margin: "48px auto",
      padding: 32,
      backgroundColor: "#ffffff",
      borderRadius: 12,
      boxShadow: "0 6px 18px rgba(0, 0, 0, 0.1)",
      fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
      textAlign: "center",
      color: "#22314b",
      userSelect: "none",
    }}
    aria-label="Welcome Dashboard"
  >
    <h1
      style={{
        fontSize: "3rem",
        marginBottom: 16,
        color: "#1976d2",
        fontWeight: "700",
        letterSpacing: "1.2px",
      }}
    >
      Welcome to MedBridge
    </h1>

    <p
      style={{
        fontSize: "1.3rem",
        marginBottom: 12,
        lineHeight: 1.5,
        maxWidth: 520,
        marginLeft: "auto",
        marginRight: "auto",
      }}
    >
      Your <strong>Medicine Expiry & Redistribution Network</strong>.
    </p>

    <p
      style={{
        fontSize: "1rem",
        color: "#555",
        maxWidth: 520,
        marginLeft: "auto",
        marginRight: "auto",
        fontStyle: "italic",
      }}
    >
      Use the navigation links above to get started on donating, claiming, and managing medicines — let's reduce waste and help those in need!
    </p>
  </div>
);

export default Dashboard;

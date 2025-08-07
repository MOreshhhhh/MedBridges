import React from "react";

const Loader = () => (
  <div
    role="status"
    aria-live="polite"
    style={{
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      padding: "2.5em",
      color: "#1976d2",
      fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
      gap: "1em",
      userSelect: "none",
      minHeight: 120,
    }}
  >
    <div
      aria-hidden="true"
      style={{
        width: 56,
        height: 56,
        border: "6px solid #cfd0d1",
        borderTopColor: "#1976d2",
        borderRadius: "50%",
        animation: "spin 1s linear infinite",
        boxShadow: "0 0 10px rgba(25, 118, 210, 0.4)",
      }}
    />
    <span
      style={{
        fontSize: 20,
        fontWeight: 700,
        letterSpacing: 1,
        color: "#1565c0",
      }}
    >
      Loading...
    </span>

    {/* CSS animation in JS */}
    <style>
      {`
        @keyframes spin {
          0% { transform: rotate(0deg);}
          100% { transform: rotate(360deg);}
        }
      `}
    </style>
  </div>
);

export default Loader;

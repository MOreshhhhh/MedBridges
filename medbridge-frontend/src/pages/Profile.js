import React, { useEffect, useState } from "react";
import axios from "axios";
import { useAuth } from "../contexts/AuthContext";

const Profile = () => {
  const { token, role } = useAuth();
  const [form, setForm] = useState({ name: "", email: "", contact: "", password: "" });
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);

  // Fetch user info on mount
  useEffect(() => {
    if (!token) return;
    setLoading(true);
    axios
      .get("http://localhost:5000/api/auth/me", {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => setForm((f) => ({ ...f, ...res.data, password: "" })))
      .catch(() => setMessage("❌ Failed to load profile."))
      .finally(() => setLoading(false));
  }, [token]);

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage("");
    try {
      // Only send fields that changed
      const updateObj = { name: form.name, email: form.email, contact: form.contact };
      if (form.password) updateObj.password = form.password;

      await axios.put("http://localhost:5000/api/auth/me", updateObj, {
        headers: { Authorization: `Bearer ${token}` },
      });

      setMessage("✅ Profile updated successfully.");
      setForm((f) => ({ ...f, password: "" }));
    } catch (err) {
      setMessage("❌ " + (err.response?.data?.error || "Update failed."));
    } finally {
      setLoading(false);
    }
  };

  if (!token)
    return (
      <div
        style={{
          maxWidth: 400,
          margin: "60px auto",
          padding: 24,
          fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
          fontSize: 18,
          textAlign: "center",
          color: "#d32f2f",
          userSelect: "none",
        }}
      >
        Please{" "}
        <a
          href="/login"
          style={{
            color: "#1976d2",
            fontWeight: "600",
            textDecoration: "none",
            padding: "6px 12px",
            borderRadius: 6,
            border: "1.5px solid #1976d2",
            transition: "background-color 0.25s ease, color 0.25s ease",
            cursor: "pointer",
          }}
          onMouseOver={(e) => {
            e.currentTarget.style.backgroundColor = "#1976d2";
            e.currentTarget.style.color = "#fff";
          }}
          onMouseOut={(e) => {
            e.currentTarget.style.backgroundColor = "transparent";
            e.currentTarget.style.color = "#1976d2";
          }}
        >
          login
        </a>{" "}
        to view your profile.
      </div>
    );

  return (
    <form
      onSubmit={handleSubmit}
      style={{
        maxWidth: 420,
        margin: "40px auto 60px",
        padding: 30,
        borderRadius: 14,
        background: "#fff",
        boxShadow: "0 8px 25px rgba(25, 118, 210, 0.15)",
        fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
        display: "flex",
        flexDirection: "column",
        userSelect: "none",
        opacity: loading ? 0.7 : 1,
        pointerEvents: loading ? "none" : "auto",
      }}
      noValidate
      autoComplete="off"
    >
      <h2
        style={{
          textAlign: "center",
          color: "#1976d2",
          fontWeight: 700,
          marginBottom: 30,
          userSelect: "none",
          fontSize: 28,
        }}
      >
        My Profile
      </h2>

      <label htmlFor="name" style={labelStyle}>
        Name <span style={{ color: "#d32f2f" }}>*</span>
      </label>
      <input
        id="name"
        name="name"
        value={form.name}
        onChange={handleChange}
        placeholder="Your full name"
        required
        style={inputStyle}
        autoComplete="name"
        disabled={loading}
        onFocus={(e) => {
          e.currentTarget.style.borderColor = "#1976d2";
          e.currentTarget.style.boxShadow = "0 0 8px rgba(25, 118, 210, 0.4)";
        }}
        onBlur={(e) => {
          e.currentTarget.style.borderColor = "#b7c8db";
          e.currentTarget.style.boxShadow = "none";
        }}
      />

      <label htmlFor="email" style={labelStyle}>
        Email <span style={{ color: "#d32f2f" }}>*</span>
      </label>
      <input
        id="email"
        name="email"
        type="email"
        value={form.email}
        onChange={handleChange}
        placeholder="you@example.com"
        required
        style={inputStyle}
        autoComplete="email"
        disabled={loading}
        onFocus={(e) => {
          e.currentTarget.style.borderColor = "#1976d2";
          e.currentTarget.style.boxShadow = "0 0 8px rgba(25, 118, 210, 0.4)";
        }}
        onBlur={(e) => {
          e.currentTarget.style.borderColor = "#b7c8db";
          e.currentTarget.style.boxShadow = "none";
        }}
      />

      <label htmlFor="contact" style={labelStyle}>
        Contact Number
      </label>
      <input
        id="contact"
        name="contact"
        value={form.contact || ""}
        onChange={handleChange}
        placeholder="Optional phone number"
        style={inputStyle}
        autoComplete="tel"
        disabled={loading}
        onFocus={(e) => {
          e.currentTarget.style.borderColor = "#1976d2";
          e.currentTarget.style.boxShadow = "0 0 8px rgba(25, 118, 210, 0.4)";
        }}
        onBlur={(e) => {
          e.currentTarget.style.borderColor = "#b7c8db";
          e.currentTarget.style.boxShadow = "none";
        }}
      />

      <label htmlFor="password" style={labelStyle}>
        New Password (optional)
      </label>
      <input
        id="password"
        name="password"
        type="password"
        value={form.password}
        onChange={handleChange}
        placeholder="Enter new password"
        style={inputStyle}
        autoComplete="new-password"
        disabled={loading}
        onFocus={(e) => {
          e.currentTarget.style.borderColor = "#1976d2";
          e.currentTarget.style.boxShadow = "0 0 8px rgba(25, 118, 210, 0.4)";
        }}
        onBlur={(e) => {
          e.currentTarget.style.borderColor = "#b7c8db";
          e.currentTarget.style.boxShadow = "none";
        }}
      />

      <button
        type="submit"
        disabled={loading}
        style={{
          marginTop: 24,
          padding: "14px 0",
          backgroundColor: "#1976d2",
          color: "#fff",
          border: "none",
          borderRadius: 8,
          fontSize: 18,
          fontWeight: "600",
          cursor: loading ? "not-allowed" : "pointer",
          boxShadow: loading ? "none" : "0 4px 12px rgba(25, 118, 210, 0.45)",
          userSelect: "none",
          transition: "background-color 0.25s ease, transform 0.2s ease",
        }}
        onMouseOver={(e) => {
          if (!loading) {
            e.currentTarget.style.backgroundColor = "#155a9f";
            e.currentTarget.style.transform = "scale(1.05)";
          }
        }}
        onMouseOut={(e) => {
          if (!loading) {
            e.currentTarget.style.backgroundColor = "#1976d2";
            e.currentTarget.style.transform = "scale(1)";
          }
        }}
      >
        {loading ? "Updating..." : "Update Profile"}
      </button>

      {message && (
        <div
          role={message.startsWith("✅") ? "status" : "alert"}
          style={{
            marginTop: 20,
            padding: 14,
            borderRadius: 8,
            color: message.startsWith("✅") ? "#2e7d32" : "#b71c1c",
            backgroundColor: message.startsWith("✅") ? "#e8f5e9" : "#fdecea",
            fontWeight: "bold",
            textAlign: "center",
            boxShadow: message.startsWith("✅")
              ? "0 1px 10px #6bc47e48"
              : "0 1px 10px #e7919140",
            userSelect: "none",
            wordBreak: "break-word",
            animation: "fadeIn 0.5s ease forwards",
          }}
        >
          {message}
        </div>
      )}

      <div
        style={{
          marginTop: 26,
          fontSize: 15,
          color: "#555",
          fontWeight: 600,
          textAlign: "center",
          userSelect: "none",
        }}
      >
        Role: <span style={{ color: "#1976d2", textTransform: "capitalize" }}>{role}</span>
      </div>

      {/* Add fadeIn keyframe style globally or via CSS */}
      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(-6px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </form>
  );
};

const labelStyle = {
  display: "block",
  marginBottom: 6,
  fontWeight: 600,
  color: "#22314b",
  userSelect: "none",
};

const inputStyle = {
  padding: "10px 14px",
  fontSize: 16,
  borderRadius: 6,
  border: "1.5px solid #b7c8db",
  marginBottom: 20,
  boxSizing: "border-box",
  transition: "border-color 0.3s ease, box-shadow 0.3s ease",
  outline: "none",
  width: "100%",
  userSelect: "text",
};

export default Profile;

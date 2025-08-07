import React, { useState } from "react";
import axios from "axios";

const Register = () => {
  const [form, setForm] = useState({
    name: "",
    email: "",
    password: "",
    role: "donor",
    contact: ""
  });
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);

  const handleChange = (e) =>
    setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage("");
    try {
      await axios.post("http://localhost:5000/api/auth/register", form);
      setMessage("✅ Registration successful! Redirecting...");
      setTimeout(() => {
        window.location.href = "/login";
      }, 1500);
    } catch (err) {
      setMessage(
        "❌ " + (err.response?.data?.error || "Registration failed.")
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <form
      onSubmit={handleSubmit}
      style={{
        maxWidth: 420,
        margin: "auto",
        marginTop: 36,
        padding: "34px 26px",
        borderRadius: 13,
        background: "#fff",
        boxShadow: "0 6px 40px 2px #1976d234",
        fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
      }}
      noValidate
      autoComplete="off"
    >
      <h2
        style={{
          textAlign: "center",
          color: "#1976d2",
          fontWeight: 700,
          margin: 0,
          marginBottom: 28,
          letterSpacing: "0.5px"
        }}
      >
        Register
      </h2>

      <label style={labelStyle} htmlFor="name">Full Name <span style={{ color: "#d32f2f" }}>*</span></label>
      <input
        id="name"
        name="name"
        placeholder="Your Name"
        value={form.name}
        onChange={handleChange}
        required
        style={inputStyle}
        disabled={loading}
      />

      <label style={labelStyle} htmlFor="email">Email <span style={{ color: "#d32f2f" }}>*</span></label>
      <input
        id="email"
        name="email"
        type="email"
        placeholder="you@email.com"
        value={form.email}
        onChange={handleChange}
        required
        style={inputStyle}
        disabled={loading}
      />

      <label style={labelStyle} htmlFor="password">Password <span style={{ color: "#d32f2f" }}>*</span></label>
      <input
        id="password"
        name="password"
        type="password"
        placeholder="Password"
        value={form.password}
        onChange={handleChange}
        required
        style={inputStyle}
        disabled={loading}
      />

      <label style={labelStyle} htmlFor="contact">Contact Number</label>
      <input
        id="contact"
        name="contact"
        type="tel"
        placeholder="Contact Number"
        value={form.contact}
        onChange={handleChange}
        style={inputStyle}
        disabled={loading}
      />

      <label style={labelStyle} htmlFor="role">Role <span style={{ color: "#d32f2f" }}>*</span></label>
      <select
        id="role"
        name="role"
        value={form.role}
        onChange={handleChange}
        style={{
          ...inputStyle,
          padding: "10px",
          fontSize: 16,
          appearance: "none",
          cursor: "pointer",
          background: "#f8fafc",
        }}
        disabled={loading}
      >
        <option value="donor">Donor</option>
        <option value="ngo">NGO / Clinic</option>
      </select>

      <button
        type="submit"
        disabled={loading}
        style={{
          width: "100%",
          marginTop: 22,
          padding: "13px",
          backgroundColor: "#1976d2",
          color: "#fff",
          border: "none",
          borderRadius: 8,
          fontSize: 18,
          fontWeight: 600,
          boxShadow: "0 2px 10px #1976d228",
          transition: "background 0.2s",
          cursor: loading ? "not-allowed" : "pointer"
        }}
        onMouseOver={e => !loading && (e.currentTarget.style.background = "#12509b")}
        onMouseOut={e => !loading && (e.currentTarget.style.background = "#1976d2")}
      >
        {loading ? "Registering..." : "Register"}
      </button>

      {message && (
        <div
          style={{
            marginTop: 20,
            borderRadius: 8,
            textAlign: "center",
            fontWeight: "bold",
            backgroundColor: message.startsWith("✅") ? "#e8f5e9" : "#fdecea",
            color: message.startsWith("✅") ? "#27703a" : "#b71c1c",
            padding: "13px 0",
            fontSize: 15,
            boxShadow: message.startsWith("✅")
              ? "0 1px 6px #6bc47e48"
              : "0 1px 6px #e7919140",
            userSelect: "none"
          }}
          role={message.startsWith("✅") ? "status" : "alert"}
        >
          {message}
        </div>
      )}
    </form>
  );
};

const labelStyle = {
  display: "block",
  marginBottom: 6,
  fontWeight: 500,
  color: "#22314b"
};

const inputStyle = {
  boxSizing: "border-box",
  width: "100%",
  padding: "10px 14px",
  borderRadius: 6,
  border: "1.5px solid #b7c8db",
  background: "#f8fafc",
  marginBottom: 18,
  fontSize: 16,
  transition: "border-color 0.2s"
};

export default Register;

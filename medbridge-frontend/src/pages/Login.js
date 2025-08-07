import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { login } = useAuth();

  const toggleShowPassword = () => setShowPassword((prev) => !prev);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage("");
    try {
      const res = await axios.post("http://localhost:5000/api/auth/login", {
        email,
        password,
      });
      const token = res.data.token;
      login(token); // IMPORTANT: use context login function!

      setMessage("✅ Login successful!");

      // Decode role to redirect accordingly
      const base64Url = token.split(".")[1];
      const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split("")
          .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
          .join("")
      );
      const user = JSON.parse(jsonPayload);
      const role = user.role || "";

      // Delay redirect so login state updates properly
      setTimeout(() => {
        if (role === "admin") {
          navigate("/admin/pending-medicines");
        } else if (role === "donor") {
          navigate("/donor/dashboard");
        } else if (role === "volunteer") {
          navigate("/logistics");
        } else if (role === "ngo") {
          navigate("/ngo/dashboard");
        } else {
          navigate("/");
        }
      }, 1000);
    } catch (err) {
      setMessage("❌ " + (err.response?.data?.message || "Login failed."));
    } finally {
      setLoading(false);
    }
  };

  const handleFocus = (e) => {
    e.currentTarget.style.borderColor = "#1976d2";
    e.currentTarget.style.boxShadow = "0 0 8px rgba(25, 118, 210, 0.5)";
    e.currentTarget.style.outline = "none";
  };

  const handleBlur = (e) => {
    e.currentTarget.style.borderColor = "#b7c8db";
    e.currentTarget.style.boxShadow = "none";
  };

  const labelStyle = {
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

  return (
    <form
      onSubmit={handleSubmit}
      style={{
        maxWidth: 400,
        margin: "60px auto",
        padding: 32,
        backgroundColor: "#fff",
        borderRadius: 12,
        boxShadow: "0 6px 20px rgba(25, 118, 210, 0.15)",
        fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
        display: "flex",
        flexDirection: "column",
        userSelect: "none",
      }}
      noValidate
      autoComplete="off"
    >
      <h2
        style={{
          color: "#1976d2",
          textAlign: "center",
          marginBottom: 28,
          fontWeight: "700",
          userSelect: "none",
          fontSize: "2rem",
        }}
      >
        Login
      </h2>

      <label htmlFor="email" style={labelStyle}>
        Email <span style={{ color: "#d32f2f" }}>*</span>
      </label>
      <input
        id="email"
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        required
        disabled={loading}
        placeholder="you@example.com"
        style={inputStyle}
        autoFocus
        onFocus={handleFocus}
        onBlur={handleBlur}
      />

      <label htmlFor="password" style={labelStyle}>
        Password <span style={{ color: "#d32f2f" }}>*</span>
      </label>
      <div style={{ position: "relative", width: "100%" }}>
        <input
          id="password"
          type={showPassword ? "text" : "password"}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          disabled={loading}
          placeholder="Your password"
          style={{ ...inputStyle, paddingRight: 44 }}
          onFocus={handleFocus}
          onBlur={handleBlur}
          autoComplete="current-password"
        />
        <button
          type="button"
          onClick={toggleShowPassword}
          aria-label={showPassword ? "Hide password" : "Show password"}
          style={{
            position: "absolute",
            right: 10,
            top: "50%",
            transform: "translateY(-50%)",
            background: "transparent",
            border: "none",
            cursor: "pointer",
            color: "#1976d2",
            fontSize: 14,
            fontWeight: "600",
            userSelect: "none",
            padding: "4px 8px",
            borderRadius: 4,
            outline: "none",
            transition: "background-color 0.2s",
          }}
          onMouseOver={(e) => (e.currentTarget.style.backgroundColor = "#e3f2fd")}
          onMouseOut={(e) => (e.currentTarget.style.backgroundColor = "transparent")}
          disabled={loading}
        >
          {showPassword ? "Hide" : "Show"}
        </button>
      </div>

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
        {loading ? "Logging in..." : "Login"}
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
            animation: "slideFadeIn 0.4s ease forwards",
          }}
        >
          {message}
          <style>{`
            @keyframes slideFadeIn {
              0% {
                opacity: 0;
                transform: translateY(-12px);
              }
              100% {
                opacity: 1;
                transform: translateY(0);
              }
            }
          `}</style>
        </div>
      )}
    </form>
  );
};

export default Login;

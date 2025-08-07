import React, { useState } from "react";
import axios from "axios";

const MedicineUpload = () => {
  const [medicine, setMedicine] = useState({
    name: "",
    expiryDate: "",
    quantity: 1,
  });
  const [photo, setPhoto] = useState(null);
  const [preview, setPreview] = useState(null);
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);

  const handleChange = (e) =>
    setMedicine({ ...medicine, [e.target.name]: e.target.value });

  const handlePhoto = (e) => {
    const file = e.target.files[0];
    if (file) {
      setPhoto(file);
      setPreview(URL.createObjectURL(file));
    } else {
      setPhoto(null);
      setPreview(null);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage("");
    const token = localStorage.getItem("token");
    const formData = new FormData();
    Object.entries(medicine).forEach(([k, v]) => formData.append(k, v));
    if (photo) formData.append("photo", photo);

    try {
      await axios.post("http://localhost:5000/api/medicines/", formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "multipart/form-data",
        },
      });
      setMessage("✅ Medicine uploaded successfully!");
      setMedicine({ name: "", expiryDate: "", quantity: 1 });
      setPhoto(null);
      setPreview(null);
    } catch (err) {
      setMessage(
        "❌ Upload failed: " + (err.response?.data?.error || "Unknown error")
      );
    } finally {
      setLoading(false);
    }
  };

  // Reusable styles for inputs with focus effects
  const inputFocusHandler = (e) => {
    e.currentTarget.style.borderColor = "#1976d2";
    e.currentTarget.style.boxShadow = "0 0 8px rgba(25, 118, 210, 0.4)";
  };
  const inputBlurHandler = (e) => {
    e.currentTarget.style.borderColor = "#ccc";
    e.currentTarget.style.boxShadow = "none";
  };

  return (
    <form
      onSubmit={handleSubmit}
      style={{
        maxWidth: 400,
        margin: "auto",
        padding: 32,
        borderRadius: 12,
        boxShadow: "0 8px 24px rgba(25, 118, 210, 0.15)",
        background: "#fff",
        fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
        userSelect: "none",
      }}
      noValidate
    >
      <h2
        style={{
          marginBottom: 28,
          textAlign: "center",
          color: "#1976d2",
          fontWeight: "700",
          fontSize: 28,
          userSelect: "none",
        }}
      >
        Upload Medicine
      </h2>

      <label htmlFor="name" style={{ display: "block", marginBottom: 6 }}>
        Medicine Name <span style={{ color: "#d32f2f" }}>*</span>
      </label>
      <input
        id="name"
        name="name"
        placeholder="Paracetamol"
        value={medicine.name}
        onChange={handleChange}
        required
        autoComplete="off"
        spellCheck={false}
        disabled={loading}
        style={{
          boxSizing: "border-box",
          width: "100%",
          padding: "12px 16px",
          borderRadius: 8,
          border: "1.5px solid #ccc",
          marginBottom: 20,
          fontSize: 16,
          transition: "border-color 0.3s ease, box-shadow 0.3s ease",
          outline: "none",
          userSelect: "text",
          opacity: loading ? 0.7 : 1,
          cursor: loading ? "not-allowed" : "text",
        }}
        onFocus={inputFocusHandler}
        onBlur={inputBlurHandler}
      />

      <label htmlFor="expiryDate" style={{ display: "block", marginBottom: 6 }}>
        Expiry Date <span style={{ color: "#d32f2f" }}>*</span>
      </label>
      <input
        id="expiryDate"
        name="expiryDate"
        type="date"
        value={medicine.expiryDate}
        onChange={handleChange}
        required
        disabled={loading}
        min={new Date().toISOString().split("T")[0]} // disallow past dates
        style={{
          boxSizing: "border-box",
          width: "100%",
          padding: "12px 16px",
          borderRadius: 8,
          border: "1.5px solid #ccc",
          marginBottom: 20,
          fontSize: 16,
          transition: "border-color 0.3s ease, box-shadow 0.3s ease",
          outline: "none",
          userSelect: "text",
          opacity: loading ? 0.7 : 1,
          cursor: loading ? "not-allowed" : "text",
        }}
        onFocus={inputFocusHandler}
        onBlur={inputBlurHandler}
      />

      <label htmlFor="quantity" style={{ display: "block", marginBottom: 6 }}>
        Quantity <span style={{ color: "#d32f2f" }}>*</span>
      </label>
      <input
        id="quantity"
        name="quantity"
        type="number"
        min="1"
        value={medicine.quantity}
        onChange={handleChange}
        required
        disabled={loading}
        style={{
          boxSizing: "border-box",
          width: "100%",
          padding: "12px 16px",
          borderRadius: 8,
          border: "1.5px solid #ccc",
          marginBottom: 20,
          fontSize: 16,
          transition: "border-color 0.3s ease, box-shadow 0.3s ease",
          outline: "none",
          userSelect: "text",
          opacity: loading ? 0.7 : 1,
          cursor: loading ? "not-allowed" : "text",
        }}
        onFocus={inputFocusHandler}
        onBlur={inputBlurHandler}
      />

      <label htmlFor="photo" style={{ display: "block", marginBottom: 8 }}>
        Medicine Photo (optional)
      </label>
      <input
        id="photo"
        type="file"
        accept="image/*"
        onChange={handlePhoto}
        disabled={loading}
        style={{
          marginBottom: 20,
          cursor: loading ? "not-allowed" : "pointer",
        }}
      />

      {preview && (
        <div
          style={{
            marginBottom: 24,
            textAlign: "center",
            transition: "opacity 0.4s ease",
          }}
        >
          <img
            src={preview}
            alt="Preview"
            width={160}
            style={{
              borderRadius: 14,
              boxShadow: "0 4px 18px rgba(0, 0, 0, 0.12)",
              maxHeight: 160,
              objectFit: "contain",
              userSelect: "none",
            }}
            draggable={false}
          />
        </div>
      )}

      <button
        type="submit"
        disabled={loading}
        style={{
          width: "100%",
          padding: "16px 0",
          backgroundColor: "#1976d2",
          color: "#fff",
          fontWeight: "700",
          fontSize: 18,
          borderRadius: 12,
          border: "none",
          cursor: loading ? "not-allowed" : "pointer",
          boxShadow: loading
            ? "none"
            : "0 6px 18px rgba(25, 118, 210, 0.6)",
          transition: "background-color 0.3s ease, transform 0.2s ease",
          userSelect: "none",
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
        {loading ? "Uploading..." : "Upload"}
      </button>

      {message && (
        <div
          style={{
            marginTop: 20,
            padding: 14,
            borderRadius: 10,
            backgroundColor: message.startsWith("✅") ? "#e6f4ea" : "#fdecea",
            color: message.startsWith("✅") ? "#2a7a2a" : "#a4262c",
            fontWeight: "600",
            textAlign: "center",
            userSelect: "none",
            boxShadow: message.startsWith("✅")
              ? "0 2px 8px #6bc47e80"
              : "0 2px 8px #e7919175",
            animation: "slideFadeIn 0.35s ease forwards",
           /* userSelect: "none", */
          }}
          role={message.startsWith("✅") ? "status" : "alert"}
        >
          {message}
          <style>{`
            @keyframes slideFadeIn {
              0% { opacity: 0; transform: translateY(-10px);}
              100% { opacity: 1; transform: translateY(0);}
            }
          `}</style>
        </div>
      )}
    </form>
  );
};

export default MedicineUpload;

import React, { useEffect, useState } from "react";
import axios from "axios";
import Toast from "../../components/Toast";
import { useAuth } from "../../contexts/AuthContext";

export default function DonorDashboard() {
  const { token } = useAuth();

  const [name, setName] = useState("");
  const [expiryDate, setExpiryDate] = useState("");
  const [quantity, setQuantity] = useState("");
  const [photo, setPhoto] = useState(null);
  const [preview, setPreview] = useState(null);
  const [medicines, setMedicines] = useState([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState("");

  // Fetch medicines when token changes
  useEffect(() => {
    const fetchMedicines = async () => {
      try {
        setLoading(true);
        const res = await axios.get("http://localhost:5000/api/medicines/my", {
          headers: { Authorization: `Bearer ${token}` },
        });
        setMedicines(res.data);
      } catch {
        setToast("Failed to load your medicines.");
      } finally {
        setLoading(false);
      }
    };

    if (token) {
      fetchMedicines();
    } else {
      setMedicines([]);
      setLoading(false);
    }
  }, [token]);

  // Clear toast messages automatically after 3 seconds
  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(""), 3000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  // Preview selected image
  useEffect(() => {
    if (photo) {
      const objectUrl = URL.createObjectURL(photo);
      setPreview(objectUrl);
      return () => URL.revokeObjectURL(objectUrl);
    } else {
      setPreview(null);
    }
  }, [photo]);

  async function handleUpload(e) {
    e.preventDefault();

    if (!name || !expiryDate || !quantity) {
      setToast("Please fill in all required fields.");
      return;
    }
    if (quantity <= 0) {
      setToast("Quantity must be positive.");
      return;
    }

    const formData = new FormData();
    formData.append("name", name);
    formData.append("expiryDate", expiryDate);
    formData.append("quantity", quantity);
    if (photo) formData.append("photo", photo);

    try {
      await axios.post("http://localhost:5000/api/medicines", formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "multipart/form-data",
        },
      });

      setToast("Medicine uploaded and pending admin approval.");
      // Clear form
      setName("");
      setExpiryDate("");
      setQuantity("");
      setPhoto(null);
      // Refresh medicines after upload
      const res = await axios.get("http://localhost:5000/api/medicines/my", {
        headers: { Authorization: `Bearer ${token}` },
      });
      setMedicines(res.data);
    } catch (err) {
      setToast(
        "Upload failed: " + (err.response?.data?.error || err.message || "Unknown error")
      );
    }
  }

  return (
    <div
      style={{
        maxWidth: 900,
        margin: "auto",
        padding: 24,
        fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
      }}
    >
      <Toast message={toast} clear={() => setToast("")} />

      <h2>Donor Dashboard</h2>

      <form
        onSubmit={handleUpload}
        style={{
          marginBottom: 32,
          display: "flex",
          flexWrap: "wrap",
          gap: 12,
          alignItems: "center",
        }}
        noValidate
      >
        <input
          type="text"
          placeholder="Medicine Name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          style={{ flex: "1 1 200px", padding: 8, borderRadius: 4, border: "1px solid #ccc" }}
          aria-label="Medicine Name"
        />
        <input
          type="date"
          placeholder="Expiry Date"
          value={expiryDate}
          onChange={(e) => setExpiryDate(e.target.value)}
          required
          style={{ flex: "0 0 160px", padding: 8, borderRadius: 4, border: "1px solid #ccc" }}
          aria-label="Expiry Date"
        />
        <input
          type="number"
          min={1}
          placeholder="Quantity"
          value={quantity}
          onChange={(e) => setQuantity(e.target.value)}
          required
          style={{
            flex: "0 0 120px",
            padding: 8,
            borderRadius: 4,
            border: "1px solid #ccc",
            textAlign: "right",
          }}
          aria-label="Quantity"
        />
        <input
          type="file"
          accept="image/*"
          onChange={(e) => setPhoto(e.target.files[0])}
          aria-label="Photo Upload"
          style={{ flex: "0 0 150px" }}
        />
        <button
          type="submit"
          style={{
            padding: "10px 28px",
            backgroundColor: "#2196f3",
            color: "#fff",
            border: "none",
            borderRadius: 6,
            cursor: "pointer",
            flex: "0 0 130px",
            fontWeight: "bold",
            fontSize: 16,
            boxShadow: "0 3px 7px rgb(0 0 0 / 0.3)",
            transition: "background-color 0.25s ease",
          }}
          onMouseOver={(e) => (e.currentTarget.style.backgroundColor = "#1769aa")}
          onMouseOut={(e) => (e.currentTarget.style.backgroundColor = "#2196f3")}
        >
          Upload
        </button>
      </form>

      {preview && (
        <div style={{ marginBottom: 20 }}>
          <b>Image Preview:</b>
          <div>
            <img
              src={preview}
              alt="Medicine preview"
              style={{
                maxWidth: "200px",
                borderRadius: 8,
                marginTop: 6,
                boxShadow: "0 2px 10px #aaa",
              }}
            />
          </div>
        </div>
      )}

      <h3>Your Uploaded Medicines</h3>

      {loading ? (
        <div style={{ padding: 20, textAlign: "center", fontStyle: "italic", color: "#666" }}>
          Loading your medicines...
        </div>
      ) : medicines.length === 0 ? (
        <div style={{ padding: 20, fontStyle: "italic", color: "#666" }}>No medicines uploaded yet.</div>
      ) : (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 22,
            justifyContent: "flex-start",
          }}
        >
          {medicines.map((med) => (
            <div
              key={med._id}
              style={{
                border: "1px solid #ccc",
                borderRadius: 12,
                padding: 16,
                width: 260,
                backgroundColor: "#fafafa",
                boxShadow: "0 2px 8px rgba(0,0,0,0.08)",
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                transition: "box-shadow 0.2s ease",
              }}
              tabIndex={0}
              aria-label={`Medicine ${med.name}, quantity ${med.quantity}, status ${med.status}`}
            >
              <div
                style={{
                  fontWeight: "bold",
                  fontSize: 20,
                  marginBottom: 6,
                  textAlign: "center",
                  color: "#1a1a1a",
                }}
              >
                {med.name}
              </div>
              <div style={{ marginBottom: 6, color: "#444", fontSize: 14 }}>
                Expiry: <b>{new Date(med.expiryDate).toLocaleDateString()}</b>
              </div>
              <div style={{ marginBottom: 8, color: "#444", fontSize: 14 }}>
                Quantity: <b>{med.quantity}</b>
              </div>
              {med.photoUrl ? (
                <img
                  src={
                    med.photoUrl.startsWith("http")
                      ? med.photoUrl
                      : `http://localhost:5000${med.photoUrl}`
                  }
                  alt={med.name}
                  style={{
                    width: 180,
                    height: 110,
                    objectFit: "cover",
                    borderRadius: 10,
                    boxShadow: "1px 1px 8px rgba(0,0,0,0.15)",
                  }}
                />
              ) : (
                <div
                  style={{
                    width: 180,
                    height: 110,
                    backgroundColor: "#eee",
                    borderRadius: 10,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    color: "#999",
                    fontStyle: "italic",
                  }}
                >
                  No photo
                </div>
              )}
              <div
                style={{
                  marginTop: 12,
                  padding: "5px 12px",
                  borderRadius: 8,
                  color: "#fff",
                  fontWeight: "bold",
                  textTransform: "capitalize",
                  backgroundColor:
                    med.status === "pending"
                      ? "#f9a825"
                      : med.status === "approved"
                      ? "#388e3c"
                      : med.status === "rejected"
                      ? "#d32f2f"
                      : "#555",
                  userSelect: "none",
                }}
              >
                {med.status}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// src/App.js

import React, { useState, useMemo } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";

import { ThemeProvider, createTheme } from "@mui/material/styles";

import Navbar from "./components/Navbar";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import MedicineUpload from "./pages/MedicineUpload";
import MedicinesList from "./pages/MedicinesList";
import Profile from "./pages/Profile";
import Logistics from "./pages/Logistics";

// Admin pages
import PendingMedicines from "./pages/admin/PendingMedicines";
import UserManagement from "./pages/admin/UserManagement";
import AdminMedicines from "./pages/admin/AdminMedicines";
import RegisteredUsers from "./pages/admin/RegisteredUsers";
import ClaimedMedicines from "./pages/admin/ClaimedMedicines";

// Other dashboards
import DonorDashboard from "./pages/donor/DonorDashboard";
import NgoDashboard from "./pages/ngo/NGODashboard";

import ProtectedRoute from "./components/ProtectedRoute";
import { AuthProvider } from "./contexts/AuthContext";

function App() {
  const [dark, setDark] = useState(false);

  const theme = useMemo(
    () =>
      createTheme({
        palette: {
          mode: dark ? "dark" : "light",
          // You can add further customizations here
        },
      }),
    [dark]
  );

  return (
    <ThemeProvider theme={theme}>
      <AuthProvider>
        <Router>
          <Navbar dark={dark} setDark={setDark} />
          <Routes>
            {/* Public routes */}
            <Route path="/" element={<Dashboard />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />

            {/* User profile */}
            <Route path="/profile" element={<Profile />} />

            {/* Admin routes (protected) */}
            <Route
              path="/admin/pending-medicines"
              element={
                <ProtectedRoute allowedRoles={["admin"]}>
                  <PendingMedicines />
                </ProtectedRoute>
              }
            />
            <Route
              path="/admin/medicines"
              element={
                <ProtectedRoute allowedRoles={["admin"]}>
                  <AdminMedicines />
                </ProtectedRoute>
              }
            />
            <Route
              path="/admin/users"
              element={
                <ProtectedRoute allowedRoles={["admin"]}>
                  <UserManagement />
                </ProtectedRoute>
              }
            />
            <Route
              path="/admin/registered-users"
              element={
                <ProtectedRoute allowedRoles={["admin"]}>
                  <RegisteredUsers />
                </ProtectedRoute>
              }
            />
            <Route
              path="/admin/claimed-medicines"
              element={
                <ProtectedRoute allowedRoles={["admin"]}>
                  <ClaimedMedicines />
                </ProtectedRoute>
              }
            />

            {/* Donor dashboard (protected) */}
            <Route
              path="/donor/dashboard"
              element={
                <ProtectedRoute allowedRoles={["donor"]}>
                  <DonorDashboard />
                </ProtectedRoute>
              }
            />

            {/* NGO dashboard (protected) */}
            <Route
              path="/ngo/dashboard"
              element={
                <ProtectedRoute allowedRoles={["ngo"]}>
                  <NgoDashboard />
                </ProtectedRoute>
              }
            />

            {/* Volunteer logistics (protected) */}
            <Route
              path="/logistics"
              element={
                <ProtectedRoute allowedRoles={["volunteer"]}>
                  <Logistics />
                </ProtectedRoute>
              }
            />

            {/* Medicine upload (donor, ngo, admin) */}
            <Route
              path="/upload"
              element={
                <ProtectedRoute allowedRoles={["donor", "ngo", "admin"]}>
                  <MedicineUpload />
                </ProtectedRoute>
              }
            />

            {/* Browse medicines (ngo, donor) */}
            <Route
              path="/medicines"
              element={
                <ProtectedRoute allowedRoles={["ngo", "donor"]}>
                  <MedicinesList />
                </ProtectedRoute>
              }
            />

            {/* 404 fallback */}
            <Route
              path="*"
              element={
                <div
                  style={{
                    padding: 32,
                    textAlign: "center",
                  }}
                >
                  <h2>404 - Page Not Found</h2>
                  <p>The page you are looking for does not exist.</p>
                </div>
              }
            />
          </Routes>
        </Router>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;

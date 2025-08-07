import { createContext, useContext, useState, useEffect } from "react";

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem("token"));
  const [user, setUser] = useState(null);
  const [role, setRole] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      try {
        const base64Url = token.split(".")[1];
        const jsonPayload = atob(base64Url.replace(/-/g, "+").replace(/_/g, "/"));
        const decodedUser = JSON.parse(jsonPayload);
        setUser(decodedUser);
        setRole(decodedUser.role);
      } catch (err) {
        console.error("Error decoding token", err);
        setUser(null);
        setRole(null);
      }
    } else {
      setUser(null);
      setRole(null);
    }
    setLoading(false);
  }, [token]);

  const login = (newToken) => {
    localStorage.setItem("token", newToken);
    setToken(newToken);
  };

  const logout = () => {
    localStorage.removeItem("token");
    setToken(null);
  };

  return (
    <AuthContext.Provider value={{ token, user, role, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);

import React, { useState } from "react";
import { Link as RouterLink, useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import {
  AppBar,
  Toolbar,
  IconButton,
  Typography,
  Button,
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Avatar,
  Box,
  Menu,
  MenuItem,
  Divider,
  useTheme,
  useMediaQuery,
  Tooltip,
} from "@mui/material";
import MenuIcon from "@mui/icons-material/Menu";
import LogoutIcon from "@mui/icons-material/Logout";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import VolunteerActivismIcon from "@mui/icons-material/VolunteerActivism";
import DashboardIcon from "@mui/icons-material/Dashboard";
import MedicationIcon from "@mui/icons-material/Medication";
import AccountCircleIcon from "@mui/icons-material/AccountCircle";
import Brightness7Icon from "@mui/icons-material/Brightness7";
import Brightness4Icon from "@mui/icons-material/Brightness4";

const Navbar = ({ dark, setDark }) => {
  const { token, user, logout } = useAuth();
  const role = user?.role ?? "";
  const name = user?.name ?? "";
  const location = useLocation();
  const navigate = useNavigate();

  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [userAnchorEl, setUserAnchorEl] = useState(null);
  const openUserMenu = Boolean(userAnchorEl);

  const navLinks = [
    {
      label: "Dashboard",
      to: "/",
      icon: <DashboardIcon />,
      show: true,
    },
    {
      label: "Browse Medicines",
      to: "/medicines",
      icon: <MedicationIcon />,
      show: true,
    },
    {
      label: "Pending Medicines",
      to: "/admin/pending-medicines",
      icon: <AdminPanelSettingsIcon color="warning" />,
      show: role === "admin",
    },
    {
      label: "Logistics",
      to: "/logistics",
      icon: <VolunteerActivismIcon color="success" />,
      show: role === "volunteer",
    },
    {
      label: "Upload Medicine",
      to: "/upload",
      icon: <CloudUploadIcon color="info" />,
      show: !!token,
    },
  ];

  const handleDrawerToggle = () => setDrawerOpen((open) => !open);
  const handleUserMenuOpen = (event) => setUserAnchorEl(event.currentTarget);
  const handleUserMenuClose = () => setUserAnchorEl(null);

  const handleLogout = () => {
    logout();
    navigate("/login");
    handleUserMenuClose();
  };

  const DrawerList = (
    <Box
      sx={{ width: 260, pt: 2 }}
      role="presentation"
      onClick={handleDrawerToggle}
      onKeyDown={(e) => {
        if (e.key === "Tab" || e.key === "Shift") return;
        handleDrawerToggle();
      }}
    >
      <Typography variant="h6" sx={{ px: 2, pb: 1, fontWeight: 700 }}>
        MedBridge
      </Typography>
      <Divider sx={{ mb: 1 }} />
      <List>
        {navLinks
          .filter((link) => link.show)
          .map((link) => (
            <ListItem
              button
              key={link.label}
              component={RouterLink}
              to={link.to}
              selected={location.pathname === link.to}
              sx={{ borderRadius: 1 }}
            >
              <ListItemIcon>{link.icon}</ListItemIcon>
              <ListItemText primary={link.label} />
            </ListItem>
          ))}
      </List>
      <Divider sx={{ my: 1 }} />
      {!token ? (
        <List>
          <ListItem button component={RouterLink} to="/login">
            <ListItemText primary="Login" />
          </ListItem>
          <ListItem button component={RouterLink} to="/register">
            <ListItemText primary="Register" />
          </ListItem>
        </List>
      ) : (
        <List>
          <ListItem button component={RouterLink} to="/profile">
            <ListItemIcon>
              <AccountCircleIcon />
            </ListItemIcon>
            <ListItemText primary="My Profile" />
          </ListItem>
          <ListItem button onClick={handleLogout} sx={{ color: theme.palette.error.main }}>
            <ListItemIcon>
              <LogoutIcon color="error" />
            </ListItemIcon>
            <ListItemText primary="Logout" sx={{ color: theme.palette.error.main }} />
          </ListItem>
        </List>
      )}
    </Box>
  );

  return (
    <AppBar
      position="sticky"
      color="primary"
      elevation={4}
      sx={{
        minHeight: { xs: 56, md: 64 }, // 56px mobile, 64px desktop
        zIndex: 1300,
      }}
    >
      <Toolbar
        sx={{
          justifyContent: "space-between",
          alignItems: "center",
          px: { xs: 1, sm: 3 },
        }}
      >
        {/* Brand Logo */}
        <Typography
          component={RouterLink}
          to="/"
          variant="h6"
          sx={{
            fontWeight: 700,
            color: "#fff",
            textDecoration: "none",
            letterSpacing: 1,
            flexShrink: 0,
            mr: 2,
          }}
        >
          MedBridge
        </Typography>

        {/* Desktop: Nav Links */}
        {!isMobile && (
          <Box sx={{ display: "flex", flex: 1, gap: 1.7 }}>
            {navLinks
              .filter((link) => link.show)
              .map((link) => (
                <Button
                  key={link.label}
                  component={RouterLink}
                  to={link.to}
                  startIcon={link.icon}
                  color={location.pathname === link.to ? "secondary" : "inherit"}
                  variant={location.pathname === link.to ? "contained" : "text"}
                  sx={{
                    fontWeight: location.pathname === link.to ? 700 : 500,
                    borderRadius: 6,
                    minWidth: 145,
                    color: location.pathname === link.to ? "#fff" : "#e3f2fd",
                    boxShadow: location.pathname === link.to ? 1 : 0,
                    textTransform: "none",
                  }}
                >
                  {link.label}
                </Button>
              ))}
          </Box>
        )}

        {/* Responsive Hamburger Icon for Mobile */}
        {isMobile && (
          <IconButton
            color="inherit"
            edge="start"
            onClick={handleDrawerToggle}
            aria-label="open navigation menu"
            sx={{ ml: 0.5 }}
          >
            <MenuIcon />
          </IconButton>
        )}

        {/* Right: Dark Mode Toggle + User info & actions */}
        <Box sx={{ display: "flex", alignItems: "center", gap: { xs: 1, md: 2 } }}>
          <Tooltip title={dark ? "Switch to Light Mode" : "Switch to Dark Mode"}>
            <IconButton
              onClick={() => setDark(!dark)}
              color="inherit"
              aria-label="Toggle dark mode"
              size="large"
            >
              {dark ? <Brightness7Icon /> : <Brightness4Icon />}
            </IconButton>
          </Tooltip>

          {token && user ? (
            <>
              {!isMobile && (
                <Typography
                  variant="subtitle2"
                  sx={{
                    maxWidth: 145,
                    fontWeight: 600,
                    color: "#e3f2fd",
                    textOverflow: "ellipsis",
                    overflow: "hidden",
                    whiteSpace: "nowrap",
                    mr: 1,
                  }}
                  title={name}
                >
                  {name} <span style={{ color: "#b3d8ee", fontSize: 13 }}>({role})</span>
                </Typography>
              )}
              <IconButton
                onClick={handleUserMenuOpen}
                sx={{ p: 0.5 }}
                color="inherit"
                aria-label="open user menu"
                aria-controls={openUserMenu ? "user-menu" : undefined}
                aria-haspopup="true"
                aria-expanded={openUserMenu ? "true" : undefined}
              >
                <Avatar sx={{ bgcolor: theme.palette.secondary.main, width: 36, height: 36 }}>
                  {name[0]?.toUpperCase() || "U"}
                </Avatar>
              </IconButton>
              <Menu
                id="user-menu"
                anchorEl={userAnchorEl}
                open={openUserMenu}
                onClose={handleUserMenuClose}
                anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                transformOrigin={{ vertical: "top", horizontal: "right" }}
                keepMounted
              >
                <MenuItem component={RouterLink} to="/profile" onClick={handleUserMenuClose}>
                  My Profile
                </MenuItem>
                <Divider />
                <MenuItem onClick={handleLogout} sx={{ color: theme.palette.error.main }}>
                  <LogoutIcon sx={{ mr: 1 }} /> Logout
                </MenuItem>
              </Menu>
            </>
          ) : (
            <>
              <Button
                component={RouterLink}
                to="/login"
                variant="outlined"
                color="inherit"
                sx={{ fontWeight: 700, borderRadius: 6 }}
              >
                Login
              </Button>
              <Button
                component={RouterLink}
                to="/register"
                variant="contained"
                color="secondary"
                sx={{ fontWeight: 700, borderRadius: 6 }}
              >
                Register
              </Button>
            </>
          )}
        </Box>

        {/* Drawer for mobile */}
        <Drawer
          anchor="right"
          open={drawerOpen}
          onClose={handleDrawerToggle}
          PaperProps={{
            sx: {
              background: theme.palette.background.paper,
              minWidth: 240,
              pt: 2,
            },
          }}
        >
          {DrawerList}
        </Drawer>
      </Toolbar>
    </AppBar>
  );
};

export default Navbar;

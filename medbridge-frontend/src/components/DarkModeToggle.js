import React from "react";
import IconButton from "@mui/material/IconButton";
import Brightness7Icon from '@mui/icons-material/Brightness7'; // Sun for light
import Brightness4Icon from '@mui/icons-material/Brightness4'; // Moon for dark
import Tooltip from "@mui/material/Tooltip";

const DarkModeToggle = ({ dark, setDark }) => (
  <Tooltip title={dark ? "Switch to Light Mode" : "Switch to Dark Mode"}>
    <IconButton
      onClick={() => setDark(d => !d)}
      color="inherit"
      aria-label="Toggle dark mode"
      sx={{
        position: "fixed",
        top: 14,
        right: 18,
        zIndex: 2000,
        backgroundColor: "rgba(255,255,255,0.15)",
        "&:hover": {
          backgroundColor: "rgba(255,255,255,0.3)"
        },
      }}
      size="large"
    >
      {dark ? <Brightness7Icon /> : <Brightness4Icon />}
    </IconButton>
  </Tooltip>
);

export default DarkModeToggle;

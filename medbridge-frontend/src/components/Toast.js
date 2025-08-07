import React, { useEffect, useState } from "react";
import Snackbar from "@mui/material/Snackbar";
import Alert from "@mui/material/Alert";
import IconButton from "@mui/material/IconButton";
import CloseIcon from "@mui/icons-material/Close";
import Slide from "@mui/material/Slide";

/**
 * Custom Slide transition (from the right)
 */
function SlideTransition(props) {
  return <Slide {...props} direction="left" />;
}

export default function Toast({
  message,
  clear,
  severity = "info", // "error" | "warning" | "info" | "success"
  duration = 2500,
  position = { vertical: "top", horizontal: "right" },
  transition = SlideTransition // Optionally allow changing transition
}) {
  const [open, setOpen] = useState(Boolean(message));

  useEffect(() => {
    if (message) {
      setOpen(true);
    } else {
      setOpen(false);
    }
  }, [message]);

  const handleClose = (event, reason) => {
    if (reason === "clickaway") {
      return;
    }
    setOpen(false);
    clear?.();
  };

  return (
    <Snackbar
      open={open}
      autoHideDuration={duration}
      onClose={handleClose}
      anchorOrigin={position}
      TransitionComponent={transition}
      ClickAwayListenerProps={{ mouseEvent: false, touchEvent: false }}
    >
      <Alert
        onClose={handleClose}
        severity={severity}
        variant="filled"
        sx={{ width: "100%", boxShadow: 3, fontWeight: "bold", letterSpacing: 0.2 }}
        action={
          <IconButton
            aria-label="close"
            color="inherit"
            size="small"
            onClick={handleClose}
          >
            <CloseIcon fontSize="small" />
          </IconButton>
        }
      >
        {message}
      </Alert>
    </Snackbar>
  );
}

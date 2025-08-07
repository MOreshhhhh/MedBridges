import React, { useEffect, useState } from 'react';
import {
  Box,
  Button,
  CircularProgress,
  Snackbar,
  Alert,
  Typography,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  TextField
} from '@mui/material';
import { DataGrid } from '@mui/x-data-grid';
import api from '../../utils/api';

export default function AdminMedicines() {
  const [medicines, setMedicines] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  // Dialog state for editing medicine
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [currentMedicine, setCurrentMedicine] = useState(null);
  const [formValues, setFormValues] = useState({});

  // Load all medicines on mount
  useEffect(() => {
    fetchMedicines();
  }, []);

  const fetchMedicines = () => {
    setLoading(true);
    api.get('/admin/medicines')
      .then(res => {
        setMedicines(res.data.map(med => ({ ...med, id: med._id })));
        setError('');
      })
      .catch(err => setError(err.response?.data?.error || 'Failed to fetch medicines'))
      .finally(() => setLoading(false));
  };

  // Open edit dialog with medicine data
  const openEditDialog = (medicine) => {
    setCurrentMedicine(medicine);
    setFormValues({
      name: medicine.name || '',
      expiry: medicine.expiry ? medicine.expiry.substring(0,10) : '',
      quantity: medicine.quantity || 0,
      status: medicine.status || 'pending',
      verified: medicine.verified || false,
      isBlocked: medicine.isBlocked || false,
    });
    setEditDialogOpen(true);
  };

  // Handle form field changes
  const handleFormChange = (field, value) => {
    setFormValues(prev => ({ ...prev, [field]: value }));
  };

  // Submit updated medicine data
  const submitUpdate = () => {
    if (!currentMedicine) return;
    const payload = {
      name: formValues.name,
      expiry: formValues.expiry,
      quantity: Number(formValues.quantity),
      status: formValues.status,
      verified: formValues.verified,
      isBlocked: formValues.isBlocked,
    };
    api.put(`/admin/medicines/${currentMedicine._id}`, payload)
      .then(() => {
        setSnackbar({ open: true, message: 'Medicine updated successfully.', severity: 'success' });
        setEditDialogOpen(false);
        fetchMedicines();
      })
      .catch(err => {
        setSnackbar({
          open: true,
          message: err.response?.data?.error || 'Failed to update medicine',
          severity: 'error'
        });
      });
  };

  const columns = [
    { field: 'name', headerName: 'Name', flex: 1, minWidth: 150 },
    { field: 'donor', headerName: 'Donor', flex: 1, minWidth: 180, valueGetter: (params) => params.row.donor?.name || '-' },
    { field: 'uploadedAt', headerName: 'Uploaded At', width: 180, 
      valueGetter: (params) => new Date(params.row.uploadedAt).toLocaleString() },
    { field: 'expiry', headerName: 'Expiry', width: 140, 
      valueGetter: (params) => params.row.expiry ? new Date(params.row.expiry).toLocaleDateString() : '-' },
    { field: 'quantity', headerName: 'Quantity', width: 100 },
    { field: 'status', headerName: 'Status', width: 140 },
    { field: 'verified', headerName: 'Verified', width: 110, 
      renderCell: (params) => (params.value ? 'Yes' : 'No') },
    { field: 'isBlocked', headerName: 'Blocked', width: 110,
      renderCell: (params) => (params.value ? 'Yes' : 'No') },
    { field: 'claimedBy', headerName: 'Claimed By', flex:1, minWidth:180, 
      valueGetter: (params) => params.row.claimedBy?.name || '-' },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 120,
      renderCell: (params) => (
        <Button variant="contained" size="small" onClick={() => openEditDialog(params.row)}>
          Edit
        </Button>
      ),
    },
  ];

  if (loading) {
    return <Box display="flex" justifyContent="center" mt={4}><CircularProgress /></Box>;
  }

  if (error) {
    return <Typography variant="h6" color="error" align="center" mt={4}>{error}</Typography>;
  }

  return (
    <Box p={3}>
      <Typography variant="h4" gutterBottom>Medicines Management</Typography>
      <Box sx={{ height: 520, width: '100%' }}>
        <DataGrid
          rows={medicines}
          columns={columns}
          pageSize={10}
          rowsPerPageOptions={[10, 25, 50]}
          disableSelectionOnClick
          autoHeight
        />
      </Box>

      {/* Edit Medicine Dialog */}
      <Dialog open={editDialogOpen} onClose={() => setEditDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Edit Medicine</DialogTitle>
        <DialogContent>
          <TextField
            margin="normal"
            label="Name"
            fullWidth
            value={formValues.name}
            onChange={e => handleFormChange('name', e.target.value)}
          />
          <TextField
            margin="normal"
            label="Expiry Date"
            type="date"
            fullWidth
            value={formValues.expiry}
            onChange={e => handleFormChange('expiry', e.target.value)}
            InputLabelProps={{ shrink: true }}
          />
          <TextField
            margin="normal"
            label="Quantity"
            type="number"
            fullWidth
            value={formValues.quantity}
            onChange={e => handleFormChange('quantity', e.target.value)}
          />
          <FormControl fullWidth margin="normal" size="small">
            <InputLabel>Status</InputLabel>
            <Select
              value={formValues.status}
              label="Status"
              onChange={e => handleFormChange('status', e.target.value)}
            >
              <MenuItem value="pending">Pending</MenuItem>
              <MenuItem value="approved">Approved</MenuItem>
              <MenuItem value="rejected">Rejected</MenuItem>
              <MenuItem value="claimed">Claimed</MenuItem>
              <MenuItem value="delivered">Delivered</MenuItem>
            </Select>
          </FormControl>
          <FormControl fullWidth margin="normal" size="small">
            <InputLabel>Verified</InputLabel>
            <Select
              value={formValues.verified ? 'true' : 'false'}
              label="Verified"
              onChange={e => handleFormChange('verified', e.target.value === 'true')}
            >
              <MenuItem value="true">Yes</MenuItem>
              <MenuItem value="false">No</MenuItem>
            </Select>
          </FormControl>
          <FormControl fullWidth margin="normal" size="small">
            <InputLabel>Blocked</InputLabel>
            <Select
              value={formValues.isBlocked ? 'true' : 'false'}
              label="Blocked"
              onChange={e => handleFormChange('isBlocked', e.target.value === 'true')}
            >
              <MenuItem value="true">Yes</MenuItem>
              <MenuItem value="false">No</MenuItem>
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={submitUpdate}>Save Changes</Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar Notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert
          severity={snackbar.severity}
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}

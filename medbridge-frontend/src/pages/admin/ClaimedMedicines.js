import React, { useEffect, useState } from 'react';
import { Box, Typography, CircularProgress, Alert } from '@mui/material';
import { DataGrid } from '@mui/x-data-grid';
import api from '../../utils/api';

export default function ClaimedMedicines() {
  const [medicines, setMedicines] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const fetchClaimedMedicines = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await api.get('/admin/medicines/claimed');
      // Map data for DataGrid usage
      setMedicines(response.data.map(med => ({ ...med, id: med._id })));
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to fetch claimed medicines');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchClaimedMedicines();
  }, []);

  const columns = [
    { field: 'name', headerName: 'Medicine Name', flex: 1, minWidth: 150 },
    { field: 'donor', headerName: 'Donor', flex: 1, minWidth: 150, 
      valueGetter: (params) => params.row.donor?.name || '-' },
    { field: 'claimedBy', headerName: 'Claimed By', flex: 1, minWidth: 150, 
      valueGetter: (params) => params.row.claimedBy?.name || '-' },
    { field: 'status', headerName: 'Status', width: 130 },
    { field: 'uploadedAt', headerName: 'Uploaded At', width: 180, 
      valueGetter: (params) => params.row.uploadedAt ? new Date(params.row.uploadedAt).toLocaleString() : '-' },
  ];

  return (
    <Box p={3}>
      <Typography variant="h4" gutterBottom>
        Claimed Medicines
      </Typography>

      {loading && <CircularProgress />}

      {error && <Alert severity="error">{error}</Alert>}

      {!loading && !error && (
        <Box sx={{ height: 550, width: '100%' }}>
          <DataGrid
            rows={medicines}
            columns={columns}
            pageSize={10}
            rowsPerPageOptions={[10, 25, 50]}
            disableSelectionOnClick
            autoHeight
          />
        </Box>
      )}
    </Box>
  );
}

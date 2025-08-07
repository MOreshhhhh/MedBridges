import React, { useEffect, useState } from 'react';
import { Box, Typography, CircularProgress, Alert, ToggleButtonGroup, ToggleButton } from '@mui/material';
import { DataGrid } from '@mui/x-data-grid';
import api from '../../utils/api';

export default function RegisteredUsers() {
  const [role, setRole] = useState('ngo');
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const fetchUsers = async (selectedRole) => {
    setLoading(true);
    setError('');
    try {
      const response = await api.get(`/admin/users?role=${selectedRole}`);
      setUsers(response.data.map(user => ({ ...user, id: user._id })));
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to fetch users');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers(role);
  }, [role]);

  const columns = [
    { field: 'name', headerName: 'Name', flex: 1, minWidth: 150 },
    { field: 'email', headerName: 'Email', flex: 1, minWidth: 200 },
    { field: 'createdAt', headerName: 'Registered On', width: 180, 
      valueGetter: (params) => new Date(params.row.createdAt).toLocaleString() },
  ];

  return (
    <Box p={3}>
      <Typography variant="h4" gutterBottom>
        Registered Users
      </Typography>

      <ToggleButtonGroup
        value={role}
        exclusive
        onChange={(e, newRole) => {
          if (newRole) setRole(newRole);
        }}
        sx={{ mb: 2 }}
      >
        <ToggleButton value="ngo">NGOs</ToggleButton>
        <ToggleButton value="donor">Donors</ToggleButton>
      </ToggleButtonGroup>

      {loading && <CircularProgress />}

      {error && <Alert severity="error">{error}</Alert>}

      {!loading && !error && (
        <Box sx={{ height: 500, width: '100%' }}>
          <DataGrid
            rows={users}
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

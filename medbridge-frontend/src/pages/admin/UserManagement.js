// src/pages/admin/UserManagement.js
import React, { useEffect, useState } from 'react';
import { DataGrid } from '@mui/x-data-grid';
import {
  Box,
  Button,
  CircularProgress,
  Snackbar,
  Alert,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem
} from '@mui/material';
import api from '../../utils/api';

export default function UserManagement() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  // Fetch users on mount or when roleFilter changes
  useEffect(() => {
    setLoading(true);
    api.get('/admin/users', { params: { role: roleFilter || undefined } })
      .then(res => setUsers(res.data.map(user => ({ ...user, id: user._id }))))
      .catch(err => setError(err.message || 'Failed to fetch users'))
      .finally(() => setLoading(false));
  }, [roleFilter]);

  // Handler to toggle blocking/unblocking user
  const toggleBlock = async (userId, currentlyBlocked) => {
    try {
      await api.patch(`/admin/users/${userId}/block`, { isBlocked: !currentlyBlocked });
      setSnackbar({
        open: true,
        message: `User ${!currentlyBlocked ? 'blocked' : 'unblocked'} successfully.`,
        severity: 'success'
      });
      // Refresh user list
      setUsers(prevUsers => prevUsers.map(u => u.id === userId ? { ...u, isBlocked: !currentlyBlocked } : u));
    } catch (err) {
      setSnackbar({
        open: true,
        message: err.response?.data?.message || 'Failed to update user status',
        severity: 'error'
      });
    }
  };

  const columns = [
    { field: 'name', headerName: 'Name', flex: 1, minWidth: 130 },
    { field: 'email', headerName: 'Email', flex: 1, minWidth: 200 },
    { field: 'role', headerName: 'Role', flex: 0.7, minWidth: 120 },
    {
      field: 'createdAt',
      headerName: 'Registered',
      width: 180,
      valueGetter: (params) => new Date(params.row.createdAt).toLocaleString()
    },
    {
      field: 'isBlocked',
      headerName: 'Blocked',
      width: 110,
      renderCell: (params) => (params.value ? 'Yes' : 'No')
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width:100,
      renderCell: (params) => (
        <Button
          size="small"
          variant={params.row.isBlocked ? 'contained' : 'outlined'}
          color={params.row.isBlocked ? 'success' : 'error'}
          onClick={() => toggleBlock(params.row.id, params.row.isBlocked)}
        >
          {params.row.isBlocked ? 'Unblock' : 'Block'}
        </Button>
      )
    }
  ];

  if (loading) return <Box display="flex" justifyContent="center" mt={4}><CircularProgress /></Box>;
  if (error) return <Typography color="error" variant="h6" align="center" mt={4}>{error}</Typography>;

  return (
    <Box p={3}>
      <Typography variant="h4" gutterBottom>User Management</Typography>
      <Box mb={2} width={150}>
        <FormControl fullWidth size="small">
          <InputLabel id="role-filter-label">Filter by Role</InputLabel>
          <Select
            labelId="role-filter-label"
            value={roleFilter}
            label="Filter by Role"
            onChange={e => setRoleFilter(e.target.value)}
          >
            <MenuItem value=''>All Roles</MenuItem>
            <MenuItem value='Admin'>Admin</MenuItem>
            <MenuItem value='Donor'>Donor</MenuItem>
            <MenuItem value='NGO'>NGO</MenuItem>
            <MenuItem value='Volunteer'>Volunteer</MenuItem>
          </Select>
        </FormControl>
      </Box>
      <Box sx={{ height: 520, width: '100%' }}>
        <DataGrid
          rows={users}
          columns={columns}
          pageSize={10}
          rowsPerPageOptions={[10, 25, 50]}
          disableSelectionOnClick
          autoHeight
        />
      </Box>
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert severity={snackbar.severity} onClose={() => setSnackbar({ ...snackbar, open: false })}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}

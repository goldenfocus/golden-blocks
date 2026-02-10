import { Elysia, t } from 'elysia';
import { requireRole } from '../middleware/auth';
import { updateUserRole, getUserById, getAdminClient } from '../db/client';
import { UserRole } from '../types';

// Update user role (admin only)
export const updateUserRoleRoute = (app: Elysia) =>
  app.patch(
    '/admin/users/:userId/role',
    async ({ params, body, user, error }) => {
      const { userId } = params;
      const { role } = body as { role: UserRole };

      // Only admins can update roles
      if (user?.role !== 'admin') {
        return error(403, { 
          success: false, 
          message: 'Only admins can update user roles' 
        });
      }

      const validRoles: UserRole[] = ['admin', 'moderator', 'user', 'guest'];
      if (!validRoles.includes(role)) {
        return error(400, { 
          success: false, 
          message: 'Invalid role' 
        });
      }

      // Prevent demoting yourself
      if (user.sub === userId && role !== 'admin') {
        return error(400, { 
          success: false, 
          message: 'Cannot demote your own admin account' 
        });
      }

      try {
        const updatedUser = await updateUserRole(userId, role);
        
        return {
          success: true,
          message: 'User role updated successfully',
          data: {
            id: updatedUser.id,
            email: updatedUser.email,
            role: updatedUser.role,
          },
        };
      } catch (err: any) {
        return error(500, { 
          success: false, 
          message: 'Failed to update user role',
          error: err.message 
        });
      }
    },
    {
      body: t.Object({
        role: t.Union([
          t.Literal('admin'),
          t.Literal('moderator'),
          t.Literal('user'),
          t.Literal('guest'),
        ]),
      }),
    }
  )
  .use(requireRole('admin'));

// Get all users (admin only)
export const getAllUsersRoute = (app: Elysia) =>
  app.get(
    '/admin/users',
    async ({ query, user, error }) => {
      if (user?.role !== 'admin') {
        return error(403, { 
          success: false, 
          message: 'Admin access required' 
        });
      }

      const page = parseInt(query.page || '1');
      const limit = parseInt(query.limit || '20');
      const offset = (page - 1) * limit;

      const admin = getAdminClient();

      const { data: users, error: dbError, count } = await admin
        .from('users')
        .select('id, email, name, role, created_at, updated_at', { count: 'exact' })
        .range(offset, offset + limit - 1)
        .order('created_at', { ascending: false });

      if (dbError) {
        return error(500, { 
          success: false, 
          message: 'Failed to fetch users',
          error: dbError.message 
        });
      }

      return {
        success: true,
        data: {
          users: users || [],
          pagination: {
            page,
            limit,
            total: count || 0,
            totalPages: Math.ceil((count || 0) / limit),
          },
        },
      };
    },
    {
      query: t.Object({
        page: t.Optional(t.String()),
        limit: t.Optional(t.String()),
      }),
    }
  )
  .use(requireRole('admin'));

// Get user by ID (admin only)
export const getUserByIdRoute = (app: Elysia) =>
  app.get(
    '/admin/users/:userId',
    async ({ params, user, error }) => {
      if (user?.role !== 'admin') {
        return error(403, { 
          success: false, 
          message: 'Admin access required' 
        });
      }

      try {
        const userData = await getUserById(params.userId);
        
        if (!userData) {
          return error(404, { 
            success: false, 
            message: 'User not found' 
          });
        }

        return {
          success: true,
          data: {
            id: userData.id,
            email: userData.email,
            name: userData.name,
            role: userData.role,
            created_at: userData.created_at,
            updated_at: userData.updated_at,
          },
        };
      } catch (err: any) {
        return error(500, { 
          success: false, 
          message: 'Failed to fetch user',
          error: err.message 
        });
      }
    }
  )
  .use(requireRole('admin'));

// Health check endpoint
export const healthRoute = (app: Elysia) =>
  app.get('/health', async () => {
    return {
      success: true,
      message: 'Auth Block API is healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
    };
  });

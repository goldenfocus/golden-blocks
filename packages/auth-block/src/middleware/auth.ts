import { Elysia, t } from 'elysia';
import { jwt } from '@elysiajs/jwt';
import { JWTPayload, ROLE_PERMISSIONS, UserRole } from '../types';

export function setupJWT(app: Elysia) {
  return app.use(
    jwt({
      name: 'jwt',
      secret: process.env.JWT_SECRET || 'development-secret-change-in-production',
      exp: '15m', // 15 minutes
    })
  );
}

export function setupRefreshJWT(app: Elysia) {
  return app.use(
    jwt({
      name: 'refreshJwt',
      secret: process.env.JWT_REFRESH_SECRET || 'development-refresh-secret-change-in-production',
      exp: '7d', // 7 days
    })
  );
}

// JWT Authentication middleware
export const authMiddleware = (app: Elysia) =>
  app
    .derive(async ({ jwt, cookie, error }) => {
      const accessToken = cookie['access_token']?.value;
      
      if (!accessToken) {
        return { user: null };
      }

      try {
        const payload = await jwt.verify(accessToken) as JWTPayload;
        return { user: payload };
      } catch {
        return { user: null };
      }
    })
    .map(({ user }) => {
      if (!user) {
        return { user: null };
      }
      return { user };
    });

// Optional auth - continues even if not authenticated
export const optionalAuth = (app: Elysia) =>
  app.derive(async ({ jwt, cookie }) => {
    const accessToken = cookie['access_token']?.value;
    
    if (!accessToken) {
      return { user: null };
    }

    try {
      const payload = await jwt.verify(accessToken) as JWTPayload;
      return { user: payload };
    } catch {
      return { user: null };
    }
  });

// RBAC middleware factory
export function requireRole(...allowedRoles: UserRole[]) {
  return (app: Elysia) =>
    app.derive(({ user, error }) => {
      if (!user) {
        return error(401, { success: false, message: 'Authentication required' });
      }

      if (!allowedRoles.includes(user.role)) {
        return error(403, { 
          success: false, 
          message: 'Insufficient permissions',
          required: allowedRoles,
          current: user.role
        });
      }

      return { user };
    });
}

// Permission check helper
export function hasPermission(
  userRole: UserRole,
  resource: string,
  action: string
): boolean {
  const permissions = ROLE_PERMISSIONS[userRole];
  
  return permissions.some(p => {
    const resourceMatch = p.resource === '*' || p.resource === resource;
    const actionMatch = p.action === action || p.action === 'admin';
    return resourceMatch && actionMatch;
  });
}

// RBAC middleware factory for specific permissions
export function requirePermission(resource: string, action: 'create' | 'read' | 'update' | 'delete' | 'admin') {
  return (app: Elysia) =>
    app.derive(({ user, error }) => {
      if (!user) {
        return error(401, { success: false, message: 'Authentication required' });
      }

      if (!hasPermission(user.role, resource, action)) {
        return error(403, { 
          success: false, 
          message: `Permission denied: ${action} on ${resource}`,
          required: { resource, action },
          current: user.role
        });
      }

      return { user };
    });
}

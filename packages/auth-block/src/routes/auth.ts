import { Elysia, t } from 'elysia';
import { z } from 'zod';
import { 
  getUserByEmail, 
  createUser, 
  verifyPassword, 
  hashPassword,
  getUserById 
} from '../db/client';
import { JWTPayload, User } from '../types';

// Request validation schemas
const registerSchema = t.Object({
  email: t.String({ format: 'email' }),
  password: t.String({ minLength: 8 }),
  confirmPassword: t.String({ minLength: 8 }),
  name: t.Optional(t.String({ minLength: 1, maxLength: 100 })),
});

const loginSchema = t.Object({
  email: t.String({ format: 'email' }),
  password: t.String(),
});

const refreshSchema = t.Object({
  refreshToken: t.String(),
});

// Helper to create tokens
async function createTokens(user: any, jwt: any, refreshJwt: any) {
  const payload: JWTPayload = {
    sub: user.id,
    email: user.email,
    role: user.role,
  };

  const accessToken = await jwt.sign(payload);
  const refreshToken = await refreshJwt.sign({ sub: user.id });

  return {
    accessToken,
    refreshToken,
    expiresIn: 900, // 15 minutes in seconds
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
      name: user.name,
      created_at: user.created_at,
      updated_at: user.updated_at,
    },
  };
}

// Register endpoint
export const registerRoute = (app: Elysia) =>
  app.post(
    '/register',
    async ({ body, jwt, refreshJwt, error, set }) => {
      const { email, password, confirmPassword, name } = body;

      // Validate passwords match
      if (password !== confirmPassword) {
        return error(400, { 
          success: false, 
          message: 'Passwords do not match' 
        });
      }

      // Check if user exists
      const existingUser = await getUserByEmail(email);
      if (existingUser) {
        return error(409, { 
          success: false, 
          message: 'User with this email already exists' 
        });
      }

      // Hash password and create user
      const passwordHash = await hashPassword(password);
      
      try {
        const user = await createUser(email, passwordHash, name);
        const tokens = await createTokens(user, jwt, refreshJwt);

        set.status = 201;
        return {
          success: true,
          message: 'User registered successfully',
          data: tokens,
        };
      } catch (err: any) {
        return error(500, { 
          success: false, 
          message: 'Failed to create user',
          error: err.message 
        });
      }
    },
    { body: registerSchema }
  );

// Login endpoint
export const loginRoute = (app: Elysia) =>
  app.post(
    '/login',
    async ({ body, jwt, refreshJwt, error }) => {
      const { email, password } = body;

      const user = await getUserByEmail(email);
      if (!user) {
        return error(401, { 
          success: false, 
          message: 'Invalid email or password' 
        });
      }

      const isValid = await verifyPassword(user, password);
      if (!isValid) {
        return error(401, { 
          success: false, 
          message: 'Invalid email or password' 
        });
      }

      const tokens = await createTokens(user, jwt, refreshJwt);

      return {
        success: true,
        message: 'Login successful',
        data: tokens,
      };
    },
    { body: loginSchema }
  );

// Refresh token endpoint
export const refreshRoute = (app: Elysia) =>
  app.post(
    '/refresh',
    async ({ body, jwt, refreshJwt, error }) => {
      const { refreshToken } = body;

      try {
        const payload = await refreshJwt.verify(refreshToken);
        const user = await getUserById(payload.sub);

        if (!user) {
          return error(401, { 
            success: false, 
            message: 'User not found' 
          });
        }

        const tokens = await createTokens(user, jwt, refreshJwt);

        return {
          success: true,
          message: 'Token refreshed successfully',
          data: tokens,
        };
      } catch {
        return error(401, { 
          success: false, 
          message: 'Invalid or expired refresh token' 
        });
      }
    },
    { body: refreshSchema }
  );

// Logout endpoint
export const logoutRoute = (app: Elysia) =>
  app.post(
    '/logout',
    async ({ cookie, set }) => {
      // Clear cookies
      cookie['access_token'].remove();
      cookie['refresh_token'].remove();

      set.status = 200;
      return {
        success: true,
        message: 'Logged out successfully',
      };
    }
  );

// Get current user endpoint
export const meRoute = (app: Elysia) =>
  app.get(
    '/me',
    async ({ user, error }) => {
      if (!user) {
        return error(401, { 
          success: false, 
          message: 'Not authenticated' 
        });
      }

      try {
        const dbUser = await getUserById(user.sub);
        if (!dbUser) {
          return error(404, { 
            success: false, 
            message: 'User not found' 
          });
        }

        return {
          success: true,
          data: {
            id: dbUser.id,
            email: dbUser.email,
            role: dbUser.role,
            name: dbUser.name,
            created_at: dbUser.created_at,
            updated_at: dbUser.updated_at,
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
  );

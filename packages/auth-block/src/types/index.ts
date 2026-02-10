// Role-based access control types
export type UserRole = 'admin' | 'moderator' | 'user' | 'guest';

export interface JWTPayload {
  sub: string; // user id
  email: string;
  role: UserRole;
  iat?: number;
  exp?: number;
}

export interface RefreshPayload {
  sub: string;
  iat?: number;
  exp?: number;
}

export interface User {
  id: string;
  email: string;
  role: UserRole;
  created_at: string;
  updated_at: string;
}

// Request body types
export interface RegisterRequest {
  email: string;
  password: string;
  confirmPassword: string;
  name?: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface OAuthCallbackRequest {
  provider: 'google' | 'github';
  code: string;
  redirect_uri: string;
}

// Response types
export interface AuthResponse {
  success: boolean;
  message: string;
  data?: {
    user: Omit<User, 'password_hash'>;
    accessToken: string;
    refreshToken?: string;
  };
}

export interface TokenResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

// RBAC Permission types
export interface Permission {
  resource: string;
  action: 'create' | 'read' | 'update' | 'delete' | 'admin';
}

export const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  admin: [
    { resource: '*', action: 'admin' },
    { resource: '*', action: 'create' },
    { resource: '*', action: 'read' },
    { resource: '*', action: 'update' },
    { resource: '*', action: 'delete' },
  ],
  moderator: [
    { resource: 'content', action: 'read' },
    { resource: 'content', action: 'update' },
    { resource: 'content', action: 'delete' },
    { resource: 'users', action: 'read' },
  ],
  user: [
    { resource: 'content', action: 'create' },
    { resource: 'content', action: 'read' },
    { resource: 'content', action: 'update' },
  ],
  guest: [
    { resource: 'content', action: 'read' },
  ],
};

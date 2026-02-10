import { Elysia, t } from 'elysia';
import { 
  getUserByEmail, 
  createUser, 
  getUserById,
  getAdminClient 
} from '../db/client';
import { JWTPayload } from '../types';

// OAuth configuration
const OAUTH_CONFIG = {
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID || '',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
  },
  github: {
    clientId: process.env.GITHUB_CLIENT_ID || '',
    clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
    authUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userInfoUrl: 'https://api.github.com/user',
  },
};

// Helper to generate OAuth URL
function generateOAuthUrl(provider: 'google' | 'github', redirectUri: string) {
  const config = OAUTH_CONFIG[provider];
  const state = crypto.randomUUID();
  
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: provider === 'google' 
      ? 'openid email profile'
      : 'read:user user:email',
    state,
    access_type: 'offline',
    prompt: 'consent',
  });

  return { url: `${config.authUrl}?${params.toString()}`, state };
}

// Helper to exchange code for tokens
async function exchangeCodeForTokens(
  provider: 'google' | 'github',
  code: string,
  redirectUri: string
) {
  const config = OAUTH_CONFIG[provider];
  
  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }),
  });

  if (!response.ok) {
    throw new Error(`Failed to exchange code: ${await response.text()}`);
  }

  return response.json();
}

// Helper to get user info from provider
async function getUserInfo(provider: 'google' | 'github', accessToken: string) {
  const config = OAUTH_CONFIG[provider];
  
  const response = await fetch(config.userInfoUrl, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch user info: ${await response.text()}`);
  }

  const data = await response.json();

  if (provider === 'google') {
    return {
      email: data.email,
      name: data.name,
      providerId: data.sub,
      avatar: data.picture,
    };
  }

  return {
    email: data.email,
    name: data.name || data.login,
    providerId: data.id.toString(),
    avatar: data.avatar_url,
  };
}

// Helper to create/update OAuth user
async function findOrCreateOAuthUser(
  provider: 'google' | 'github',
  providerId: string,
  email: string,
  name?: string
) {
  const admin = getAdminClient();

  // Try to find existing user by email
  let user = await getUserByEmail(email);

  if (user) {
    // Update OAuth provider info if needed
    await admin
      .from('users')
      .update({ 
        name: name || user.name,
        updated_at: new Date().toISOString()
      })
      .eq('id', user.id);
    
    return user;
  }

  // Create new user
  const { data, error } = await admin
    .from('users')
    .insert({
      email,
      name: name || email.split('@')[0],
      role: 'user',
      provider,
      provider_id: providerId,
    })
    .select()
    .single();

  if (error) throw error;
  return data;
}

// OAuth URL endpoint
export const oauthUrlRoute = (app: Elysia) =>
  app.get(
    '/oauth/:provider',
    async ({ params, error, set }) => {
      const { provider } = params;

      if (!['google', 'github'].includes(provider)) {
        return error(400, { 
          success: false, 
          message: 'Invalid provider' 
        });
      }

      const baseUrl = process.env.APP_URL || 'http://localhost:3000';
      const redirectUri = `${baseUrl}/api/auth/oauth/callback`;
      const { url, state } = generateOAuthUrl(provider as 'google' | 'github', redirectUri);

      return {
        success: true,
        data: { url, state },
      };
    }
  );

// OAuth callback endpoint
export const oauthCallbackRoute = (app: Elysia) =>
  app.post(
    '/oauth/callback',
    async ({ body, jwt, refreshJwt, error }) => {
      const { provider, code, redirect_uri } = body;

      if (!['google', 'github'].includes(provider)) {
        return error(400, { 
          success: false, 
          message: 'Invalid provider' 
        });
      }

      try {
        // Exchange code for tokens
        const tokens = await exchangeCodeForTokens(
          provider as 'google' | 'github',
          code,
          redirect_uri
        );

        // Get user info
        const userInfo = await getUserInfo(
          provider as 'google' | 'github',
          tokens.access_token
        );

        // Find or create user
        const user = await findOrCreateOAuthUser(
          provider as 'google' | 'github',
          userInfo.providerId,
          userInfo.email,
          userInfo.name
        );

        // Create JWT tokens
        const payload: JWTPayload = {
          sub: user.id,
          email: user.email,
          role: user.role,
        };

        const accessToken = await jwt.sign(payload);
        const refreshToken = await refreshJwt.sign({ sub: user.id });

        return {
          success: true,
          message: 'OAuth authentication successful',
          data: {
            accessToken,
            refreshToken,
            expiresIn: 900,
            user: {
              id: user.id,
              email: user.email,
              role: user.role,
              name: user.name,
              avatar: userInfo.avatar,
            },
          },
        };
      } catch (err: any) {
        console.error('OAuth error:', err);
        return error(500, { 
          success: false, 
          message: 'OAuth authentication failed',
          error: err.message 
        });
      }
    },
    {
      body: t.Object({
        provider: t.Union([t.Literal('google'), t.Literal('github')]),
        code: t.String(),
        redirect_uri: t.String({ format: 'uri' }),
      }),
    }
  );

// Get OAuth URLs helper endpoint
export const oauthProvidersRoute = (app: Elysia) =>
  app.get('/oauth/providers', async () => {
    const providers = [];
    
    if (process.env.GOOGLE_CLIENT_ID) {
      providers.push({
        name: 'google',
        label: 'Google',
        icon: 'google',
      });
    }
    
    if (process.env.GITHUB_CLIENT_ID) {
      providers.push({
        name: 'github',
        label: 'GitHub',
        icon: 'github',
      });
    }

    return {
      success: true,
      data: { providers },
    };
  });

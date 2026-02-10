import { Elysia, t } from 'elysia';
import cors from '@elysiajs/cors';
import { setupJWT, setupRefreshJWT, authMiddleware } from './middleware/auth';
import { 
  registerRoute, 
  loginRoute, 
  refreshRoute, 
  logoutRoute,
  meRoute 
} from './routes/auth';
import { 
  oauthUrlRoute, 
  oauthCallbackRoute,
  oauthProvidersRoute 
} from './routes/oauth';
import { 
  updateUserRoleRoute, 
  getAllUsersRoute,
  getUserByIdRoute,
  healthRoute 
} from './routes/admin';

// Create the Elysia app
const app = new Elysia()
  // CORS configuration
  .use(
    cors({
      origin: process.env.CORS_ORIGIN?.split(',') || '*',
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      credentials: true,
      allowedHeaders: ['Content-Type', 'Authorization'],
    })
  )
  // Cookie configuration
  .derive(({ cookie }) => ({
    cookies: cookie,
  }))
  // JWT setup
  .use(setupJWT)
  .use(setupRefreshJWT)
  // Cookie parsing
  .derive(({ cookie }) => {
    return {
      accessToken: cookie['access_token'],
      refreshToken: cookie['refresh_token'],
    };
  })
  // Health check
  .use(healthRoute)
  // Auth routes
  .use(registerRoute)
  .use(loginRoute)
  .use(refreshRoute)
  .use(logoutRoute)
  .use(meRoute)
  // OAuth routes
  .use(oauthUrlRoute)
  .use(oauthCallbackRoute)
  .use(oauthProvidersRoute)
  // Admin routes (RBAC protected)
  .use(getAllUsersRoute)
  .use(getUserByIdRoute)
  .use(updateUserRoleRoute)
  // Error handling
  .onError(({ error, set }) => {
    console.error('Error:', error);

    // Handle validation errors
    if (error.message?.includes('Validation')) {
      set.status = 400;
      return {
        success: false,
        message: 'Validation error',
        error: error.message,
      };
    }

    // Handle known errors
    set.status = error.status || 500;
    return {
      success: false,
      message: error.message || 'Internal server error',
    };
  })
  // Request logging
  .onRequest(({ request, method, url }) => {
    console.log(`${method} ${url}`);
  });

// Export the app for programmatic use
export { app };

// Start the server if this file is run directly
if (process.env.NODE_ENV !== 'test') {
  const port = parseInt(process.env.PORT || '3001');
  const host = process.env.HOST || '0.0.0.0';

  app.listen(port, host, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║           🛡️  GoldenBlocks Auth Block API                 ║
╠═══════════════════════════════════════════════════════════╣
║  🚀 Server running on http://${host}:${port}                      ║
║  📚 API Documentation: http://${host}:${port}/docs                ║
║  ❤️  Health Check: http://${host}:${port}/health                  ║
╚═══════════════════════════════════════════════════════════╝
    `);
  });
}

export type App = typeof app;

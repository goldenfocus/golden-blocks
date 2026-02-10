import { createClient, SupabaseClient } from '@supabase/supabase-js';

let supabase: SupabaseClient | null = null;

export function getSupabase(): SupabaseClient {
  if (!supabase) {
    const url = process.env.SUPABASE_URL;
    const anonKey = process.env.SUPABASE_ANON_KEY;

    if (!url || !anonKey) {
      throw new Error('SUPABASE_URL and SUPABASE_ANON_KEY must be set');
    }

    supabase = createClient(url, anonKey);
  }

  return supabase;
}

export function getAdminClient(): SupabaseClient {
  const url = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_KEY;

  if (!url || !serviceKey) {
    throw new Error('SUPABASE_URL and SUPABASE_SERVICE_KEY must be set');
  }

  return createClient(url, serviceKey);
}

// Database schema helper functions
export async function createUser(
  email: string,
  passwordHash: string,
  name?: string,
  role: 'user' = 'user'
) {
  const admin = getAdminClient();
  
  const { data, error } = await admin
    .from('users')
    .insert({
      email,
      password_hash: passwordHash,
      name: name || email.split('@')[0],
      role,
    })
    .select()
    .single();

  if (error) throw error;
  return data;
}

export async function getUserByEmail(email: string) {
  const supabase = getSupabase();
  
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();

  if (error && error.code !== 'PGRST116') throw error;
  return data;
}

export async function getUserById(id: string) {
  const supabase = getSupabase();
  
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('id', id)
    .single();

  if (error && error.code !== 'PGRST116') throw error;
  return data;
}

export async function updateUserRole(userId: string, role: 'admin' | 'moderator' | 'user') {
  const admin = getAdminClient();
  
  const { data, error } = await admin
    .from('users')
    .update({ role, updated_at: new Date().toISOString() })
    .eq('id', userId)
    .select()
    .single();

  if (error) throw error;
  return data;
}

export async function verifyPassword(user: any, password: string): Promise<boolean> {
  // In production, use argon2 or bcrypt to verify
  // This is a placeholder - implement proper password verification
  const { hash, verify } = await import('argon2');
  
  try {
    return await verify(user.password_hash, password);
  } catch {
    return false;
  }
}

export async function hashPassword(password: string): Promise<string> {
  const { hash } = await import('argon2');
  return await hash(password);
}

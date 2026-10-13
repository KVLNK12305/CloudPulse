import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || 'https://vrwqpgodyndyszgnnssn.supabase.co';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

export const isSupabaseConfigured = Boolean(
  supabaseAnonKey &&
  supabaseAnonKey !== 'PASTE_YOUR_SUPABASE_ANON_KEY_HERE' &&
  !supabaseAnonKey.includes('PASTE_YOUR')
);

export const supabase = createClient(
  supabaseUrl,
  isSupabaseConfigured ? supabaseAnonKey : 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy',
  {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true,
    },
  }
);

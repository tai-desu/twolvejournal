/* ============================================================
   TWØLVE — cloud sync configuration (optional)

   Leave both values empty ("") and the journal runs fully local
   (one browser, one device, encrypted in localStorage).

   To sync across devices with Supabase:
   1. Create a free project at supabase.com
   2. Run the SQL from README.md (creates your `vaults` table)
   3. Project Settings → API → copy the two values below
   4. Commit this file and redeploy
   ============================================================ */
const SUPABASE_URL = "https://bshqrrfczetumqktvhwm.supabase.co";       // e.g. "https://abcdefgh.supabase.co"
const SUPABASE_ANON_KEY = "sb_publishable_xdKFBb4125hCdWKeNkZvbQ_1KwIfaDa";  // the long "anon public" key

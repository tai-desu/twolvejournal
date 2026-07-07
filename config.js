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
const SUPABASE_URL = "";       // e.g. "https://abcdefgh.supabase.co"
const SUPABASE_ANON_KEY = "";  // the long "anon public" key

/* Set to false once your account exists to hide the Create account
   button. Also disable "Allow new users to sign up" in Supabase
   (Authentication settings) — that's the real server-side lock. */
const ALLOW_SIGNUP = true;

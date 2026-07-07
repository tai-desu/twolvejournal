# TWØLVE — private life-wheel journal

A personal journal built around the 12 life areas wheel. Two sections:

- **Journal** — daily writing (feelings, struggles, reflection) plus goals, per area. Scroll to turn the wheel and move between areas, exactly like the arc-numeral navigation reference.
- **Book** — read everything you have written as an open book: one chapter per area (use the thumb tabs), one entry per page, with animated page turns. Arrow keys work too.
- **Evaluation** — every ~3 months, score every category 1–10 ("how satisfied am I with this right now?"). Scores render as a wheel chart: each category radiates out from a red core (low) toward a blue rim (high). The app reminds you when 90 days have passed.

No server, no accounts, no tracking. Everything you write is **encrypted with your password (AES-256-GCM, key derived with PBKDF2)** and stored only in your own browser.

## Files

| file | what it is |
|---|---|
| `index.html` | the app shell |
| `styles.css` | all styling |
| `app.js` | logic: encryption, wheel, journal, evaluation chart, settings |
| `quotes.js` | **the 100 motivation quotes — edit this file any time** to add/replace quotes |
| `config.js` | optional Supabase keys for cross-device sync (empty = local-only mode) |

## Put it on GitHub (free hosting via GitHub Pages)

1. Create a **new repository** on github.com. Set it to **Private** if you want the code hidden too (Pages from a private repo needs GitHub Pro; a public repo is also fine — the repo only contains code, never your journal data).
2. Upload these four files to the repo root (`Add file → Upload files`).
3. Go to **Settings → Pages → Source: Deploy from a branch → main / (root) → Save**.
4. After a minute your journal is live at `https://<your-username>.github.io/<repo-name>/`.
5. Open it, set your password, start writing.

To update the quotes later: edit `quotes.js` on GitHub and commit — the site redeploys automatically.

## How the security works (honest version)

- On first visit you set a password. A key is derived from it (PBKDF2, 310k iterations) and every save encrypts the whole journal with AES-GCM before it touches `localStorage`.
- Without the password, the stored data is unreadable ciphertext. **There is no password recovery** — that's the price of real encryption. If you forget it, only an exported backup can save you.
- The lock button (and closing the tab) drops the key from memory.
- Caveats to know: data lives in *one browser on one device*. Clearing site data deletes it. So back up regularly — the app shows a reminder banner if you've never exported or if your last export is older than 14 days.

## Backup routine (recommended)

Two export formats in Settings, import accepts both:
- **Readable (.json)** — plain text you can open anywhere, forever. Keep it somewhere private (encrypted disk, password-protected folder).
- **Encrypted (.json)** — the AES-encrypted vault; unreadable without your password. Safe to drop into any cloud drive (Google Drive, iCloud, Dropbox).

The simple habit: when the reminder banner appears (every 14 days), click Export. Keep the latest readable copy somewhere private on your device and the encrypted copy in your cloud drive — one local, one remote. To move to a new device or recover after clearing browser data, open the app and import either file (the encrypted one asks you to log in with the password it was created under).


## Optional: sync across devices (Supabase)

Out of the box the journal is local-only. To make it live in the cloud and sync between your phone and laptop:

1. Create a free project at **supabase.com** (the free tier is plenty for a personal journal).
2. In the Supabase dashboard, open **SQL Editor** and run:

```sql
create table vaults (
  user_id uuid primary key references auth.users(id) on delete cascade,
  salt text not null,
  iv text not null,
  data text not null,
  updated_at timestamptz default now()
);
alter table vaults enable row level security;
create policy "own vault" on vaults
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
```

3. **Authentication → Sign In / Up → Email**: make sure Email is enabled. For instant login without email confirmation, turn **off** "Confirm email" (fine for a personal project).
4. **Project Settings → API**: copy the Project URL and the `anon public` key into `config.js`, commit, redeploy.
5. Open the app → **Create account** with your email and a password. On your other devices, just **Sign in** with the same account.

How it works and what it means for privacy:
- Your journal is still encrypted **on your device** with a key derived from your password before anything is uploaded. The `vaults` table only ever holds ciphertext — anyone looking at the database sees unreadable base64, and row-level security means only your logged-in account can even fetch that.
- Sync is last-write-wins: whichever device saved most recently is the version you get on next sign-in. The topbar shows "synced ✓" after each save, or "offline · saved on this device" if you're without internet (it lands in the cloud next time you save online).
- The password does double duty (Supabase account + vault encryption), so changing it in Settings updates both. If you reset your Supabase password outside the app, the vault still needs the old password to decrypt — keep exports as your safety net.
- Backups work exactly the same in cloud mode, and the 14-day reminder still applies. Cloud sync protects you from device loss; backups protect you from everything else.

## Customizing

- **Areas & categories**: Settings tab — rename any of the 12 areas, edit up to 5 categories each (one per line). Defaults follow the 12-life-areas wheel: Health, Appearance, Love, Family, Friends, Career, Money, Self-Growth, Spirituality, Recreation, Environment, Community.
- **Scoring scale**: 1–10 satisfaction. Guidance shown in-app: 1–2 neglected · 3–4 struggling · 5–6 okay but flat · 7–8 good, steady · 9–10 thriving.
- **Colors**: change `--score-lo` / `--score-hi` (and the rest of the palette) at the top of `styles.css`.

## Run locally

Just open `index.html` in a browser — no build step, no dependencies.

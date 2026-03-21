Bank Management System

A fully functional bank management system with thorough password security built with Flask and PostgreSQL, deployed on Vercel with Supabase as the database.

Live: [bank-management-system-seven-sand.vercel.app](https://bank-management-system-seven-sand.vercel.app/login)


What it does:
Register and log in to a personal account
Deposit and withdraw money
View full transaction history
Dashboard with recent activity and balance


The USP: Password Security
Passwords are hashed using bcrypt with auto-generated salts. When a user registers, their password is never stored. Instead, bcrypt generates a random salt, combines it with the password, and runs it through a cost factor (14 rounds here) to produce a hash. The salt is stored inside the hash itself.
Why this matters —> rainbow table attacks are a common way to crack stolen password databases. A rainbow table is a precomputed list of hashes for common passwords. Salting defeats this completely because even if two users have the same password, their hashes will be different. There is no precomputed table that can account for a unique random salt per user.
On top of this, the system uses automatic hash upgrades i.e if an older account was hashed with fewer rounds, the hash is silently upgraded to the current standard on next successful login. Login attempts are also rate-limited with a lockout after 3 failed tries. If a user gets locked out, there is a cooldown period of 5 minutes after which they can attempt to login again.


Tech stack:
Backend -> Flask, Python

Database -> PostgreSQL via Supabase

Frontend -> Tailwind CSS, Space Grotesk and Inter via Google Fonts, Material Symbols icons [Google Stitch + Claude used for Frontend generation]

Deployment -> Vercel 


The Journey:
The project started with SQLite3 as the database. It worked perfectly locally. The plan was to deploy on Render using a mounted disk. However, disks are paid, and since this is a hobby project it didn't make sense to do so.
So I tried switching to Vercel. However, Vercel is a serverless environment i.e there is no persistent filesystem. This means that anything SQLite writes would keep vanishing every time a new function is called. 
Therefore, the switch was made to PostgreSQL and we stored it on Supabase as there's a generous free tier and it's easy to setup. I ensured that only the SQL setup was changed and all the other functionalities remained intact.


Deployment on Vercel took longer than it should have because I wasn't aware that Supabase's direct connection is IPv6 only whereas Vercel runs on IPv4. This led to me trying to configure various other things until i found out that the main issue was in fact this.
The fix was switching from the direct connection string to Supabase's session pooler with the IPv4 shared pooler option enabled.
The second issue was the connection URL encoding. I was getting a "could not translate host name" error for a while and upon further inspection, the reason turned out to be a password containing a special character (@). When pasted raw into a connection URL, the @ in the password is interpreted as the delimiter between credentials and hostname, corrupting the URL. 
The fix was URL encoding the password (@ becomes %40) before putting it in the DATABASE_URL environment variable.


Project structure

├── app.py               # All routes and business logic
├── api/
│   └── index.py         # Vercel entry point
├── templates/
│   ├── base.html        # Layout, nav, styling
│   ├── dashboard.html
│   ├── login.html
│   ├── deposit.html
│   ├── withdraw.html
│   └── history.html
├── requirements.txt
└── vercel.json
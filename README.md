# Nagrik Setu — Road Grievance Portal

## Run locally
    npm install
    npm start            # http://localhost:3000
The first start prints a one-time admin login (or set ADMIN_EMAIL / ADMIN_PASSWORD). Officer console: `/#/officer`.
Demo mode: Aadhaar accepts any checksum-valid number and OTP `123456`. Never use demo mode with real data.

## Deploy with Docker
    docker build -t nagrik-setu .
    docker run -d -p 3000:3000 -v nagrik-data:/data --env-file .env nagrik-setu
Put it behind an HTTPS reverse proxy (Nginx/Caddy/cloud load balancer). HTTPS is required: the browser encrypts the Aadhaar number with WebCrypto, which only works on HTTPS or localhost. Back up the `/data` volume, including `secrets.json`; without it, encrypted data cannot be read.

## Go-live checklist
1. Obtain UIDAI AUA/KUA access (or integrate DigiLocker) and set `AADHAAR_PROVIDER_URL`; keep `ALLOW_MOCK_AADHAAR` unset.
2. Move keys to a KMS (`DATA_KEY`, `JWT_SECRET`, `PEPPER` env vars) and host in an India region, preferably a MeitY-empanelled cloud.
3. Connect an AI detection service (`AI_DETECT_URL`); the bundled detector is heuristic only.
4. Move SQLite to PostgreSQL and files to encrypted object storage for multi-instance scale (see docs/TECH_SPEC.md).
5. Complete a security audit (CERT-In empanelled auditor / STQC), DPDP review, and add your privacy notice and grievance officer details.

# Nagrik Setu — Technical Specification & Roadmap
Secure road-grievance redressal portal for Indian citizens. Version 1.0

## 1. System architecture
```
 Citizen browser                                   Officer browser
 (SPA, WebCrypto RSA-OAEP for Aadhaar)             (SPA, Verification desk)
        │  HTTPS/TLS1.3 + HSTS                            │
        └───────────────┬─────────────────────────────────┘
                 WAF / Reverse proxy (rate limit, CSP, mTLS to origin)
                        │
        ┌───────────────▼────────────────┐
        │  API (Node/Express)            │  auth: JWT in httpOnly+SameSite=Strict cookie
        │  • Citizen API  /api/*         │  CSRF: custom header + SameSite
        │  • Officer API  /api/admin/*   │  RBAC: citizen | officer | superadmin
        │  • Crypto service (AES-GCM)    │
        │  • Aadhaar adapter ────────────┼──► UIDAI AUA/KUA (OTP e-KYC) / DigiLocker
        │  • AI-image adapter ───────────┼──► Detection service (C2PA + ML model)
        └───────┬──────────────┬─────────┘
          SQLite→PostgreSQL   Encrypted object store (files: AES-256-GCM envelope)
          (field-encrypted)   Keys: KMS/HSM in production
```
**Citizen portal:** register with DPDP consent → Aadhaar OTP verification → create / view / edit / withdraw reports (images + PDFs, optional text) → track timeline → erase account.
**Officer portal:** queue by status and AI risk → review evidence → verify / keep flagged / reject (reason mandatory) → send for repair → upload repair proof → close → (superadmin) delete reports and manage officers.

## 2. Database schema
| Table | Key columns |
|---|---|
| **users** | id, email_idx (HMAC, lookup), email_enc, name_enc, phone_enc, pw_hash (bcrypt-12), aadhaar_ref (HMAC), aadhaar_last4, aadhaar_verified, consent_at, deleted_at |
| **admins** | id, email, name, pw_hash, role (officer / superadmin) |
| **complaints** | id, user_id→users, title, description_enc (optional), location_text, lat, lng, status, ai_risk, created_at, updated_at, deleted_at |
| **verification_status** | complaint_id (PK), state (pending/flagged/verified/rejected), reviewer_id→admins, note, reviewed_at |
| **complaint_files** | id, complaint_id, kind (evidence/repair), name, mime (sniffed from magic bytes), path (encrypted blob), sha256, ai_score, ai_notes |
| **events** | id, complaint_id, actor, action, note, ts — append-only audit trail |
| **aadhaar_txn** | id, user_id, ref, last4, expires, tries — short-lived OTP transaction |

Status machine: `submitted → pending_review | flagged → verified | rejected → in_repair → repair_submitted → closed` (`withdrawn` by citizen before review).

## 3. Security protocol
**Encryption model (honest scope).** Officers must read reports, so pure end-to-end encryption between citizens only is not possible. The design uses:
1. **Client-side hybrid encryption for the most sensitive field (Aadhaar number):** encrypted in the browser with the server's RSA-3072 OAEP public key; only the verification service can decrypt, in memory, for one OTP check. It is never written to disk or logs.
2. **Field-level and file-level AES-256-GCM** (random 96-bit IV, auth tag) for name, phone, email, description and all uploads — encrypted before they reach the database or disk.
3. **In transit:** TLS 1.3, HSTS, strict CSP, no third-party scripts.
4. **Keys:** in production hold the data key and RSA private key in a KMS/HSM (e.g. MeitY-empanelled cloud KMS); use envelope encryption with per-record data keys and yearly rotation. The demo auto-generates keys into `data/secrets.json` (mode 0600).
5. Blind indexes (HMAC with pepper) for email and Aadhaar-uniqueness lookups.

**Aadhaar verification flow (compliance-first).**
Browser encrypts number → `/aadhaar/start` → server validates Verhoeff checksum, calls the licensed AUA/KUA OTP API → user enters OTP → `/aadhaar/verify` → provider returns yes/no → store **only** HMAC reference + last 4 digits + verified flag. Legal basis: Aadhaar Act 2016 and UIDAI regulations require an Aadhaar-authentication licence (AUA/KUA, or a sub-AUA through a licensed entity); storing the full number is prohibited without it. Alternative with lower compliance burden: **DigiLocker / Meri Pehchaan (NIC)** consented identity.

**Application hardening:** bcrypt cost 12, 8-hour sessions, rate limiting (global and strict on auth/Aadhaar), CSRF header check, helmet headers, magic-byte file validation, 10 MB × 6-file limit, decrypt-on-read file streaming only to the owner or officers, `nosniff`, no-store caching, soft deletes, immutable audit events. Add for production: MFA for officers, IP allow-listing, ClamAV scanning, WAF, centralised logging with PII scrubbing.

**Indian legal requirements.**
- **DPDP Act 2023 and its Rules:** notice and consent at collection, purpose limitation, data minimisation, accuracy, storage limitation, breach notification to the Data Protection Board and affected users, right to access / correction / erasure (implemented: account erasure), grievance officer contact. Government entities may qualify for State exemptions only as the Act specifies — obtain legal sign-off.
- **IT Act 2000 (s.43A, 72A) and SPDI Rules 2011** where still applicable; **CERT-In Directions 2022:** report incidents within 6 hours, retain logs 180 days, sync clocks to NTP (NIC/NPL).
- **MeitY guidelines:** host on a MeitY-empanelled cloud in India (data localisation), STQC / CERT-In-empanelled security audit before go-live, **GIGW 3.0** and WCAG 2.1 AA accessibility, bilingual (Hindi/English + regional) UI.
- Retention: complaint records per the department's records schedule; erased users' reports are anonymised.

## 4. Feature workflows
**A. Complaint submission.** Auth + `aadhaar_verified` check → validate title/location (description optional) → require ≥1 evidence file → sniff each file's real type (JPG/PNG/WebP/PDF) → SHA-256 → AI scan → duplicate-hash check → encrypt and store → create `complaints` + `verification_status` → status `pending_review`, or `flagged` if risk ≥ 0.70 → audit events.
**B. Admin verification.** Queue sorted by AI risk. Officer sees evidence with per-file AI score and reasons, masked citizen identity (last 4 only). Decision: *Verify* → `verified`; *Keep flagged*; *Reject* (reason mandatory, shown to citizen). AI never auto-rejects; a human always decides. Citizens do not see AI scores, to prevent evasion.
**C. Resolution loop.** `verified` → *Send for repair* (`in_repair`) → field team uploads repair photos/PDF (+note) → `repair_submitted` → closing officer confirms → `closed`. The server refuses to close without at least one repair file. The full timeline is visible to the citizen.
**CRUD:** Citizen — create, read, update (until reviewed), delete/withdraw (until reviewed), erase account. Officer — read, review, transition, upload proof, close; superadmin — delete reports, create/remove officers.

**AI-image detection layers.** (1) Provenance: C2PA / generator markers in metadata. (2) Forensics: missing camera EXIF, re-encoding traces, ELA, GPS vs reported location mismatch. (3) ML classifier via `AI_DETECT_URL` (e.g. a self-hosted ViT/CLIP-based detector or a commercial API such as Hive/Reality Defender — evaluate on Indian road imagery). (4) Perceptual + SHA-256 duplicate detection. (5) Human review. The bundled adapter implements (1), (2 partial) and (4); plug your model in for (3). No detector is 100% accurate — keep the human step.

## 5. Tech stack
| Concern | Demo build | Production recommendation |
|---|---|---|
| Backend | Node 20 + Express | NestJS / Spring Boot, behind NIC/cloud WAF |
| Frontend | Static SPA | React/Next.js with i18n, GIGW 3.0 audit |
| DB | SQLite (WAL) | PostgreSQL 16 with pgcrypto, PostGIS for geo-queries, TDE, PITR backups |
| Files | Encrypted local blobs | S3-compatible store (MeitY-empanelled) with SSE-KMS + client-side envelope |
| Keys | Local file | KMS/HSM, rotation, split duties |
| Auth | bcrypt + JWT cookie | Keycloak/OIDC, MFA for officers, optional DigiLocker/Meri Pehchaan |
| AI image | Heuristics + adapter | Python FastAPI microservice: C2PA verify, ViT/CLIP detector, imagehash; queue via Celery/Redis |
| Ops | Docker | Kubernetes, Prometheus/Grafana, SIEM, SAST/DAST in CI, STQC audit |

## 6. Roadmap
| Phase | Weeks | Deliverables |
|---|---|---|
| 0 Discovery & legal | 1–3 | DPIA, AUA/KUA licence path or DigiLocker onboarding, data-retention schedule, hosting choice |
| 1 Core MVP (this build) | 4–7 | Auth, Aadhaar adapter, CRUD, encrypted storage, officer desk, audit trail |
| 2 Hardening | 8–11 | PostgreSQL, KMS, MFA, ClamAV, WAF, rate/abuse controls, load tests |
| 3 AI & geo | 12–15 | ML detector service, EXIF-GPS match, map view, duplicate-area clustering |
| 4 Compliance & audit | 16–18 | STQC / CERT-In audit, VAPT fixes, GIGW/WCAG, Hindi + regional languages |
| 5 Pilot & scale | 19–24 | One-district pilot, SMS/WhatsApp notifications (DLT-registered), SLA dashboards, state rollout |

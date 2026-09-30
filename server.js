Const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const mysql = require('mysql2/promise');

const app = express();
app.set('trust proxy', 1); // Render HTTPS & Real IP support ke liye zaroori
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"]
  }
});

// =================================================================
// 1. RENDER ENVIRONMENT VARIABLES & OFFICIAL BRANDING
// =================================================================
const JWT_SECRET = process.env.JWT_SECRET || 'd4k_fallback_secret_key_2026';
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const SENDER_EMAIL = process.env.SENDER_EMAIL || 'd.4k.studio.private.limited@gmail.com';
const TIDB_URL = process.env.TIDB_URL;
const DEFAULT_GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';

// Official Platform Branding Details (Included in every email footer & Console OTP)
const PLATFORM_BRAND = {
  developerName: "Danish Raja Ji",
  companyName: "D 4K Studio Private Limited",
  officialEmail: "d.4k.studio.private.limited@gmail.com",
  location: "Naya Basti, Bokaro Thermal, Jharkhand, India",
  website: "https://mr4k09.000.pe/?i=1",
  phone: "+91 9430320021"
};

// =================================================================
// 2. TiDB CLOUD (MySQL) CONNECTION & AUTO-TABLE SETUP
// =================================================================
const pool = mysql.createPool({
  uri: TIDB_URL,
  ssl: {
    minVersion: 'TLSv1.2',
    rejectUnauthorized: true
  },
  waitForConnections: true,
  connectionLimit: 10,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000
});

async function initDatabase() {
  try {
    // 1. Projects Table (With Real-Time Settings, Expiry, Providers & Google Client ID)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS projects (
        project_id VARCHAR(64) PRIMARY KEY,
        api_key VARCHAR(128) NOT NULL,
        project_name VARCHAR(100) NOT NULL,
        developer_name VARCHAR(100) DEFAULT 'Developer',
        admin_email VARCHAR(150) UNIQUE NOT NULL,
        admin_password VARCHAR(255) NOT NULL,
        expires_at VARCHAR(64) DEFAULT NULL,
        enabled_providers TEXT DEFAULT NULL,
        authorized_domains TEXT DEFAULT NULL,
        google_client_id VARCHAR(255) DEFAULT NULL,
        realtime_db_active TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 2. End-Users Table (Strictly Isolated per project_id)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS end_users (
        user_id VARCHAR(64) PRIMARY KEY,
        project_id VARCHAR(64) NOT NULL,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(150) NOT NULL,
        password VARCHAR(255) NOT NULL,
        auth_provider VARCHAR(30) DEFAULT 'email',
        status VARCHAR(20) DEFAULT 'active',
        last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_project_user (project_id, email),
        INDEX idx_project (project_id)
      )
    `);

    // 3. Real-Time Project Chats Table (Cloud Stored & Isolated per project_id)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS project_chats (
        chat_id VARCHAR(64) PRIMARY KEY,
        project_id VARCHAR(64) NOT NULL,
        room_id VARCHAR(100) DEFAULT 'global',
        sender_id VARCHAR(64) NOT NULL,
        sender_name VARCHAR(100) NOT NULL,
        sender_email VARCHAR(150) DEFAULT '',
        receiver_id VARCHAR(64) DEFAULT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_chat_project (project_id),
        INDEX idx_chat_room (project_id, room_id)
      )
    `);

    // 4. Cloud Customer Support Messages Table (Synced across User, Console & Admin Panel)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS support_messages (
        msg_id VARCHAR(64) PRIMARY KEY,
        project_id VARCHAR(64) DEFAULT 'global',
        sender_role VARCHAR(20) NOT NULL,
        sender_name VARCHAR(100) NOT NULL,
        text TEXT NOT NULL,
        time_label VARCHAR(40) DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_sup_project (project_id)
      )
    `);

    // Safe migrations for existing tables
    await pool.query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS developer_name VARCHAR(100) DEFAULT 'Developer'`).catch(() => {});
    await pool.query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS expires_at VARCHAR(64) DEFAULT NULL`).catch(() => {});
    await pool.query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS enabled_providers TEXT DEFAULT NULL`).catch(() => {});
    await pool.query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS authorized_domains TEXT DEFAULT NULL`).catch(() => {});
    await pool.query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS google_client_id VARCHAR(255) DEFAULT NULL`).catch(() => {});
    await pool.query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS realtime_db_active TINYINT(1) DEFAULT 0`).catch(() => {});

    await pool.query(`ALTER TABLE end_users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(30) DEFAULT 'email'`).catch(() => {});
    await pool.query(`ALTER TABLE end_users ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active'`).catch(() => {});
    await pool.query(`ALTER TABLE end_users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP`).catch(() => {});

    console.log("TiDB Cloud Database Connected & All Multi-Tenant Tables Ready!");
  } catch (err) {
    console.error("Database Connection Error:", err.message);
  }
}
initDatabase();

// Helper to parse JSON columns safely
function safeParseJSON(str, fallback) {
  if (!str) return fallback;
  try { return JSON.parse(str); } catch (e) { return fallback; }
}

// Helper to format project config for Console & SDK
function formatProjectConfig(row) {
  const defaultProviders = {
    email_otp: true,
    passwordless_otp: true,
    magic_link: true,
    google: true,
    forgot_pass: true
  };
  const defaultDomains = ["localhost", "d4k-auth-server.onrender.com"];
  return {
    projectId: row.project_id,
    apiKey: row.api_key,
    projectName: row.project_name,
    developerName: row.developer_name || "Developer",
    adminEmail: row.admin_email,
    expiresAt: row.expires_at || null,
    enabledProviders: safeParseJSON(row.enabled_providers, defaultProviders),
    authorizedDomains: safeParseJSON(row.authorized_domains, defaultDomains),
    googleClientId: row.google_client_id || DEFAULT_GOOGLE_CLIENT_ID || "",
    realtimeDbActive: Boolean(row.realtime_db_active)
  };
}

// Helper to validate Project Expiry & Provider Status on every Auth Request
async function verifyProjectActiveAndProvider(projectId, apiKey, requiredProviderKey = null) {
  const query = apiKey
    ? 'SELECT * FROM projects WHERE project_id = ? AND api_key = ?'
    : 'SELECT * FROM projects WHERE project_id = ?';
  const params = apiKey ? [projectId, apiKey] : [projectId];

  const [rows] = await pool.query(query, params);
  if (rows.length === 0) {
    return { valid: false, status: 401, error: "Invalid projectId or apiKey." };
  }

  const project = formatProjectConfig(rows[0]);

  // 1. Check Server-Side Expiry Rule
  if (project.expiresAt) {
    const expTime = new Date(project.expiresAt).getTime();
    if (!isNaN(expTime) && Date.now() > expTime) {
      return {
        valid: false,
        status: 403,
        error: `SDK API Key expired on ${new Date(project.expiresAt).toDateString()}. Please renew in 4k Studio Console.`
      };
    }
  }

  // 2. Check if Sign-in Provider is Enabled in Console
  if (requiredProviderKey && project.enabledProviders && project.enabledProviders[requiredProviderKey] === false) {
    return {
      valid: false,
      status: 403,
      error: `This sign-in method (${requiredProviderKey}) is currently disabled by the project administrator.`
    };
  }

  return { valid: true, project };
}

// Helper to broadcast live updates to the Developer Console room
function notifyConsoleRealtime(projectId, eventType, payload = {}) {
  io.to(`console_${projectId}`).emit('console-realtime-sync', {
    eventType,
    projectId,
    timestamp: new Date().toISOString(),
    ...payload
  });
}

// Server Live Health Check Route
app.get('/', (req, res) => {
  res.json({
    status: "LIVE",
    service: "Multi-Tenant Auth, OTP, Realtime DB & WebRTC Signaling Server",
    poweredBy: PLATFORM_BRAND.companyName,
    leadDeveloper: PLATFORM_BRAND.developerName,
    senderEmail: SENDER_EMAIL
  });
});

// In-Memory Stores for Pending OTPs, Magic Links & Smart Rate Limiting
const pendingConsoleProjects = new Map();
const pendingRegistrations = new Map();
const otpLoginAndResetMap = new Map();
const magicLinkMap = new Map();
const brevoRateLimitMap = new Map();
let supportAgentStatus = { online: false, agentName: "Support Agent" };

// Fast Auto-cleanup of expired records every 6 seconds
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pendingConsoleProjects.entries()) if (now > v.expiresAt) pendingConsoleProjects.delete(k);
  for (const [k, v] of pendingRegistrations.entries()) if (now > v.expiresAt) pendingRegistrations.delete(k);
  for (const [k, v] of otpLoginAndResetMap.entries()) if (now > v.expiresAt) otpLoginAndResetMap.delete(k);
  for (const [k, v] of magicLinkMap.entries()) if (now > v.expiresAt) magicLinkMap.delete(k);
  for (const [k, v] of brevoRateLimitMap.entries()) if (now > v.resetWindow) brevoRateLimitMap.delete(k);
}, 6 * 1000);


// =================================================================
// 3. SMART OTP TIMER & BREVO ANTI-BAN SHIELD
// (1st = Instant | 2nd = after 10s | 3rd = after 12s | 4th = 15m Lock)
// =================================================================
function checkBrevoProtection(req, email) {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
  const now = Date.now();

  const emailKey = `email_${email}`;
  const ipKey = `ip_${ip}`;

  const SECOND_TRY_GAP_MS = 10 * 1000;    // 10 seconds wait before 2nd OTP
  const THIRD_TRY_GAP_MS = 12 * 1000;     // 12 seconds wait before 3rd OTP
  const BIG_TIMER_MS = 15 * 60 * 1000;    // 15 minutes (900s) lock on 4th request

  let emailRecord = brevoRateLimitMap.get(emailKey) || {
    count: 0,
    lastSent: 0,
    lockedUntil: 0,
    resetWindow: now + BIG_TIMER_MS
  };

  let ipRecord = brevoRateLimitMap.get(ipKey) || {
    count: 0,
    lockedUntil: 0,
    resetWindow: now + BIG_TIMER_MS
  };

  if (now > emailRecord.resetWindow && now > emailRecord.lockedUntil) {
    emailRecord = { count: 0, lastSent: 0, lockedUntil: 0, resetWindow: now + BIG_TIMER_MS };
  }
  if (now > ipRecord.resetWindow && now > ipRecord.lockedUntil) {
    ipRecord = { count: 0, lockedUntil: 0, resetWindow: now + BIG_TIMER_MS };
  }

  // 1. Check if Big Timer (15 min lock) is active for this Email
  if (now < emailRecord.lockedUntil) {
    const waitSec = Math.ceil((emailRecord.lockedUntil - now) / 1000);
    return {
      allowed: false,
      retryAfterSeconds: waitSec,
      error: `Too many OTP requests. Please wait ${waitSec} seconds before trying again.`
    };
  }

  // 2. Check if IP is locked due to heavy spam
  if (now < ipRecord.lockedUntil) {
    const waitSec = Math.ceil((ipRecord.lockedUntil - now) / 1000);
    return {
      allowed: false,
      retryAfterSeconds: waitSec,
      error: `Network rate limit exceeded. Please wait ${waitSec} seconds.`
    };
  }

  // 3. Step-by-step custom gap: 2nd try = 10s gap, 3rd try = 12s gap
  if (emailRecord.count === 1) {
    const elapsed = now - emailRecord.lastSent;
    if (elapsed < SECOND_TRY_GAP_MS) {
      const waitSec = Math.ceil((SECOND_TRY_GAP_MS - elapsed) / 1000);
      return {
        allowed: false,
        retryAfterSeconds: waitSec,
        error: `Please wait ${waitSec} seconds before requesting the 2nd OTP.`
      };
    }
  } else if (emailRecord.count === 2) {
    const elapsed = now - emailRecord.lastSent;
    if (elapsed < THIRD_TRY_GAP_MS) {
      const waitSec = Math.ceil((THIRD_TRY_GAP_MS - elapsed) / 1000);
      return {
        allowed: false,
        retryAfterSeconds: waitSec,
        error: `Please wait ${waitSec} seconds before requesting the 3rd OTP.`
      };
    }
  }

  // 4. Trigger Big Timer (15 minutes) on 4th request
  if (emailRecord.count >= 3) {
    emailRecord.lockedUntil = now + BIG_TIMER_MS;
    emailRecord.resetWindow = now + BIG_TIMER_MS;
    brevoRateLimitMap.set(emailKey, emailRecord);
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil(BIG_TIMER_MS / 1000),
      error: `Maximum 3 OTP attempts reached. Please wait 15 minutes (900 seconds).`
    };
  }

  // 5. IP limit check (Max 10 requests per 15 mins per IP)
  if (ipRecord.count >= 10) {
    ipRecord.lockedUntil = now + BIG_TIMER_MS;
    brevoRateLimitMap.set(ipKey, ipRecord);
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil(BIG_TIMER_MS / 1000),
      error: `Too many requests from this IP. Locked for 15 minutes.`
    };
  }

  emailRecord.count += 1;
  emailRecord.lastSent = now;
  ipRecord.count += 1;

  brevoRateLimitMap.set(emailKey, emailRecord);
  brevoRateLimitMap.set(ipKey, ipRecord);

  let nextWaitSeconds = 10;
  if (emailRecord.count === 1) nextWaitSeconds = 10;
  else if (emailRecord.count === 2) nextWaitSeconds = 12;
  else nextWaitSeconds = 900;

  return { allowed: true, attemptNumber: emailRecord.count, nextWaitSeconds };
}


// =================================================================
// 4. ROYAL CLASS PREMIUM EMAIL SENDER WITH D 4K STUDIO FOOTER
// =================================================================
async function sendDynamicBrevoEmail({ senderName, toEmail, toName, otp, magicLinkUrl, purposeText, extraNote }) {
  const preheaderText = magicLinkUrl
    ? `Instant 1-Click Login Link for ${senderName} • Valid for 10 mins • Secured by ${PLATFORM_BRAND.companyName}`
    : `One-Time Passcode: ${otp} for ${senderName} • Tap code to copy • Secured by ${PLATFORM_BRAND.companyName}`;

  const actionBlockHtml = magicLinkUrl
    ? `
      <div style="background: linear-gradient(180deg, #f8fafc 0%, #eff6ff 100%); border: 1px solid #bfdbfe; border-radius: 14px; padding: 24px 16px; text-align: center; margin: 24px 0;">
        <div style="font-size: 11px; font-weight: 700; color: #64748b; letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 14px;">
          Instant 1-Click Authentication
        </div>
        <a href="${magicLinkUrl}" style="background: linear-gradient(135deg, #0f172a, #1e3a8a); color: #fbbf24; border: 1px solid #f59e0b; text-decoration: none; padding: 14px 28px; border-radius: 10px; font-size: 16px; font-weight: 800; display: inline-block; box-shadow: 0 6px 16px rgba(15, 23, 42, 0.2);">
          Login Instantly to ${senderName}
        </a>
        <p style="font-size: 12px; color: #64748b; margin-top: 14px; word-break: break-all; margin-bottom: 0;">
          Or copy and paste this link in your browser:<br/>
          <a href="${magicLinkUrl}" style="color: #2563eb;">${magicLinkUrl}</a>
        </p>
      </div>
    `
    : `
      <!-- VIP OTP Vault Box with 1-Tap Full Selection -->
      <div style="background: linear-gradient(180deg, #f8fafc 0%, #eff6ff 100%); border: 1px solid #bfdbfe; border-radius: 14px; padding: 22px 16px; text-align: center; margin: 24px 0; box-shadow: inset 0 2px 6px rgba(37, 99, 235, 0.06);">
        <div style="font-size: 11px; font-weight: 700; color: #64748b; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 10px;">
          One-Time Security Passcode (Tap Code to Copy)
        </div>
        <div title="Tap to select OTP" style="display: inline-block; background: #0f172a; color: #fbbf24; font-size: 32px; font-weight: 800; letter-spacing: 10px; padding: 12px 24px 12px 34px; border-radius: 10px; border: 1px solid #334155; box-shadow: 0 6px 16px rgba(15, 23, 42, 0.2); user-select: all; -webkit-user-select: all; -moz-user-select: all; cursor: pointer;">${otp}</div>
        <div style="font-size: 12px; color: #1e40af; font-weight: 600; margin-top: 12px;">
          &#9201; Valid for 10 Minutes &bull; Single-Use Only
        </div>
      </div>
    `;

  const emailHtml = `
    <div style="display: none; max-height: 0px; overflow: hidden; opacity: 0; font-size: 1px; line-height: 1px; color: #ffffff;">
      ${preheaderText}
    </div>

    <div style="max-width: 560px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 12px 30px rgba(0,0,0,0.12); border: 1px solid #e2e8f0; font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
      
      <!-- Top Luxury Gold-Blue Crown Bar -->
      <div style="height: 5px; background: linear-gradient(90deg, #f59e0b, #3b82f6, #1d4ed8, #f59e0b);"></div>

      <!-- Executive Royal Header (Dynamic Project Sender Name) -->
      <div style="background: linear-gradient(135deg, #090d16 0%, #0f172a 55%, #1e3a8a 100%); padding: 28px 24px; text-align: center;">
        <div style="display: inline-block; background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.4); color: #fbbf24; font-size: 11px; font-weight: 700; letter-spacing: 1.5px; padding: 5px 14px; border-radius: 50px; text-transform: uppercase; margin-bottom: 12px;">
          &#10003; Official Verified Security
        </div>
        <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 800; letter-spacing: 0.5px;">
          ${senderName}
        </h1>
        <p style="color: #93c5fd; margin: 6px 0 0 0; font-size: 13px; letter-spacing: 0.3px;">
          Secure Identity &amp; Cloud Verification Service
        </p>
      </div>

      <!-- Main White Luxury Body -->
      <div style="padding: 30px 24px; color: #1e293b; background-color: #ffffff;">
        <p style="font-size: 16px; margin: 0 0 10px 0; color: #0f172a;">
          Hello <strong style="color: #1d4ed8;">${toName || 'User'}</strong>,
        </p>
        <p style="font-size: 14px; color: #475569; line-height: 1.6; margin: 0 0 18px 0;">
          A secure verification request was initiated for your account on <strong>${senderName}</strong>. Please use the confidential verification details below to complete your <strong>${purposeText}</strong>:
        </p>

        ${extraNote ? `<p style="font-size: 13px; color: #1e40af; background: #eff6ff; padding: 12px 14px; border-radius: 8px; border: 1px solid #bfdbfe; margin-bottom: 18px;">${extraNote}</p>` : ''}

        ${actionBlockHtml}

        <!-- Security Metadata Summary -->
        <div style="background-color: #f8fafc; border-left: 4px solid #2563eb; border-radius: 8px; padding: 14px 16px; margin-bottom: 20px; font-size: 12.5px; color: #334155; line-height: 1.8;">
          <div><strong>&bull; Service / Application:</strong> ${senderName}</div>
          <div><strong>&bull; Action Requested:</strong> ${purposeText}</div>
          <div><strong>&bull; Security Standard:</strong> 256-Bit SSL &amp; TiDB Cloud Encrypted</div>
        </div>

        <p style="font-size: 12.5px; color: #64748b; line-height: 1.5; margin: 0;">
          &#128274; <strong>Security Notice:</strong> This verification is valid for <strong>10 minutes</strong>. Never share this code or link with anyone.
        </p>
      </div>

      <!-- Official D 4K Studio Private Limited Executive Corporate Footer -->
      <div style="background: linear-gradient(180deg, #0f172a 0%, #090d16 100%); color: #cbd5e1; padding: 26px 24px; border-top: 3px solid #f59e0b; font-size: 12.5px; line-height: 1.7;">
        
        <div style="display: inline-block; background: rgba(56, 189, 248, 0.12); color: #38bdf8; font-size: 11px; font-weight: 800; padding: 4px 10px; border-radius: 6px; letter-spacing: 0.8px; text-transform: uppercase; margin-bottom: 10px;">
          &#9889; Powered &amp; Secured By ${PLATFORM_BRAND.companyName}
        </div>

        <div style="color: #f8fafc; font-size: 13px; margin-bottom: 4px;">
          <strong>Lead Developer:</strong> ${PLATFORM_BRAND.developerName}
        </div>
        <div style="color: #94a3b8; font-size: 12px; margin-bottom: 16px;">
          <strong>Headquarters:</strong> ${PLATFORM_BRAND.location}
        </div>

        <div style="margin: 16px 0;">
          <a href="${PLATFORM_BRAND.website}" target="_blank" style="display: inline-block; background-color: #2563eb; color: #ffffff; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; font-weight: 700; margin-right: 8px;">
            Official Website
          </a>
          <a href="tel:+919430320021" style="display: inline-block; background-color: #1e293b; color: #fbbf24; border: 1px solid #475569; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; font-weight: 700;">
            ${PLATFORM_BRAND.phone}
          </a>
        </div>

        <div style="margin-top: 16px; padding-top: 12px; border-top: 1px solid #1e293b; color: #64748b; font-size: 11px; text-align: center;">
          &copy; ${new Date().getFullYear()} ${PLATFORM_BRAND.companyName}. All rights reserved.
        </div>
      </div>

    </div>
  `;

  const subjectLine = magicLinkUrl
    ? `🔐 Instant Login Link — ${senderName}`
    : `🔐 [${otp}] Official Verification Code — ${senderName}`;

  await axios.post(
    'https://api.brevo.com/v3/smtp/email',
    {
      sender: {
        name: senderName,
        email: SENDER_EMAIL
      },
      to: [{ email: toEmail, name: toName || 'User' }],
      subject: subjectLine,
      htmlContent: emailHtml
    },
    {
      headers: {
        'accept': 'application/json',
        'api-key': BREVO_API_KEY,
        'content-type': 'application/json'
      },
      timeout: 12000
    }
  );
}


// =================================================================
// PART 1: CONSOLE PANEL APIs (Developer OTP Signup, Login & Real Google OAuth)
// =================================================================

// Step 1: Developer registers on Console -> Sender Name is D 4K Studio Private Limited
app.post('/api/console/register-send-otp', async (req, res) => {
  try {
    const { developerName, projectName, adminEmail, adminPassword } = req.body;
    if (!projectName || !adminEmail || !adminPassword) {
      return res.status(400).json({ error: "projectName, adminEmail, and adminPassword are required." });
    }

    const cleanAdminEmail = adminEmail.toLowerCase().trim();
    const [existing] = await pool.query('SELECT project_id FROM projects WHERE admin_email = ?', [cleanAdminEmail]);
    if (existing.length > 0) {
      return res.status(400).json({ error: "A project is already registered with this admin email. Please login." });
    }

    const guard = checkBrevoProtection(req, cleanAdminEmail);
    if (!guard.allowed) {
      return res.status(429).json({ error: guard.error, retryAfterSeconds: guard.retryAfterSeconds });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    pendingConsoleProjects.set(cleanAdminEmail, {
      developerName: (developerName || "Developer").trim(),
      projectName: projectName.trim(),
      adminEmail: cleanAdminEmail,
      adminPassword: hashedPassword,
      otp,
      wrongAttempts: 0,
      expiresAt: Date.now() + 10 * 60 * 1000
    });

    await sendDynamicBrevoEmail({
      senderName: PLATFORM_BRAND.companyName,
      toEmail: cleanAdminEmail,
      toName: (developerName || projectName).trim(),
      otp,
      purposeText: `Developer Console Registration for "${projectName.trim()}"`,
      extraNote: `Once verified, your project "${projectName.trim()}" will be activated as your custom Automatic Email Sender Name for all your app users.`
    });

    res.json({
      message: `Verification OTP sent from ${PLATFORM_BRAND.companyName} to ${cleanAdminEmail}.`,
      attemptNumber: guard.attemptNumber,
      nextWaitSeconds: guard.nextWaitSeconds
    });
  } catch (err) {
    const detailMsg = err.response && err.response.data ? JSON.stringify(err.response.data) : err.message;
    console.error("Console OTP Error:", detailMsg);
    res.status(500).json({ error: "Failed to send verification OTP. Check Brevo API Key & Sender Email.", details: detailMsg });
  }
});

// Step 2: Verify Developer OTP -> Save Project in TiDB & Generate projectId + apiKey Config
app.post('/api/console/verify-project-otp', async (req, res) => {
  try {
    const { adminEmail, otp } = req.body;
    if (!adminEmail || !otp) {
      return res.status(400).json({ error: "adminEmail and otp are required." });
    }

    const cleanAdminEmail = adminEmail.toLowerCase().trim();
    const pendingProject = pendingConsoleProjects.get(cleanAdminEmail);

    if (!pendingProject) {
      return res.status(400).json({ error: "No pending project registration found. Please request a new OTP." });
    }
    if (Date.now() > pendingProject.expiresAt) {
      pendingConsoleProjects.delete(cleanAdminEmail);
      return res.status(400).json({ error: "OTP has expired. Please register again." });
    }
    if (pendingProject.otp !== otp.toString().trim()) {
      pendingProject.wrongAttempts = (pendingProject.wrongAttempts || 0) + 1;
      if (pendingProject.wrongAttempts >= 3) {
        pendingConsoleProjects.delete(cleanAdminEmail);
        return res.status(400).json({ error: "3 wrong OTP attempts! Security lock triggered. Please request a new OTP." });
      }
      return res.status(400).json({ error: `Invalid OTP code. (${3 - pendingProject.wrongAttempts} attempts left)` });
    }

    const projectId = "proj_" + crypto.randomBytes(6).toString('hex');
    const apiKey = "d4k_" + crypto.randomBytes(16).toString('hex');
    const defaultProviders = JSON.stringify({
      email_otp: true,
      passwordless_otp: true,
      magic_link: true,
      google: true,
      forgot_pass: true
    });
    const defaultDomains = JSON.stringify(["localhost", "d4k-auth-server.onrender.com"]);

    await pool.query(
      `INSERT INTO projects (project_id, api_key, project_name, developer_name, admin_email, admin_password, enabled_providers, authorized_domains, realtime_db_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`,
      [projectId, apiKey, pendingProject.projectName, pendingProject.developerName, cleanAdminEmail, pendingProject.adminPassword, defaultProviders, defaultDomains]
    );

    pendingConsoleProjects.delete(cleanAdminEmail);

    const [rows] = await pool.query('SELECT * FROM projects WHERE project_id = ?', [projectId]);
    const projectConfig = formatProjectConfig(rows[0]);
    const consoleToken = jwt.sign({ projectId, adminEmail: cleanAdminEmail }, JWT_SECRET, { expiresIn: '3650d' });

    res.json({
      message: "Project verified and created successfully! Your automatic Sender Name is now active.",
      consoleToken,
      projectConfig
    });
  } catch (err) {
    res.status(500).json({ error: "Database error while creating project." });
  }
});

// Console Login for Existing Developers
app.post('/api/console/login', async (req, res) => {
  try {
    const { adminEmail, adminPassword } = req.body;
    const [rows] = await pool.query('SELECT * FROM projects WHERE admin_email = ?', [(adminEmail || '').toLowerCase().trim()]);

    if (rows.length === 0) return res.status(400).json({ error: "No project found with this email." });

    const project = rows[0];
    const isMatch = await bcrypt.compare(adminPassword, project.admin_password);
    if (!isMatch) return res.status(400).json({ error: "Invalid password." });

    const consoleToken = jwt.sign({ projectId: project.project_id, adminEmail: project.admin_email }, JWT_SECRET, { expiresIn: '3650d' });

    res.json({
      message: "Console login successful.",
      consoleToken,
      projectConfig: formatProjectConfig(project)
    });
  } catch (err) {
    res.status(500).json({ error: "Console login failed." });
  }
});

// Real Google OAuth Login / Auto-Project Creation for Developer Console (Verifies with Google Servers)
app.post('/api/console/google-oauth', async (req, res) => {
  try {
    const { googleIdToken, googleAccessToken, projectName } = req.body;
    if (!googleIdToken && !googleAccessToken) {
      return res.status(400).json({ error: "Official Google ID Token or Access Token is required." });
    }

    let googleData;
    if (googleIdToken) {
      const gRes = await axios.get(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(googleIdToken)}`);
      googleData = gRes.data;
    } else {
      const gRes = await axios.get(`https://www.googleapis.com/oauth2/v3/userinfo`, {
        headers: { Authorization: `Bearer ${googleAccessToken}` }
      });
      googleData = gRes.data;
    }

    if (!googleData || !googleData.email || String(googleData.email_verified) !== 'true') {
      return res.status(401).json({ error: "Google account could not be verified by Google servers." });
    }

    const cleanAdminEmail = googleData.email.toLowerCase().trim();
    const devName = (googleData.name || cleanAdminEmail.split('@')[0]).trim();

    let [rows] = await pool.query('SELECT * FROM projects WHERE admin_email = ?', [cleanAdminEmail]);

    if (rows.length === 0) {
      const projectId = "proj_" + crypto.randomBytes(6).toString('hex');
      const apiKey = "d4k_" + crypto.randomBytes(16).toString('hex');
      const finalProjName = (projectName || `${devName} App`).trim();
      const randomPass = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 10);
      const defaultProviders = JSON.stringify({
        email_otp: true,
        passwordless_otp: true,
        magic_link: true,
        google: true,
        forgot_pass: true
      });
      const defaultDomains = JSON.stringify(["localhost", "d4k-auth-server.onrender.com"]);

      await pool.query(
        `INSERT INTO projects (project_id, api_key, project_name, developer_name, admin_email, admin_password, enabled_providers, authorized_domains, realtime_db_active)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`,
        [projectId, apiKey, finalProjName, devName, cleanAdminEmail, randomPass, defaultProviders, defaultDomains]
      );
      [rows] = await pool.query('SELECT * FROM projects WHERE project_id = ?', [projectId]);
    }

    const project = rows[0];
    const consoleToken = jwt.sign({ projectId: project.project_id, adminEmail: project.admin_email }, JWT_SECRET, { expiresIn: '3650d' });

    res.json({
      message: "Verified Google Console Login Successful!",
      consoleToken,
      projectConfig: formatProjectConfig(project)
    });
  } catch (err) {
    res.status(401).json({ error: "Official Google token verification failed." });
  }
});


// =================================================================
// PART 2: 100% VERIFIED USER AUTHENTICATION METHODS (Enforces Expiry & Providers)
// =================================================================

// Public Project Config Endpoint for Client SDK Initialization
app.get('/api/auth/project-info', async (req, res) => {
  try {
    const { projectId, apiKey } = req.query;
    const check = await verifyProjectActiveAndProvider(projectId, apiKey, null);
    if (!check.valid) return res.status(check.status).json({ error: check.error });

    const p = check.project;
    res.json({
      projectId: p.projectId,
      projectName: p.projectName,
      expiresAt: p.expiresAt,
      enabledProviders: p.enabledProviders,
      googleClientId: p.googleClientId,
      realtimeDbActive: p.realtimeDbActive
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to load project configuration." });
  }
});

// METHOD 1: Email + Password Signup with Dynamic Project Sender Name
app.post('/api/auth/register-send-otp', async (req, res) => {
  try {
    const { projectId, apiKey, name, email, password } = req.body;
    if (!projectId || !apiKey || !name || !email || !password) {
      return res.status(400).json({ error: "projectId, apiKey, name, email, and password are required." });
    }

    const check = await verifyProjectActiveAndProvider(projectId, apiKey, 'email_otp');
    if (!check.valid) return res.status(check.status).json({ error: check.error });

    const cleanEmail = email.toLowerCase().trim();

    const [userRows] = await pool.query('SELECT user_id FROM end_users WHERE project_id = ? AND email = ?', [projectId, cleanEmail]);
    if (userRows.length > 0) return res.status(400).json({ error: "Email is already registered in this project." });

    const guard = checkBrevoProtection(req, cleanEmail);
    if (!guard.allowed) {
      return res.status(429).json({ error: guard.error, retryAfterSeconds: guard.retryAfterSeconds });
    }

    const senderProjectName = check.project.projectName;
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedPassword = await bcrypt.hash(password, 10);

    pendingRegistrations.set(`${projectId}_${cleanEmail}`, {
      projectId,
      projectName: senderProjectName,
      name: name.trim(),
      email: cleanEmail,
      password: hashedPassword,
      otp,
      wrongAttempts: 0,
      expiresAt: Date.now() + 10 * 60 * 1000
    });

    await sendDynamicBrevoEmail({
      senderName: senderProjectName,
      toEmail: cleanEmail,
      toName: name.trim(),
      otp,
      purposeText: "Account Registration"
    });

    res.json({
      message: `OTP sent to your email from ${senderProjectName}.`,
      attemptNumber: guard.attemptNumber,
      nextWaitSeconds: guard.nextWaitSeconds
    });
  } catch (error) {
    console.error("OTP Error:", error.response ? error.response.data : error.message);
    res.status(500).json({ error: "Failed to send OTP email." });
  }
});

// Verify Signup OTP & Permanently Save User in TiDB
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { projectId, email, otp } = req.body;
    if (!projectId || !email || !otp) return res.status(400).json({ error: "projectId, email, and otp are required." });

    const pendingKey = `${projectId}_${email.toLowerCase().trim()}`;
    const pendingUser = pendingRegistrations.get(pendingKey);

    if (!pendingUser) return res.status(400).json({ error: "No pending registration found. Please request a new OTP." });
    if (Date.now() > pendingUser.expiresAt) {
      pendingRegistrations.delete(pendingKey);
      return res.status(400).json({ error: "OTP has expired." });
    }
    if (pendingUser.otp !== otp.toString().trim()) {
      pendingUser.wrongAttempts = (pendingUser.wrongAttempts || 0) + 1;
      if (pendingUser.wrongAttempts >= 3) {
        pendingRegistrations.delete(pendingKey);
        return res.status(400).json({ error: "3 wrong attempts! OTP cancelled for security. Please request a new OTP." });
      }
      return res.status(400).json({ error: `Invalid OTP code. (${3 - pendingUser.wrongAttempts} attempts left)` });
    }

    const userId = "usr_" + crypto.randomBytes(8).toString('hex');

    await pool.query(
      'INSERT INTO end_users (user_id, project_id, name, email, password, auth_provider, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [userId, pendingUser.projectId, pendingUser.name, pendingUser.email, pendingUser.password, 'email_otp', 'active']
    );

    pendingRegistrations.delete(pendingKey);

    const token = jwt.sign(
      { id: userId, projectId: pendingUser.projectId, projectName: pendingUser.projectName, name: pendingUser.name, email: pendingUser.email },
      JWT_SECRET,
      { expiresIn: '3650d' }
    );

    notifyConsoleRealtime(pendingUser.projectId, 'USER_REGISTERED', { userId, name: pendingUser.name, email: pendingUser.email });

    res.json({
      message: "Account verified and saved successfully.",
      token,
      user: { id: userId, name: pendingUser.name, email: pendingUser.email, projectId: pendingUser.projectId }
    });
  } catch (err) {
    res.status(500).json({ error: "Database error while saving user." });
  }
});

// METHOD 2: Standard Email + Password Login (Only Verified DB Users)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { projectId, apiKey, email, password } = req.body;
    const check = await verifyProjectActiveAndProvider(projectId, apiKey || null, 'email_otp');
    if (!check.valid) return res.status(check.status).json({ error: check.error });

    const [rows] = await pool.query(
      `SELECT u.*, p.project_name FROM end_users u JOIN projects p ON u.project_id = p.project_id WHERE u.project_id = ? AND u.email = ?`,
      [projectId, (email || '').toLowerCase().trim()]
    );

    if (rows.length === 0) return res.status(400).json({ error: "User not found in this project." });

    const user = rows[0];
    if (user.status === 'blocked') return res.status(403).json({ error: "Your account has been suspended by the administrator." });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid password." });

    await pool.query('UPDATE end_users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?', [user.user_id]);

    const token = jwt.sign(
      { id: user.user_id, projectId: user.project_id, projectName: user.project_name, name: user.name, email: user.email },
      JWT_SECRET,
      { expiresIn: '3650d' }
    );

    notifyConsoleRealtime(user.project_id, 'USER_LOGGED_IN', { userId: user.user_id, email: user.email });

    res.json({
      message: "Login successful.",
      token,
      user: { id: user.user_id, name: user.name, email: user.email, projectId: user.project_id }
    });
  } catch (err) {
    res.status(500).json({ error: "Server error during login." });
  }
});

// METHOD 3: Passwordless Direct Email OTP Login
app.post('/api/auth/send-login-otp', async (req, res) => {
  try {
    const { projectId, apiKey, email } = req.body;
    const check = await verifyProjectActiveAndProvider(projectId, apiKey, 'passwordless_otp');
    if (!check.valid) return res.status(check.status).json({ error: check.error });

    const cleanEmail = (email || '').toLowerCase().trim();

    const [rows] = await pool.query(
      `SELECT u.*, p.project_name FROM end_users u JOIN projects p ON u.project_id = p.project_id WHERE u.project_id = ? AND p.api_key = ? AND u.email = ?`,
      [projectId, apiKey, cleanEmail]
    );
    if (rows.length === 0) return res.status(400).json({ error: "Email is not registered in this project." });

    const user = rows[0];
    if (user.status === 'blocked') return res.status(403).json({ error: "Account is suspended." });

    const guard = checkBrevoProtection(req, cleanEmail);
    if (!guard.allowed) {
      return res.status(429).json({ error: guard.error, retryAfterSeconds: guard.retryAfterSeconds });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpLoginAndResetMap.set(`login_${projectId}_${cleanEmail}`, {
      user,
      otp,
      wrongAttempts: 0,
      expiresAt: Date.now() + 10 * 60 * 1000
    });

    await sendDynamicBrevoEmail({
      senderName: user.project_name,
      toEmail: cleanEmail,
      toName: user.name,
      otp,
      purposeText: "Passwordless OTP Login"
    });

    res.json({
      message: "Login OTP sent to your email.",
      attemptNumber: guard.attemptNumber,
      nextWaitSeconds: guard.nextWaitSeconds
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to send login OTP." });
  }
});

app.post('/api/auth/verify-login-otp', async (req, res) => {
  try {
    const { projectId, email, otp } = req.body;
    const key = `login_${projectId}_${(email || '').toLowerCase().trim()}`;
    const record = otpLoginAndResetMap.get(key);

    if (!record || Date.now() > record.expiresAt) {
      otpLoginAndResetMap.delete(key);
      return res.status(400).json({ error: "OTP expired or invalid." });
    }
    if (record.otp !== otp.toString().trim()) {
      record.wrongAttempts = (record.wrongAttempts || 0) + 1;
      if (record.wrongAttempts >= 3) {
        otpLoginAndResetMap.delete(key);
        return res.status(400).json({ error: "3 wrong attempts! Login OTP cancelled. Please request a new OTP." });
      }
      return res.status(400).json({ error: `Incorrect OTP. (${3 - record.wrongAttempts} attempts left)` });
    }

    otpLoginAndResetMap.delete(key);
    const user = record.user;
    await pool.query('UPDATE end_users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?', [user.user_id]);

    const token = jwt.sign(
      { id: user.user_id, projectId: user.project_id, projectName: user.project_name, name: user.name, email: user.email },
      JWT_SECRET,
      { expiresIn: '3650d' }
    );

    notifyConsoleRealtime(user.project_id, 'USER_LOGGED_IN', { userId: user.user_id, email: user.email });

    res.json({
      message: "OTP login successful.",
      token,
      user: { id: user.user_id, name: user.name, email: user.email, projectId: user.project_id }
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to verify login OTP." });
  }
});

// METHOD 4: MAGIC LINK (One-Click Email Button Login / Verified Auto-Signup)
app.post('/api/auth/send-magic-link', async (req, res) => {
  try {
    const { projectId, apiKey, email, name, redirectUrl } = req.body;
    if (!projectId || !email || !redirectUrl) {
      return res.status(400).json({ error: "projectId, email, and redirectUrl are required." });
    }

    const check = await verifyProjectActiveAndProvider(projectId, apiKey || null, 'magic_link');
    if (!check.valid) return res.status(check.status).json({ error: check.error });

    const cleanEmail = email.toLowerCase().trim();

    const guard = checkBrevoProtection(req, cleanEmail);
    if (!guard.allowed) {
      return res.status(429).json({ error: guard.error, retryAfterSeconds: guard.retryAfterSeconds });
    }

    const senderProjectName = check.project.projectName;
    const magicToken = crypto.randomBytes(32).toString('hex');

    magicLinkMap.set(magicToken, {
      projectId,
      projectName: senderProjectName,
      email: cleanEmail,
      name: (name || cleanEmail.split('@')[0]).trim(),
      redirectUrl: redirectUrl.trim(),
      expiresAt: Date.now() + 10 * 60 * 1000
    });

    const serverBaseUrl = `${req.protocol}://${req.get('host')}`;
    const clickUrl = `${serverBaseUrl}/api/auth/magic-login?token=${magicToken}`;

    await sendDynamicBrevoEmail({
      senderName: senderProjectName,
      toEmail: cleanEmail,
      toName: (name || cleanEmail.split('@')[0]).trim(),
      magicLinkUrl: clickUrl,
      purposeText: "Instant 1-Click Magic Link Login"
    });

    res.json({
      message: `Magic Login Link sent to ${cleanEmail} from ${senderProjectName}.`,
      attemptNumber: guard.attemptNumber,
      nextWaitSeconds: guard.nextWaitSeconds
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to send Magic Link email." });
  }
});

// When user clicks the Magic Link button inside their real email inbox
app.get('/api/auth/magic-login', async (req, res) => {
  try {
    const { token } = req.query;
    const record = magicLinkMap.get(token);

    if (!record || Date.now() > record.expiresAt) {
      magicLinkMap.delete(token);
      return res.status(400).send("<h2>Magic Link has expired or is invalid. Please request a new link.</h2>");
    }

    magicLinkMap.delete(token);

    const [existing] = await pool.query(
      'SELECT * FROM end_users WHERE project_id = ? AND email = ?',
      [record.projectId, record.email]
    );

    let userId;
    let displayName = record.name;

    if (existing.length > 0) {
      if (existing[0].status === 'blocked') {
        return res.status(403).send("<h2>Your account has been suspended by the administrator.</h2>");
      }
      userId = existing[0].user_id;
      displayName = existing[0].name;
      await pool.query('UPDATE end_users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?', [userId]);
    } else {
      userId = "usr_" + crypto.randomBytes(8).toString('hex');
      const randomPass = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 10);
      await pool.query(
        'INSERT INTO end_users (user_id, project_id, name, email, password, auth_provider, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [userId, record.projectId, displayName, record.email, randomPass, 'magic_link', 'active']
      );
    }

    notifyConsoleRealtime(record.projectId, 'USER_MAGIC_LOGIN', { userId, email: record.email });

    const jwtToken = jwt.sign(
      { id: userId, projectId: record.projectId, projectName: record.projectName, name: displayName, email: record.email },
      JWT_SECRET,
      { expiresIn: '3650d' }
    );

    const separator = record.redirectUrl.includes('?') ? '&' : '?';
    return res.redirect(`${record.redirectUrl}${separator}authToken=${jwtToken}`);
  } catch (err) {
    res.status(500).send("<h2>Server error during Magic Link authentication.</h2>");
  }
});

// METHOD 5: Forgot & Reset Password via OTP
app.post('/api/auth/forgot-password-otp', async (req, res) => {
  try {
    const { projectId, apiKey, email } = req.body;
    const check = await verifyProjectActiveAndProvider(projectId, apiKey || null, 'forgot_pass');
    if (!check.valid) return res.status(check.status).json({ error: check.error });

    const cleanEmail = (email || '').toLowerCase().trim();

    const [rows] = await pool.query(
      `SELECT u.*, p.project_name FROM end_users u JOIN projects p ON u.project_id = p.project_id WHERE u.project_id = ? AND u.email = ?`,
      [projectId, cleanEmail]
    );
    if (rows.length === 0) return res.status(400).json({ error: "Email not registered in this project." });

    const guard = checkBrevoProtection(req, cleanEmail);
    if (!guard.allowed) {
      return res.status(429).json({ error: guard.error, retryAfterSeconds: guard.retryAfterSeconds });
    }

    const user = rows[0];
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpLoginAndResetMap.set(`reset_${projectId}_${cleanEmail}`, {
      userId: user.user_id,
      otp,
      wrongAttempts: 0,
      expiresAt: Date.now() + 10 * 60 * 1000
    });

    await sendDynamicBrevoEmail({
      senderName: user.project_name,
      toEmail: cleanEmail,
      toName: user.name,
      otp,
      purposeText: "Password Reset"
    });

    res.json({
      message: "Password reset OTP sent to your email.",
      attemptNumber: guard.attemptNumber,
      nextWaitSeconds: guard.nextWaitSeconds
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to send password reset OTP." });
  }
});

app.post('/api/auth/reset-password-verify', async (req, res) => {
  try {
    const { projectId, email, otp, newPassword } = req.body;
    if (!newPassword) return res.status(400).json({ error: "newPassword is required." });

    const key = `reset_${projectId}_${(email || '').toLowerCase().trim()}`;
    const record = otpLoginAndResetMap.get(key);

    if (!record || Date.now() > record.expiresAt) {
      otpLoginAndResetMap.delete(key);
      return res.status(400).json({ error: "OTP has expired." });
    }
    if (record.otp !== otp.toString().trim()) {
      record.wrongAttempts = (record.wrongAttempts || 0) + 1;
      if (record.wrongAttempts >= 3) {
        otpLoginAndResetMap.delete(key);
        return res.status(400).json({ error: "3 wrong attempts! Reset OTP cancelled. Please request a new OTP." });
      }
      return res.status(400).json({ error: `Incorrect OTP. (${3 - record.wrongAttempts} attempts left)` });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE end_users SET password = ? WHERE user_id = ?', [hashedPassword, record.userId]);
    otpLoginAndResetMap.delete(key);

    res.json({ message: "Password updated successfully. You can now log in." });
  } catch (err) {
    res.status(500).json({ error: "Failed to reset password." });
  }
});

// METHOD 6: 100% VERIFIED GOOGLE LOGIN (Verifies idToken or accessToken with Official Google Servers)
app.post('/api/auth/google-verified-login', async (req, res) => {
  try {
    const { projectId, apiKey, googleIdToken, googleAccessToken } = req.body;
    if (!projectId || (!googleIdToken && !googleAccessToken)) {
      return res.status(400).json({ error: "projectId and official googleIdToken (or googleAccessToken) are required." });
    }

    const check = await verifyProjectActiveAndProvider(projectId, apiKey || null, 'google');
    if (!check.valid) return res.status(check.status).json({ error: check.error });

    const projectName = check.project.projectName;

    let googleData;
    if (googleIdToken) {
      const gRes = await axios.get(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(googleIdToken)}`);
      googleData = gRes.data;
    } else {
      const gRes = await axios.get(`https://www.googleapis.com/oauth2/v3/userinfo`, {
        headers: { Authorization: `Bearer ${googleAccessToken}` }
      });
      googleData = gRes.data;
    }

    if (!googleData || !googleData.email || String(googleData.email_verified) !== 'true') {
      return res.status(401).json({ error: "Google account email could not be verified." });
    }

    const cleanEmail = googleData.email.toLowerCase().trim();
    const displayName = (googleData.name || cleanEmail.split('@')[0]).trim();

    const [existing] = await pool.query('SELECT * FROM end_users WHERE project_id = ? AND email = ?', [projectId, cleanEmail]);
    let userId;

    if (existing.length > 0) {
      if (existing[0].status === 'blocked') return res.status(403).json({ error: "Account is suspended." });
      userId = existing[0].user_id;
      await pool.query('UPDATE end_users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?', [userId]);
    } else {
      userId = "usr_" + crypto.randomBytes(8).toString('hex');
      const dummyPass = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 10);
      await pool.query(
        'INSERT INTO end_users (user_id, project_id, name, email, password, auth_provider, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [userId, projectId, displayName, cleanEmail, dummyPass, 'google_verified', 'active']
      );
    }

    notifyConsoleRealtime(projectId, 'USER_GOOGLE_LOGIN', { userId, name: displayName, email: cleanEmail });

    const token = jwt.sign(
      { id: userId, projectId, projectName, name: displayName, email: cleanEmail },
      JWT_SECRET,
      { expiresIn: '3650d' }
    );

    res.json({
      message: "Verified Google login successful.",
      token,
      user: { id: userId, name: displayName, email: cleanEmail, projectId, authProvider: 'google_verified' }
    });
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired Google token." });
  }
});

// METHOD 7: Auto-Login Session Verification
app.get('/api/auth/auto-login', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Authorization token missing." });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) return res.status(401).json({ error: "Token expired or invalid." });

    try {
      const check = await verifyProjectActiveAndProvider(decoded.projectId, null, null);
      if (!check.valid) return res.status(check.status).json({ error: check.error });

      const [rows] = await pool.query('SELECT status, name, email FROM end_users WHERE user_id = ? AND project_id = ?', [decoded.id, decoded.projectId]);
      if (rows.length === 0 || rows[0].status === 'blocked') {
        return res.status(403).json({ error: "Account deleted or suspended." });
      }
      res.json({ message: "Auto-login successful.", user: { ...decoded, name: rows[0].name, email: rows[0].email } });
    } catch (e) {
      return res.status(500).json({ error: "Verification error." });
    }
  });
});

// METHOD 8: ISOLATED ONE-SHOT & REAL-TIME USER SEARCH FOR CHATTING APPS
// Only registered & logged-in users of THIS projectId can search other active users of THIS projectId!
app.post('/api/auth/search-users', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader ? authHeader.split(' ')[1] : req.body.token;
    if (!token) return res.status(401).json({ error: "Only logged-in users of this project can search users." });

    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded || !decoded.projectId || !decoded.id) {
      return res.status(401).json({ error: "Invalid user session." });
    }

    // Confirm searching user is still active in this project
    const [me] = await pool.query('SELECT status FROM end_users WHERE user_id = ? AND project_id = ?', [decoded.id, decoded.projectId]);
    if (me.length === 0 || me[0].status === 'blocked') {
      return res.status(403).json({ error: "Your account is not authorized to search in this project." });
    }

    const q = (req.body.query || '').trim();
    const searchPattern = `%${q}%`;

    // Strictly isolated to decoded.projectId
    const [users] = await pool.query(
      `SELECT user_id, name, email, auth_provider, last_login
       FROM end_users
       WHERE project_id = ? AND status = 'active' AND (name LIKE ? OR email LIKE ? OR user_id LIKE ?)
       ORDER BY last_login DESC LIMIT 50`,
      [decoded.projectId, searchPattern, searchPattern, searchPattern]
    );

    res.json({
      projectId: decoded.projectId,
      count: users.length,
      users
    });
  } catch (err) {
    res.status(401).json({ error: "Unauthorized or expired token for user search." });
  }
});

// METHOD 9: PROJECT-ISOLATED CHATTING HISTORY API (For Chatting Apps using SDK)
app.get('/api/auth/chats', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Token required." });
    const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    const roomId = req.query.roomId || 'global';

    const [chats] = await pool.query(
      'SELECT * FROM project_chats WHERE project_id = ? AND room_id = ? ORDER BY created_at ASC LIMIT 200',
      [decoded.projectId, roomId]
    );
    res.json({ projectId: decoded.projectId, roomId, chats });
  } catch (err) {
    res.status(401).json({ error: "Invalid token." });
  }
});


// =================================================================
// PART 3: FULL ACCESS CONSOLE MANAGEMENT & CLOUD DELETE APIs
// =================================================================

function verifyConsoleAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Console token missing." });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err || !decoded.projectId) return res.status(401).json({ error: "Invalid console token." });
    req.admin = decoded;
    next();
  });
}

// Get & Update Full Project Settings (Name, Expiry, Providers, Domains, Google Client ID, Realtime DB Toggle)
app.get('/api/console/project-settings', verifyConsoleAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM projects WHERE project_id = ?', [req.admin.projectId]);
    if (rows.length === 0) return res.status(404).json({ error: "Project not found." });
    res.json({ projectConfig: formatProjectConfig(rows[0]) });
  } catch (err) {
    res.status(500).json({ error: "Failed to load project settings." });
  }
});

app.put('/api/console/project-settings', verifyConsoleAdmin, async (req, res) => {
  try {
    const { projectName, expiresAt, enabledProviders, authorizedDomains, googleClientId, realtimeDbActive } = req.body;
    const pid = req.admin.projectId;

    const [rows] = await pool.query('SELECT * FROM projects WHERE project_id = ?', [pid]);
    if (rows.length === 0) return res.status(404).json({ error: "Project not found." });
    const current = formatProjectConfig(rows[0]);

    const nextName = projectName !== undefined ? projectName.trim() : current.projectName;
    const nextExpiry = expiresAt !== undefined ? expiresAt : current.expiresAt;
    const nextProviders = enabledProviders !== undefined ? JSON.stringify(enabledProviders) : JSON.stringify(current.enabledProviders);
    const nextDomains = authorizedDomains !== undefined ? JSON.stringify(authorizedDomains) : JSON.stringify(current.authorizedDomains);
    const nextGoogleId = googleClientId !== undefined ? googleClientId.trim() : current.googleClientId;
    const nextDbActive = realtimeDbActive !== undefined ? (realtimeDbActive ? 1 : 0) : (current.realtimeDbActive ? 1 : 0);

    await pool.query(
      `UPDATE projects
       SET project_name = ?, expires_at = ?, enabled_providers = ?, authorized_domains = ?, google_client_id = ?, realtime_db_active = ?
       WHERE project_id = ?`,
      [nextName, nextExpiry, nextProviders, nextDomains, nextGoogleId, nextDbActive, pid]
    );

    const [updated] = await pool.query('SELECT * FROM projects WHERE project_id = ?', [pid]);
    const updatedConfig = formatProjectConfig(updated[0]);

    notifyConsoleRealtime(pid, 'PROJECT_SETTINGS_UPDATED', { projectConfig: updatedConfig });

    res.json({
      message: "Project settings saved in TiDB Cloud & synced in real time!",
      projectConfig: updatedConfig
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to update project settings in cloud." });
  }
});

app.put('/api/console/update-project', verifyConsoleAdmin, async (req, res) => {
  try {
    const { newProjectName } = req.body;
    if (!newProjectName) return res.status(400).json({ error: "newProjectName is required." });

    await pool.query('UPDATE projects SET project_name = ? WHERE project_id = ?', [newProjectName.trim(), req.admin.projectId]);
    notifyConsoleRealtime(req.admin.projectId, 'PROJECT_NAME_UPDATED', { projectName: newProjectName.trim() });
    res.json({ message: "Project/Sender Name updated successfully.", projectName: newProjectName.trim() });
  } catch (err) {
    res.status(500).json({ error: "Failed to update project name." });
  }
});

// Get All Users of Project
app.get('/api/console/users', verifyConsoleAdmin, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT user_id, name, email, auth_provider, status, last_login, created_at FROM end_users WHERE project_id = ? ORDER BY created_at DESC',
      [req.admin.projectId]
    );
    res.json({ totalUsers: users.length, users });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch project users." });
  }
});

// Create Verified User Directly from Console
app.post('/api/console/users/create', verifyConsoleAdmin, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "name, email, and password are required." });

    const userId = "usr_" + crypto.randomBytes(8).toString('hex');
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO end_users (user_id, project_id, name, email, password, auth_provider, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [userId, req.admin.projectId, name.trim(), email.toLowerCase().trim(), hashedPassword, 'admin_created', 'active']
    );
    notifyConsoleRealtime(req.admin.projectId, 'USER_CREATED', { userId, name, email });
    res.json({ message: "User created in TiDB Cloud successfully." });
  } catch (err) {
    res.status(400).json({ error: "Email already exists in this project or invalid data." });
  }
});

// Update User Name, Status (Block/Unblock) or Password in Cloud
app.put('/api/console/users/:userId', verifyConsoleAdmin, async (req, res) => {
  try {
    const { name, status, newPassword } = req.body;
    const { userId } = req.params;

    if (name) {
      await pool.query('UPDATE end_users SET name = ? WHERE user_id = ? AND project_id = ?', [name.trim(), userId, req.admin.projectId]);
    }
    if (status) {
      await pool.query('UPDATE end_users SET status = ? WHERE user_id = ? AND project_id = ?', [status, userId, req.admin.projectId]);
    }
    if (newPassword) {
      const hashed = await bcrypt.hash(newPassword, 10);
      await pool.query('UPDATE end_users SET password = ? WHERE user_id = ? AND project_id = ?', [hashed, userId, req.admin.projectId]);
    }

    notifyConsoleRealtime(req.admin.projectId, 'USER_UPDATED', { userId });
    res.json({ message: "User updated in TiDB Cloud successfully." });
  } catch (err) {
    res.status(500).json({ error: "Failed to update user." });
  }
});

// PERMANENT CLOUD DELETE: Delete User & Their Chats from TiDB Cloud
app.delete('/api/console/users/:userId', verifyConsoleAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    await pool.query('DELETE FROM end_users WHERE user_id = ? AND project_id = ?', [userId, req.admin.projectId]);
    await pool.query('DELETE FROM project_chats WHERE sender_id = ? AND project_id = ?', [userId, req.admin.projectId]);

    notifyConsoleRealtime(req.admin.projectId, 'USER_DELETED', { userId });
    res.json({ message: "User and associated records permanently deleted from TiDB Cloud." });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete user from cloud." });
  }
});

// Full Realtime Database Snapshot (Users + Project Chats + Support Messages + Settings)
app.get('/api/console/database', verifyConsoleAdmin, async (req, res) => {
  try {
    const pid = req.admin.projectId;
    const [projRows] = await pool.query('SELECT * FROM projects WHERE project_id = ?', [pid]);
    const [users] = await pool.query('SELECT user_id, name, email, auth_provider, status, last_login, created_at FROM end_users WHERE project_id = ? ORDER BY created_at DESC', [pid]);
    const [chats] = await pool.query('SELECT * FROM project_chats WHERE project_id = ? ORDER BY created_at DESC LIMIT 300', [pid]);
    const [support] = await pool.query('SELECT * FROM support_messages WHERE project_id = ? OR project_id = "global" ORDER BY created_at ASC LIMIT 300', [pid]);

    res.json({
      projectConfig: projRows.length ? formatProjectConfig(projRows[0]) : null,
      users,
      chats,
      support
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to load Realtime Database from TiDB Cloud." });
  }
});

// Add a Chat/Data Record from Console to TiDB Cloud
app.post('/api/console/chats', verifyConsoleAdmin, async (req, res) => {
  try {
    const { senderName, senderEmail, roomId, message } = req.body;
    if (!message) return res.status(400).json({ error: "Message is required." });

    const chatId = "chat_" + crypto.randomBytes(8).toString('hex');
    const pid = req.admin.projectId;

    await pool.query(
      'INSERT INTO project_chats (chat_id, project_id, room_id, sender_id, sender_name, sender_email, message) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [chatId, pid, roomId || 'global', 'admin_console', (senderName || 'Admin').trim(), (senderEmail || '').trim(), message.trim()]
    );

    const chatRecord = {
      chat_id: chatId,
      project_id: pid,
      room_id: roomId || 'global',
      sender_id: 'admin_console',
      sender_name: (senderName || 'Admin').trim(),
      message: message.trim(),
      created_at: new Date().toISOString()
    };

    io.to(`${pid}_${roomId || 'global'}`).emit('receive-message', chatRecord);
    notifyConsoleRealtime(pid, 'CHAT_ADDED', { chat: chatRecord });

    res.json({ message: "Chat record saved to TiDB Cloud.", chat: chatRecord });
  } catch (err) {
    res.status(500).json({ error: "Failed to save chat record in cloud." });
  }
});

// PERMANENT CLOUD DELETE: Delete a Specific Chat Message from TiDB Cloud
app.delete('/api/console/chats/:chatId', verifyConsoleAdmin, async (req, res) => {
  try {
    const { chatId } = req.params;
    await pool.query('DELETE FROM project_chats WHERE chat_id = ? AND project_id = ?', [chatId, req.admin.projectId]);
    notifyConsoleRealtime(req.admin.projectId, 'CHAT_DELETED', { chatId });
    io.to(`console_${req.admin.projectId}`).emit('chat-deleted', { chatId });
    res.json({ message: "Chat message permanently deleted from TiDB Cloud." });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete chat from cloud." });
  }
});

// PERMANENT CLOUD DELETE: Delete Entire Project & All Cloud Data
app.delete('/api/console/project', verifyConsoleAdmin, async (req, res) => {
  try {
    const pid = req.admin.projectId;
    await pool.query('DELETE FROM end_users WHERE project_id = ?', [pid]);
    await pool.query('DELETE FROM project_chats WHERE project_id = ?', [pid]);
    await pool.query('DELETE FROM support_messages WHERE project_id = ?', [pid]);
    await pool.query('DELETE FROM projects WHERE project_id = ?', [pid]);
    res.json({ message: "Project and all associated cloud data permanently deleted." });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete project from cloud." });
  }
});


// =================================================================
// PART 4: CLOUD CUSTOMER SUPPORT APIs (Human Agent + AI + Cloud Delete)
// =================================================================

app.get('/api/support/messages', async (req, res) => {
  try {
    const projectId = req.query.projectId || 'global';
    const [rows] = await pool.query(
      'SELECT * FROM support_messages WHERE project_id = ? OR project_id = "global" ORDER BY created_at ASC LIMIT 200',
      [projectId]
    );
    res.json({ agentStatus: supportAgentStatus, messages: rows });
  } catch (err) {
    res.status(500).json({ error: "Failed to load support messages." });
  }
});

app.post('/api/support/messages', async (req, res) => {
  try {
    const { projectId, senderRole, senderName, text, timeLabel } = req.body;
    if (!text) return res.status(400).json({ error: "Message text is required." });

    const msgId = "msg_" + crypto.randomBytes(8).toString('hex');
    const pid = projectId || 'global';
    const role = senderRole || 'user';
    const name = role === 'ai' ? 'Reply by AI' : (senderName || 'User');
    const time = timeLabel || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    await pool.query(
      'INSERT INTO support_messages (msg_id, project_id, sender_role, sender_name, text, time_label) VALUES (?, ?, ?, ?, ?, ?)',
      [msgId, pid, role, name, text, time]
    );

    const savedMsg = { msg_id: msgId, id: msgId, project_id: pid, senderRole: role, senderName: name, text, time };
    io.emit('support-message-new', savedMsg);
    if (pid !== 'global') notifyConsoleRealtime(pid, 'SUPPORT_MSG_ADDED', { message: savedMsg });

    res.json({ message: "Support message saved in TiDB Cloud.", data: savedMsg });
  } catch (err) {
    res.status(500).json({ error: "Failed to save support message in cloud." });
  }
});

// PERMANENT CLOUD DELETE: Delete Support Message from TiDB Cloud
app.delete('/api/support/messages/:msgId', async (req, res) => {
  try {
    const { msgId } = req.params;
    await pool.query('DELETE FROM support_messages WHERE msg_id = ?', [msgId]);
    io.emit('support-message-deleted', { msgId });
    res.json({ message: "Support message permanently deleted from TiDB Cloud.", msgId });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete support message from cloud." });
  }
});

// Update Human Agent Online/Offline Status (For Admin Support Panel)
app.post('/api/support/agent-status', (req, res) => {
  const { online, agentName } = req.body;
  supportAgentStatus = {
    online: Boolean(online),
    agentName: (agentName || "Support Agent").trim()
  };
  io.emit('support-agent-status', supportAgentStatus);
  res.json({ message: "Agent status updated.", agentStatus: supportAgentStatus });
});


// =================================================================
// PART 5: SOCKET.IO (Real-Time Chat, One-Shot Search, Console Sync & WebRTC)
// =================================================================

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  const mode = socket.handshake.auth?.mode;

  // Allow Support & Console listeners
  if (mode === 'support_public') {
    socket.isSupportGuest = true;
    return next();
  }

  if (!token) return next(new Error("Authentication error"));

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) return next(new Error("Invalid token"));

    // Case 1: Developer Console Admin Socket
    if (decoded.adminEmail && decoded.projectId && !decoded.id) {
      socket.isConsoleAdmin = true;
      socket.projectId = decoded.projectId;
      return next();
    }

    // Case 2: End-User Socket (Verified against TiDB)
    try {
      const [rows] = await pool.query('SELECT status, name, email FROM end_users WHERE user_id = ? AND project_id = ?', [decoded.id, decoded.projectId]);
      if (rows.length === 0 || rows[0].status === 'blocked') {
        return next(new Error("Account suspended or deleted from cloud"));
      }
      socket.user = { ...decoded, name: rows[0].name, email: rows[0].email };
      next();
    } catch (dbErr) {
      return next(new Error("Database verification failed"));
    }
  });
});

io.on('connection', (socket) => {
  // Join Developer Console Live Sync Room
  if (socket.isConsoleAdmin && socket.projectId) {
    socket.join(`console_${socket.projectId}`);
  }

  // Support Typing Broadcasts (Agent or AI)
  socket.on('support-typing', (data) => {
    socket.broadcast.emit('support-typing', data);
  });

  if (!socket.user) return;

  console.log(`[${socket.user.projectName}] Connected: ${socket.user.name}`);

  // Join Project-Isolated Room
  socket.on('join-room', (roomId) => {
    const cleanRoom = roomId || 'global';
    const isolatedRoom = `${socket.user.projectId}_${cleanRoom}`;
    socket.join(isolatedRoom);
    socket.to(isolatedRoom).emit('user-joined', {
      userId: socket.user.id,
      name: socket.user.name,
      email: socket.user.email,
      socketId: socket.id
    });
  });

  // Real-Time One-Shot User Search via Socket (Strictly isolated to socket.user.projectId)
  socket.on('search-project-users', async ({ query }, callback) => {
    try {
      const q = `%${(query || '').trim()}%`;
      const [users] = await pool.query(
        `SELECT user_id, name, email, auth_provider, last_login
         FROM end_users
         WHERE project_id = ? AND status = 'active' AND (name LIKE ? OR email LIKE ? OR user_id LIKE ?)
         ORDER BY last_login DESC LIMIT 50`,
        [socket.user.projectId, q, q, q]
      );
      if (typeof callback === 'function') callback({ success: true, users });
      else socket.emit('search-project-users-result', { users });
    } catch (err) {
      if (typeof callback === 'function') callback({ success: false, error: "Search failed" });
    }
  });

  // Real-Time Chat Message -> Saved in TiDB Cloud + Sent to Room + Synced to Console Realtime DB
  socket.on('send-message', async ({ roomId, message, receiverId }) => {
    if (!message || !String(message).trim()) return;
    const cleanRoom = roomId || 'global';
    const isolatedRoom = `${socket.user.projectId}_${cleanRoom}`;
    const chatId = "chat_" + crypto.randomBytes(8).toString('hex');
    const cleanMsg = String(message).trim();

    try {
      await pool.query(
        'INSERT INTO project_chats (chat_id, project_id, room_id, sender_id, sender_name, sender_email, receiver_id, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [chatId, socket.user.projectId, cleanRoom, socket.user.id, socket.user.name, socket.user.email || '', receiverId || null, cleanMsg]
      );
    } catch (e) {}

    const payload = {
      chatId,
      projectId: socket.user.projectId,
      roomId: cleanRoom,
      senderId: socket.user.id,
      senderName: socket.user.name,
      senderEmail: socket.user.email,
      receiverId: receiverId || null,
      message: cleanMsg,
      time: new Date().toISOString()
    };

    io.to(isolatedRoom).emit('receive-message', payload);
    notifyConsoleRealtime(socket.user.projectId, 'CHAT_ADDED', { chat: payload });
  });

  // Delete Chat Message in Real-Time from Client App -> Deletes from TiDB Cloud
  socket.on('delete-message', async ({ chatId, roomId }) => {
    try {
      await pool.query('DELETE FROM project_chats WHERE chat_id = ? AND project_id = ? AND sender_id = ?', [chatId, socket.user.projectId, socket.user.id]);
      const isolatedRoom = `${socket.user.projectId}_${roomId || 'global'}`;
      io.to(isolatedRoom).emit('chat-deleted', { chatId });
      notifyConsoleRealtime(socket.user.projectId, 'CHAT_DELETED', { chatId });
    } catch (e) {}
  });

  // WebRTC Audio/Video Signaling
  socket.on('webrtc-offer', ({ targetSocketId, offer, callType }) => {
    socket.to(targetSocketId).emit('webrtc-offer', {
      senderSocketId: socket.id,
      senderName: socket.user.name,
      callType: callType || 'video',
      offer
    });
  });

  socket.on('webrtc-answer', ({ targetSocketId, answer }) => {
    socket.to(targetSocketId).emit('webrtc-answer', {
      senderSocketId: socket.id,
      answer
    });
  });

  socket.on('webrtc-ice-candidate', ({ targetSocketId, candidate }) => {
    socket.to(targetSocketId).emit('webrtc-ice-candidate', {
      senderSocketId: socket.id,
      candidate
    });
  });

  socket.on('end-call', ({ targetSocketId }) => {
    socket.to(targetSocketId).emit('call-ended', { senderSocketId: socket.id });
  });
});


// =================================================================
// PART 6: DYNAMIC FIREBASE-STYLE CLIENT SDK ENGINE (/sdk.js)
// Allows any developer to connect their project in just 6-8 lines!
// =================================================================
app.get('/sdk.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.send(`
(function(window) {
  const FourKStudio = {
    config: null,
    socket: null,
    currentUser: null,

    initializeApp(config) {
      this.config = config;
      return this;
    },

    async request(endpoint, method = 'POST', body = null) {
      const headers = { 'Content-Type': 'application/json' };
      const token = localStorage.getItem('fourk_user_token_' + this.config.projectId);
      if (token) headers['Authorization'] = 'Bearer ' + token;

      const opts = { method, headers };
      if (body) {
        opts.body = JSON.stringify({
          projectId: this.config.projectId,
          apiKey: this.config.apiKey,
          ...body
        });
      }
      const res = await fetch(this.config.serverUrl + endpoint, opts);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Request failed');
      return data;
    },

    // One-Shot & Real-Time Isolated User Search (Searches ONLY users of this projectId)
    async searchProjectUsers(query = '') {
      const data = await this.request('/api/auth/search-users', 'POST', { query });
      return data.users || [];
    },

    // Connect Real-Time Socket for Chatting & WebRTC
    connectRealtime(roomId = 'global', onMessage = () => {}) {
      const token = localStorage.getItem('fourk_user_token_' + this.config.projectId);
      if (!token || typeof io === 'undefined') return null;
      this.socket = io(this.config.serverUrl, { auth: { token } });
      this.socket.on('connect', () => {
        this.socket.emit('join-room', roomId);
      });
      this.socket.on('receive-message', onMessage);
      return this.socket;
    },

    sendMessage(roomId, message, receiverId = null) {
      if (this.socket) {
        this.socket.emit('send-message', { roomId: roomId || 'global', message, receiverId });
      }
    }
  };
  window.FourKStudio = FourKStudio;
})(window);
  `);
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

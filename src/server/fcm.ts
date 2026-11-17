import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
import { getChannelById, isChannelOpenPublic, projectId } from './db.ts';

const require = createRequire(import.meta.url);
const webpush = require('web-push') as typeof import('web-push');

export interface WebPushSubscriptionJSON {
  endpoint: string;
  expirationTime?: number | null;
  keys: {
    p256dh: string;
    auth: string;
  };
}

export interface DeviceTokenRecord {
  id: string;
  token: string;
  subscription?: WebPushSubscriptionJSON;
  userId: number;
  username: string;
  deviceId?: string;
  platform?: string;
  deviceModel?: string;
  updatedAt: number;
  createdAt: number;
}

interface VapidKeys {
  publicKey: string;
  privateKey: string;
  subject: string;
}

const FCM_STORE_FILE = path.resolve('data/fcm_tokens.json');
const VAPID_STORE_FILE = path.resolve('data/vapid_keys.json');
const SERVICE_ACCOUNT_FILE = path.resolve('data/firebase_service_account.json');
const SHARED_FIREBASE_PROJECT_ID = projectId || 'majestic-interface-ksmzh';

// Cache for recently dispatched messageIds (avoid double push across client fx + server routes)
const recentDispatchedMessages = new Map<string, number>();

function pruneRecentDispatched() {
  const now = Date.now();
  for (const [k, ts] of recentDispatchedMessages.entries()) {
    if (now - ts > 60_000) {
      recentDispatchedMessages.delete(k);
    }
  }
}

let cachedVapidKeys: VapidKeys | null = null;

function ensureVapidKeys(): VapidKeys {
  if (cachedVapidKeys) return cachedVapidKeys;

  const envPub = (process.env.VAPID_PUBLIC_KEY || '').trim();
  const envPriv = (process.env.VAPID_PRIVATE_KEY || '').trim();
  const envSub = (process.env.VAPID_SUBJECT || 'mailto:support@sami-trading.app').trim();

  if (envPub && envPriv) {
    cachedVapidKeys = { publicKey: envPub, privateKey: envPriv, subject: envSub };
    webpush.setVapidDetails(cachedVapidKeys.subject, cachedVapidKeys.publicKey, cachedVapidKeys.privateKey);
    return cachedVapidKeys;
  }

  try {
    if (fs.existsSync(VAPID_STORE_FILE)) {
      const saved = JSON.parse(fs.readFileSync(VAPID_STORE_FILE, 'utf-8'));
      if (saved?.publicKey && saved?.privateKey) {
        cachedVapidKeys = {
          publicKey: String(saved.publicKey),
          privateKey: String(saved.privateKey),
          subject: String(saved.subject || envSub),
        };
        webpush.setVapidDetails(cachedVapidKeys.subject, cachedVapidKeys.publicKey, cachedVapidKeys.privateKey);
        return cachedVapidKeys;
      }
    }
  } catch (err) {
    console.warn('[WebPush] Error loading saved VAPID keys:', err);
  }

  const generated = webpush.generateVAPIDKeys();
  cachedVapidKeys = {
    publicKey: generated.publicKey,
    privateKey: generated.privateKey,
    subject: envSub,
  };

  try {
    const dir = path.dirname(VAPID_STORE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(VAPID_STORE_FILE, JSON.stringify(cachedVapidKeys, null, 2), 'utf-8');
  } catch (err) {
    console.warn('[WebPush] Error saving generated VAPID keys:', err);
  }

  webpush.setVapidDetails(cachedVapidKeys.subject, cachedVapidKeys.publicKey, cachedVapidKeys.privateKey);
  return cachedVapidKeys;
}

// Initialize VAPID keys eagerly so web-push is always ready
try {
  ensureVapidKeys();
} catch (err) {
  console.warn('[WebPush] VAPID init warning:', err);
}

export function getVapidPublicKey(): string {
  return ensureVapidKeys().publicKey;
}

function loadFcmTokens(): Record<string, DeviceTokenRecord> {
  try {
    if (fs.existsSync(FCM_STORE_FILE)) {
      return JSON.parse(fs.readFileSync(FCM_STORE_FILE, 'utf-8'));
    }
  } catch (err) {
    console.error('[FCM] Error reading tokens:', err);
  }
  return {};
}

function saveFcmTokens(tokens: Record<string, DeviceTokenRecord>) {
  try {
    const dir = path.dirname(FCM_STORE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(FCM_STORE_FILE, JSON.stringify(tokens, null, 2), 'utf-8');
  } catch (err) {
    console.error('[FCM] Error saving tokens:', err);
  }
}

function removeTokensByValue(keysToDelete: string[]) {
  if (keysToDelete.length === 0) return;
  const tokens = loadFcmTokens();
  let changed = false;
  for (const key of keysToDelete) {
    if (key in tokens) {
      delete tokens[key];
      changed = true;
    }
  }
  if (changed) {
    saveFcmTokens(tokens);
  }
}

// Service-account OAuth2 token cache for FCM HTTP v1
let cachedFcmAccessToken: { token: string; expiresAt: number } | null = null;

interface ServiceAccountJson {
  client_email: string;
  private_key: string;
  token_uri?: string;
  project_id?: string;
}

function loadServiceAccountCredentials(): ServiceAccountJson | null {
  const rawEnv = (process.env.FIREBASE_SERVICE_ACCOUNT_KEY || process.env.GCP_SERVICE_ACCOUNT_KEY || '').trim();
  if (rawEnv) {
    try {
      const jsonStr = rawEnv.startsWith('{') ? rawEnv : Buffer.from(rawEnv, 'base64').toString('utf8');
      const parsed = JSON.parse(jsonStr);
      if (parsed?.client_email && parsed?.private_key) return parsed;
    } catch (e: any) {
      console.warn('[FCM] Invalid service account env JSON:', e?.message);
    }
  }

  try {
    if (fs.existsSync(SERVICE_ACCOUNT_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(SERVICE_ACCOUNT_FILE, 'utf-8'));
      if (parsed?.client_email && parsed?.private_key) return parsed;
    }
  } catch {}

  return null;
}

function base64UrlEncode(input: Buffer | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf-8') : input;
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function getFcmV1AccessToken(): Promise<{ token: string; projectId: string } | null> {
  const nowSec = Math.floor(Date.now() / 1000);
  if (cachedFcmAccessToken && cachedFcmAccessToken.expiresAt - 60 > Date.now()) {
    return { token: cachedFcmAccessToken.token, projectId: SHARED_FIREBASE_PROJECT_ID };
  }

  const sa = loadServiceAccountCredentials();
  if (sa) {
    try {
      const header = base64UrlEncode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
      const claimSet = base64UrlEncode(
        JSON.stringify({
          iss: sa.client_email,
          scope: 'https://www.googleapis.com/auth/firebase.messaging',
          aud: sa.token_uri || 'https://oauth2.googleapis.com/token',
          iat: nowSec,
          exp: nowSec + 3600,
        })
      );
      const unsignedJwt = `${header}.${claimSet}`;
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(unsignedJwt);
      const signature = base64UrlEncode(signer.sign(sa.private_key));
      const assertion = `${unsignedJwt}.${signature}`;

      const tokenRes = await fetch(sa.token_uri || 'https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=${encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer')}&assertion=${encodeURIComponent(assertion)}`,
        signal: AbortSignal.timeout(8_000),
      });
      if (tokenRes.ok) {
        const tj = (await tokenRes.json()) as { access_token?: string; expires_in?: number };
        if (tj.access_token) {
          cachedFcmAccessToken = {
            token: tj.access_token,
            expiresAt: Date.now() + ((tj.expires_in || 3600) * 1000),
          };
          return {
            token: tj.access_token,
            projectId: sa.project_id || SHARED_FIREBASE_PROJECT_ID,
          };
        }
      }
    } catch (err: any) {
      console.warn('[FCM v1] Service account token exchange failed:', err?.message || err);
    }
  }

  // Fallback to Cloud Run / GCE Metadata Server OAuth2 token when running with Firebase IAM permissions
  try {
    const rTok = await fetch('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', {
      headers: { 'Metadata-Flavor': 'Google' },
      signal: AbortSignal.timeout(2_500),
    });
    if (rTok.ok) {
      const tj = (await rTok.json()) as { access_token?: string; expires_in?: number };
      if (tj.access_token) {
        cachedFcmAccessToken = {
          token: tj.access_token,
          expiresAt: Date.now() + ((tj.expires_in || 1800) * 1000),
        };
        return { token: tj.access_token, projectId: SHARED_FIREBASE_PROJECT_ID };
      }
    }
  } catch {}

  return null;
}

export function hasServerFcmCredentials(): boolean {
  return Boolean(
    process.env.FCM_SERVER_KEY ||
      process.env.FIREBASE_MESSAGING_KEY ||
      loadServiceAccountCredentials() ||
      cachedVapidKeys
  );
}

export async function registerDeviceToken(params: {
  token?: string;
  subscription?: WebPushSubscriptionJSON;
  userId: number;
  username: string;
  deviceId?: string;
  platform?: string;
  deviceModel?: string;
}): Promise<DeviceTokenRecord> {
  const tokens = loadFcmTokens();
  const cleanPlatform = String(params.platform || (params.subscription ? 'web' : 'android')).toLowerCase();
  const cleanDev = String(params.deviceId || 'dev').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 64) || 'dev';
  const cleanToken = String(params.token || params.subscription?.endpoint || '').trim();
  const id = `${cleanPlatform === 'web' ? 'web_push' : 'fcm_tok'}_${params.userId}_${cleanDev}`;
  const now = Date.now();

  // Remove stale registrations on the exact same deviceId, token, or Web Push endpoint belonging to previous accounts
  for (const [key, item] of Object.entries(tokens)) {
    if (key === id) continue;
    const sameDevice = Boolean(cleanDev && cleanDev !== 'dev' && item.deviceId === cleanDev && (item.platform || 'android') === cleanPlatform);
    const sameToken = Boolean(cleanToken && item.token === cleanToken);
    const sameEndpoint = Boolean(
      params.subscription?.endpoint && item.subscription?.endpoint === params.subscription.endpoint
    );
    if (sameDevice || sameToken || sameEndpoint) {
      delete tokens[key];
    }
  }

  const record: DeviceTokenRecord = {
    id,
    token: cleanToken,
    ...(params.subscription ? { subscription: params.subscription } : {}),
    userId: Number(params.userId),
    username: String(params.username || ''),
    deviceId: cleanDev,
    platform: cleanPlatform,
    deviceModel: params.deviceModel,
    updatedAt: now,
    createdAt: tokens[id]?.createdAt || now,
  };

  tokens[id] = record;
  saveFcmTokens(tokens);
  return record;
}

export async function unregisterDeviceToken(
  userId: number,
  token?: string,
  deviceId?: string,
  endpoint?: string
): Promise<void> {
  const tokens = loadFcmTokens();
  let changed = false;

  for (const [key, item] of Object.entries(tokens)) {
    if (item.userId === userId) {
      if (
        (token && item.token === token) ||
        (endpoint && item.subscription?.endpoint === endpoint) ||
        (deviceId && item.deviceId === deviceId) ||
        (!token && !deviceId && !endpoint)
      ) {
        delete tokens[key];
        changed = true;
      }
    }
  }

  if (changed) {
    saveFcmTokens(tokens);
  }
}

async function sendWebPushRecord(
  record: DeviceTokenRecord,
  payload: {
    title: string;
    body: string;
    chatType: string;
    data: Record<string, string>;
  }
): Promise<{ ok: boolean; expired?: boolean; error?: string }> {
  if (!record.subscription?.endpoint || !record.subscription?.keys?.p256dh || !record.subscription?.keys?.auth) {
    return { ok: false, error: 'invalid_subscription' };
  }
  try {
    ensureVapidKeys();
    const webPayload = JSON.stringify({
      title: payload.title,
      body: payload.body,
      icon: '/icon-192.png',
      badge: '/favicon.png',
      tag: payload.data.messageId ? `sami-msg-${payload.data.messageId}` : undefined,
      data: {
        ...payload.data,
        title: payload.title,
        body: payload.body,
        recipientUserId: String(record.userId),
        fromNotification: 'true',
      },
    });
    await webpush.sendNotification(record.subscription, webPayload, {
      TTL: 86_400,
      urgency: 'high',
    });
    return { ok: true };
  } catch (err: any) {
    const statusCode = Number(err?.statusCode || 0);
    if (statusCode === 404 || statusCode === 410) {
      return { ok: false, expired: true, error: `gone_${statusCode}` };
    }
    return { ok: false, error: err?.message || String(err) };
  }
}

async function sendAndroidFcmMessage(
  record: DeviceTokenRecord,
  payload: {
    title: string;
    body: string;
    chatType: string;
    data: Record<string, string>;
  }
): Promise<{ ok: boolean; unregistered?: boolean; error?: string }> {
  const token = record.token?.trim();
  if (!token) return { ok: false, error: 'missing_token' };

  const perDeviceData: Record<string, string> = {};
  for (const [k, v] of Object.entries(payload.data)) {
    if (v !== undefined && v !== null) {
      perDeviceData[k] = String(v);
    }
  }
  perDeviceData.title = payload.title;
  perDeviceData.body = payload.body;
  perDeviceData.chatType = payload.chatType;
  perDeviceData.recipientUserId = String(record.userId);
  perDeviceData.fromNotification = 'true';

  // 1. Try FCM HTTP v1 API (data-only HIGH priority so SamiFirebaseMessagingService.onMessageReceived wakes even when app process is closed, enforcing targetRecipientId + lockscreen redaction + deep-link extras)
  const auth = await getFcmV1AccessToken();
  if (auth) {
    try {
      const fcmUrl = `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(auth.projectId)}/messages:send`;
      const res = await fetch(fcmUrl, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${auth.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: {
            token,
            data: perDeviceData,
            android: {
              priority: 'HIGH',
              ttl: '86400s',
            },
          },
        }),
        signal: AbortSignal.timeout(8_000),
      });
      if (res.ok) {
        return { ok: true };
      }
      const errText = await res.text();
      if (errText.includes('UNREGISTERED') || errText.includes('registration-token-not-registered')) {
        return { ok: false, unregistered: true, error: errText };
      }
      if (res.status !== 403 && res.status !== 401) {
        return { ok: false, error: `fcm_v1_${res.status}: ${errText.slice(0, 180)}` };
      }
    } catch (err: any) {
      console.warn('[FCM v1] Dispatch warning:', err?.message || err);
    }
  }

  // 2. Fallback to Legacy FCM Server Key if explicitly configured
  const legacyKey = (process.env.FCM_SERVER_KEY || process.env.FIREBASE_MESSAGING_KEY || '').trim();
  if (legacyKey) {
    try {
      const res = await fetch('https://fcm.googleapis.com/fcm/send', {
        method: 'POST',
        headers: {
          Authorization: `key=${legacyKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          to: token,
          priority: 'high',
          time_to_live: 86400,
          data: perDeviceData,
        }),
        signal: AbortSignal.timeout(8_000),
      });
      if (res.ok) {
        const j = (await res.json()) as { success?: number; results?: Array<{ error?: string }> };
        if (j?.success && j.success > 0) return { ok: true };
        const resErr = j?.results?.[0]?.error || '';
        if (resErr === 'NotRegistered' || resErr === 'InvalidRegistration') {
          return { ok: false, unregistered: true, error: resErr };
        }
        return { ok: false, error: resErr || 'legacy_fcm_failed' };
      }
      return { ok: false, error: `legacy_http_${res.status}` };
    } catch (err: any) {
      return { ok: false, error: err?.message || String(err) };
    }
  }

  return { ok: false, error: 'no_fcm_server_credentials' };
}

export async function sendNotificationToUsers(
  recipientIds: number[],
  payload: {
    title?: string;
    body?: string;
    chatType?: string;
    excludeUserId?: number;
    data?: Record<string, string>;
  }
): Promise<{
  success: boolean;
  sentCount: number;
  webPushSent: number;
  fcmSent: number;
  matchedDevices: number;
}> {
  const tokens = loadFcmTokens();
  const seenTargets = new Set<string>();
  const matchingRecords: DeviceTokenRecord[] = [];
  const targetAll = !Array.isArray(recipientIds) || recipientIds.length === 0;

  for (const item of Object.values(tokens)) {
    if (payload.excludeUserId && item.userId === payload.excludeUserId) continue;
    if (!targetAll && !recipientIds.includes(item.userId)) continue;

    const dedupAddr =
      item.platform === 'web' && item.subscription?.endpoint
        ? `web:${item.subscription.endpoint}`
        : item.token
        ? `fcm:${item.token}`
        : '';
    if (!dedupAddr || seenTargets.has(dedupAddr)) continue;
    seenTargets.add(dedupAddr);
    matchingRecords.push(item);
  }

  if (matchingRecords.length === 0) {
    return { success: true, sentCount: 0, webPushSent: 0, fcmSent: 0, matchedDevices: 0 };
  }

  const title = String(payload.title || 'رسالة جديدة - Sami');
  const body = String(payload.body || 'لديك إشعار جديد في تطبيق Sami');
  const chatType = String(payload.chatType || payload.data?.chatType || 'channel');
  const baseData: Record<string, string> = { ...(payload.data || {}) };

  let webPushSent = 0;
  let fcmSent = 0;
  const expiredKeys: string[] = [];

  await Promise.allSettled(
    matchingRecords.map(async (rec) => {
      if (rec.platform === 'web' && rec.subscription?.endpoint) {
        const res = await sendWebPushRecord(rec, { title, body, chatType, data: baseData });
        if (res.ok) {
          webPushSent++;
        } else if (res.expired) {
          expiredKeys.push(rec.id);
        }
      } else if (rec.token) {
        const res = await sendAndroidFcmMessage(rec, { title, body, chatType, data: baseData });
        if (res.ok) {
          fcmSent++;
        } else if (res.unregistered) {
          expiredKeys.push(rec.id);
        }
      }
    })
  );

  if (expiredKeys.length > 0) {
    removeTokensByValue(expiredKeys);
  }

  const totalSent = webPushSent + fcmSent;
  console.log(
    `[Push Dispatch] matched=${matchingRecords.length}, webPushSent=${webPushSent}, fcmSent=${fcmSent}, title="${title}"`
  );

  return {
    success: true,
    sentCount: totalSent,
    webPushSent,
    fcmSent,
    matchedDevices: matchingRecords.length,
  };
}

export async function dispatchAuthorizedChatPush(params: {
  senderId: number;
  senderName?: string;
  senderRole?: string;
  chatType: 'channel' | 'private';
  channelId?: string;
  receiverId?: number;
  partnerId?: number;
  targetUserIds?: number[];
  messageId: string;
  title?: string;
  snippet: string;
}): Promise<{
  sentCount: number;
  webPushSent?: number;
  fcmSent?: number;
  matchedDevices?: number;
  recipientIds?: number[];
  deduped?: boolean;
  error?: string;
}> {
  try {
    pruneRecentDispatched();
    const cleanMsgId = String(params.messageId || '').trim();
    if (cleanMsgId && recentDispatchedMessages.has(cleanMsgId)) {
      return { sentCount: 0, deduped: true };
    }
    if (cleanMsgId) {
      recentDispatchedMessages.set(cleanMsgId, Date.now());
    }

    const tokens = loadFcmTokens();
    const recipientSet = new Set<number>();
    const isPrivate = params.chatType === 'private';

    if (Array.isArray(params.targetUserIds) && params.targetUserIds.length > 0) {
      for (const rawId of params.targetUserIds) {
        const uid = Number(rawId);
        if (uid > 0 && uid !== params.senderId && (isPrivate || uid < 9_000_000)) {
          recipientSet.add(uid);
        }
      }
    } else if (isPrivate) {
      const rId = Number(params.receiverId || params.partnerId || 0);
      if (rId > 0 && rId !== params.senderId) {
        recipientSet.add(rId);
      }
    } else if (params.channelId) {
      const ch = await getChannelById(params.channelId).catch(() => null);
      if (ch) {
        const isOpen = isChannelOpenPublic(ch);
        const candidates = isOpen
          ? Array.from(new Set([...(ch.memberIds || []), ...Object.values(tokens).map((t) => t.userId)]))
          : (ch.allowedMemberIds || ch.memberIds || []);
        for (const rawId of candidates) {
          const uid = Number(rawId);
          if (uid > 0 && uid !== params.senderId && uid < 9_000_000) {
            recipientSet.add(uid);
          }
        }
      } else {
        for (const item of Object.values(tokens)) {
          if (item.userId !== params.senderId && item.userId < 9_000_000) {
            recipientSet.add(item.userId);
          }
        }
      }
    }

    const recipientIds = Array.from(recipientSet);
    if (recipientIds.length === 0) {
      return { sentCount: 0, recipientIds: [] };
    }

    const senderDisplay = params.senderName || 'رسالة جديدة';
    const title = params.title || senderDisplay;
    const partnerForRecipient = isPrivate ? String(params.partnerId || params.senderId) : '';

    const data: Record<string, string> = {
      type: isPrivate ? 'private_message' : 'channel_important',
      chatType: isPrivate ? 'private' : 'channel',
      channelId: isPrivate ? '' : String(params.channelId || ''),
      partnerId: partnerForRecipient,
      partnerIdStr: partnerForRecipient,
      privateChatWithUserId: partnerForRecipient,
      senderId: String(params.senderId),
      senderName: senderDisplay,
      messageId: cleanMsgId || `msg_${Date.now()}`,
      fromNotification: 'true',
    };

    const pushResult = await sendNotificationToUsers(recipientIds, {
      title,
      body: params.snippet || 'وصلتك رسالة جديدة',
      chatType: data.chatType,
      excludeUserId: params.senderId,
      data,
    });

    return {
      sentCount: pushResult.sentCount,
      webPushSent: pushResult.webPushSent,
      fcmSent: pushResult.fcmSent,
      matchedDevices: pushResult.matchedDevices,
      recipientIds,
    };
  } catch (err: any) {
    return { sentCount: 0, error: err?.message || String(err) };
  }
}

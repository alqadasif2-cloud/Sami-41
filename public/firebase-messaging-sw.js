// Firebase & Web Push Service Worker for closed/background notifications
/* eslint-disable no-restricted-globals */

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

const recentMessageIds = [];

self.addEventListener('push', (event) => {
  let data = {};
  try {
    if (event.data) {
      data = event.data.json();
    }
  } catch (e) {
    data = {
      title: 'Sami',
      body: event.data ? event.data.text() : 'وصلتك رسالة جديدة',
    };
  }

  const payloadData = (data && typeof data.data === 'object' && data.data) ? data.data : data;
  const messageId = payloadData && payloadData.messageId ? String(payloadData.messageId).trim() : '';

  if (messageId) {
    if (recentMessageIds.includes(messageId)) {
      return;
    }
    recentMessageIds.push(messageId);
    if (recentMessageIds.length > 80) {
      recentMessageIds.shift();
    }
  }

  const title =
    payloadData.title ||
    data.title ||
    (data.notification && data.notification.title) ||
    'Sami';
  const body =
    payloadData.body ||
    data.body ||
    (data.notification && data.notification.body) ||
    'وصلتك رسالة جديدة';

  const rawType = String(payloadData.chatType || payloadData.type || '').trim();
  const rawPartner = Number(
    payloadData.partnerId ||
      payloadData.partnerIdStr ||
      payloadData.privateChatWithUserId ||
      0
  );
  const rawSender = Number(payloadData.senderId || 0);
  const isPrivate =
    rawType === 'private' ||
    rawType === 'private_message' ||
    (!payloadData.channelId && rawPartner > 0);
  const chatType = isPrivate ? 'private' : 'channel';
  const resolvedPartner = isPrivate ? (rawPartner > 0 ? rawPartner : (rawSender > 0 ? rawSender : null)) : null;

  const options = {
    body,
    icon: payloadData.icon || data.icon || '/icon-192.png',
    badge: '/favicon.png',
    dir: 'rtl',
    lang: 'ar',
    vibrate: [200, 100, 200],
    data: {
      type: isPrivate ? 'private_message' : 'channel_important',
      chatType,
      channelId: !isPrivate && payloadData.channelId ? String(payloadData.channelId).trim() : '',
      partnerId: resolvedPartner,
      privateChatWithUserId: resolvedPartner,
      senderId: rawSender > 0 ? rawSender : null,
      senderName: payloadData.senderName ? String(payloadData.senderName) : '',
      recipientUserId: payloadData.recipientUserId ? Number(payloadData.recipientUserId) || null : null,
      messageId: messageId || '',
      title,
      body,
      fromNotification: true,
    },
    tag: messageId ? `sami-msg-${messageId}` : (data.tag || `sami-msg-${Date.now()}`),
    renotify: !messageId,
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const raw = event.notification.data || {};
  const isPrivate =
    raw.chatType === 'private' ||
    raw.type === 'private_message' ||
    (!raw.channelId && Number(raw.partnerId || raw.privateChatWithUserId || 0) > 0);
  const partnerNum = isPrivate
    ? Number(raw.partnerId || raw.privateChatWithUserId || raw.senderId || 0) || null
    : null;

  const notifData = {
    type: isPrivate ? 'private_message' : 'channel_important',
    chatType: isPrivate ? 'private' : 'channel',
    channelId: !isPrivate && raw.channelId ? String(raw.channelId).trim() : null,
    partnerId: partnerNum,
    privateChatWithUserId: partnerNum,
    senderId: raw.senderId ? Number(raw.senderId) || null : null,
    senderName: raw.senderName || '',
    recipientUserId: raw.recipientUserId ? Number(raw.recipientUserId) || null : null,
    messageId: raw.messageId ? String(raw.messageId).trim() : null,
    fromNotification: true,
  };

  const deepLinkParam = encodeURIComponent(JSON.stringify(notifData));
  const targetUrl = `/?sami_deeplink=${deepLinkParam}`;

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(async (clientList) => {
      const origin = self.location.origin;
      const sameOriginClients = clientList.filter((c) => {
        try {
          return typeof c.url === 'string' && c.url.startsWith(origin);
        } catch {
          return false;
        }
      });

      const targetClient =
        sameOriginClients.find((c) => c.focused) ||
        sameOriginClients.find((c) => c.visibilityState === 'visible') ||
        sameOriginClients[0];

      if (targetClient) {
        try {
          if ('focus' in targetClient) {
            await targetClient.focus();
          }
          targetClient.postMessage({
            type: 'app_open_chat_message',
            detail: notifData,
          });
          return targetClient;
        } catch {
          if ('navigate' in targetClient) {
            return targetClient.navigate(targetUrl);
          }
        }
      }

      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl);
      }
      return undefined;
    })
  );
});

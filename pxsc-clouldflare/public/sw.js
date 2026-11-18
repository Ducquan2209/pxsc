// Service worker: nhận thông báo đẩy và hiển thị lên màn hình
self.addEventListener('push', function (event) {
  var data = {};
  try { data = event.data.json(); }
  catch (e) { data = { title: 'Thông báo mới', body: event.data ? event.data.text() : '' }; }
  event.waitUntil(
    self.registration.showNotification(data.title || 'Thông báo mới', {
      body: data.body || '',
      data: { url: data.url || '/' }
    })
  );
});

self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  var url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(clients.openWindow(url));
});

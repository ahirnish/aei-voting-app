// static/service-worker.js
const CACHE_NAME = 'voting-app-v1';
const urlsToCache = [
  '/',
  '/login',
  '/static/manifest.json',
  '/offline.html'
  // Only include URLs that are guaranteed to exist and be accessible
];

// Install the service worker and cache the static assets
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Opened cache');
        // Cache one URL at a time to prevent a single failure from aborting the entire caching process
        return Promise.all(
          urlsToCache.map(url => {
            return cache.add(url).catch(error => {
              console.error('Failed to cache:', url, error);
              // Continue despite the error
              return Promise.resolve();
            });
          })
        );
      })
  );
});

// Activate and clean up old caches
self.addEventListener('activate', event => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

// Serve cached content when offline
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // Cache hit - return response
        if (response) {
          return response;
        }
        
        // Clone the request because it can only be used once
        const fetchRequest = event.request.clone();
        
        return fetch(fetchRequest).then(
          response => {
            // Check if we received a valid response
            if(!response || response.status !== 200 || response.type !== 'basic') {
              return response;
            }

            // Clone the response
            const responseToCache = response.clone();

            // Try to cache the response
            caches.open(CACHE_NAME)
              .then(cache => {
                // Don't cache API responses that might change
                if (!event.request.url.includes('/vote/')) {
                  cache.put(event.request, responseToCache).catch(err => {
                    console.warn('Failed to update cache for:', event.request.url, err);
                  });
                }
              });

            return response;
          }
        ).catch(() => {
          // If the request is for a page, show the offline page
          if (event.request.mode === 'navigate') {
            return caches.match('/offline.html');
          }
        });
      })
  );
});

// Handle errors more gracefully
self.addEventListener('error', event => {
  console.error('Service worker error:', event.error);
});

self.addEventListener('unhandledrejection', event => {
  console.error('Service worker unhandled promise rejection:', event.reason);
});
/* Service worker: makes the analyzer installable and fast on repeat visits.
 *  - Pinned downloads (Pyodide runtime, Scapy wheel, fonts) never change,
 *    so they are served from cache after the first visit.
 *  - The site's own files (page, detectors in nthunt/) use the network first,
 *    so a new push shows up immediately, with the cache as an offline fallback.
 */
const SHELL = "nthunt-shell-v1";
const RUNTIME = "nthunt-runtime-v1";

const PINNED = [
  (u) => u.hostname === "cdn.jsdelivr.net" && u.pathname.startsWith("/pyodide/v"),
  (u) => u.hostname === "files.pythonhosted.org",
  (u) => u.hostname === "fonts.gstatic.com",
];

self.addEventListener("install", () => self.skipWaiting());

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      for (const key of await caches.keys()) if (![SHELL, RUNTIME].includes(key)) await caches.delete(key);
      await self.clients.claim();
    })()
  );
});

async function cacheFirst(request) {
  const cache = await caches.open(RUNTIME);
  const hit = await cache.match(request);
  if (hit) return hit;
  // Fetch as CORS so the response is readable and cacheable, even when the
  // original request (e.g. importScripts) was made in no-cors mode.
  let res;
  try {
    res = await fetch(request.url, { mode: "cors", credentials: "omit" });
  } catch (_) {
    return fetch(request); // fall back to the browser's normal request
  }
  if (res.ok) cache.put(request, res.clone());
  return res;
}

async function networkFirst(request) {
  const cache = await caches.open(SHELL);
  try {
    const res = await fetch(request);
    if (res.ok) cache.put(request, res.clone());
    return res;
  } catch (err) {
    const hit = await cache.match(request, { ignoreSearch: true });
    if (hit) return hit;
    throw err;
  }
}

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (PINNED.some((test) => test(url))) event.respondWith(cacheFirst(request));
  else if (url.origin === self.location.origin) event.respondWith(networkFirst(request));
});

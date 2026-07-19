(() => {
  'use strict';

  if (window.__stMobileStreamRelayInstalled) {
    return;
  }
  window.__stMobileStreamRelayInstalled = true;

  const originalFetch = window.fetch.bind(window);
  const relayPaths = new Set([
    '/api/backends/chat-completions/generate',
    '/api/backends/text-completions/generate',
    '/api/backends/kobold/generate',
    '/api/novelai/generate',
  ]);
  const retryDelays = [250, 500, 1_000, 2_000, 5_000];
  const relayRetryLifetimeMs = 80 * 60_000;
  const visibleStallWatchdogMs = 45_000;
  const resumeResetDebounceMs = 1_500;
  const pendingAbortStorageKey = 'st-mobile-pending-stream-relay-aborts-v1';
  const cancelLoops = new Set();
  const activeRelaySessions = new Set();

  const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

  function streamingFlagMatches(pathname, parsed) {
    if (pathname === '/api/backends/chat-completions/generate'
        || pathname === '/api/backends/text-completions/generate') {
      return parsed?.stream === true;
    }
    return parsed?.streaming === true;
  }

  async function inspectRequest(input, init) {
    let request;
    try {
      request = new Request(input, init);
    } catch {
      return { request: null, details: null };
    }
    const url = new URL(request.url, location.href);
    if (request.method !== 'POST'
        || url.origin !== location.origin
        || url.search !== ''
        || !relayPaths.has(url.pathname)) {
      return { request, details: null };
    }
    let body;
    let parsed;
    try {
      body = await request.clone().text();
      parsed = JSON.parse(body);
    } catch {
      return { request, details: null };
    }
    if (!streamingFlagMatches(url.pathname, parsed)) {
      return { request, details: null };
    }
    return { request, details: {
      url: request.url,
      headers: new Headers(request.headers),
      body,
      signal: request.signal,
      credentials: request.credentials,
      mode: request.mode,
      cache: request.cache,
      redirect: request.redirect,
      referrer: request.referrer,
      referrerPolicy: request.referrerPolicy,
      integrity: request.integrity,
    } };
  }

  function makeTransportRequest(details, relayId, offset, transportSignal) {
    const headers = new Headers(details.headers);
    headers.set('x-st-mobile-relay-id', relayId);
    headers.set('x-st-mobile-relay-offset', String(offset));
    return new Request(details.url, {
      method: 'POST',
      headers,
      body: details.body,
      signal: transportSignal,
      credentials: details.credentials,
      mode: details.mode,
      cache: 'no-store',
      redirect: details.redirect,
      referrer: details.referrer,
      referrerPolicy: details.referrerPolicy,
      integrity: details.integrity,
    });
  }

  function abortError(signal) {
    if (signal?.reason instanceof Error) {
      return signal.reason;
    }
    return new DOMException('The generation was aborted', 'AbortError');
  }

  function pendingAbortIds() {
    try {
      const value = JSON.parse(localStorage.getItem(pendingAbortStorageKey) ?? '[]');
      return Array.isArray(value) ? value.filter((id) => typeof id === 'string') : [];
    } catch {
      return [];
    }
  }

  function rememberPendingAbort(relayId) {
    try {
      localStorage.setItem(pendingAbortStorageKey, JSON.stringify([...new Set([...pendingAbortIds(), relayId])]));
    } catch {
      // In-memory retries still run when storage is unavailable.
    }
  }

  function forgetPendingAbort(relayId) {
    try {
      const remaining = pendingAbortIds().filter((id) => id !== relayId);
      if (remaining.length === 0) {
        localStorage.removeItem(pendingAbortStorageKey);
      } else {
        localStorage.setItem(pendingAbortStorageKey, JSON.stringify(remaining));
      }
    } catch {
      // Gateway tombstones remain the final race-safe cancellation backstop.
    }
  }

  async function cancelRelay(relayId) {
    rememberPendingAbort(relayId);
    if (cancelLoops.has(relayId)) {
      return;
    }
    cancelLoops.add(relayId);
    try {
      let retryIndex = 0;
      while (true) {
        try {
          const response = await originalFetch(`/__mobile/stream-relay/${relayId}`, {
            method: 'DELETE',
            cache: 'no-store',
            credentials: 'same-origin',
            keepalive: true,
          });
          if (response.ok || response.status === 401 || response.status === 403 || response.status === 404) {
            forgetPendingAbort(relayId);
            return;
          }
        } catch {
          // Retry after focus/network returns.
        }
        await delay(retryDelays[Math.min(retryIndex, retryDelays.length - 1)]);
        retryIndex += 1;
      }
    } finally {
      cancelLoops.delete(relayId);
    }
  }

  for (const relayId of pendingAbortIds()) {
    void cancelRelay(relayId);
  }
  const resumePendingAborts = () => {
    for (const relayId of pendingAbortIds()) {
      void cancelRelay(relayId);
    }
  };
  const pauseActiveRelays = (reason) => {
    for (const session of [...activeRelaySessions]) {
      session.pause(reason);
    }
  };
  const resumeActiveRelays = (reason) => {
    resumePendingAborts();
    for (const session of [...activeRelaySessions]) {
      session.resume(reason);
    }
  };
  window.addEventListener('online', () => resumeActiveRelays('online'));
  window.addEventListener('pageshow', () => resumeActiveRelays('pageshow'));
  window.addEventListener('focus', () => resumeActiveRelays('focus'));
  window.addEventListener('stMobileHostPause', () => pauseActiveRelays('host-pause'));
  window.addEventListener('stMobileHostResume', () => resumeActiveRelays('host-resume'));
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      resumeActiveRelays('visibility-visible');
    } else {
      pauseActiveRelays('visibility-hidden');
    }
  });

  async function relayedFetch(details) {
    const relayId = crypto.randomUUID();
    const relayStartedAt = Date.now();
    const relayRetryDeadline = relayStartedAt + relayRetryLifetimeMs;
    let offset = 0;
    let retryIndex = 0;
    let stopped = false;
    let settled = false;
    let cleanedUp = false;
    let suspended = document.visibilityState === 'hidden';
    let terminalError = null;
    let lastResumeResetAt = 0;
    let controllerRef = null;
    let activeTransport = null;
    let deadlineTimer = null;
    let stallTimer = null;
    const stateChangeWaiters = new Set();

    const retryLifetimeExpired = () => Date.now() >= relayRetryDeadline;
    const retryLifetimeError = (cause) => new Error(
      'Stream relay reconnect lifetime expired without starting a duplicate generation',
      cause ? { cause } : undefined,
    );
    const lifecycleTransportError = (reason) => new DOMException(
      `Mobile relay transport reset after ${reason}`,
      'AbortError',
    );
    const visibleStallError = () => new Error(
      'Mobile relay transport made no progress while visible; reconnecting without duplicating the generation',
    );

    const notifyStateChange = () => {
      const waiters = [...stateChangeWaiters];
      stateChangeWaiters.clear();
      for (const resolve of waiters) {
        resolve();
      }
    };
    const clearStallWatchdog = () => {
      if (stallTimer !== null) {
        clearTimeout(stallTimer);
        stallTimer = null;
      }
    };
    const armStallWatchdog = () => {
      clearStallWatchdog();
      if (stopped || suspended || !activeTransport) {
        return;
      }
      const watchedTransport = activeTransport;
      stallTimer = setTimeout(() => {
        if (!stopped && !suspended && activeTransport === watchedTransport) {
          watchedTransport.abort(visibleStallError());
        }
      }, visibleStallWatchdogMs);
    };
    const waitUntilActive = async () => {
      while (suspended && !stopped) {
        await new Promise((resolve) => stateChangeWaiters.add(resolve));
      }
    };
    const waitForRetry = (milliseconds) => new Promise((resolve) => {
      let finished = false;
      const finish = () => {
        if (finished) {
          return;
        }
        finished = true;
        clearTimeout(timer);
        stateChangeWaiters.delete(finish);
        resolve();
      };
      const timer = setTimeout(finish, milliseconds);
      stateChangeWaiters.add(finish);
      if (stopped) {
        finish();
      }
    });

    const lifecycleSession = {
      pause(reason) {
        if (stopped) {
          return;
        }
        suspended = true;
        lastResumeResetAt = 0;
        clearStallWatchdog();
        notifyStateChange();
        activeTransport?.abort(lifecycleTransportError(reason));
      },
      resume(reason) {
        if (stopped) {
          return;
        }
        const wasSuspended = suspended;
        suspended = false;
        notifyStateChange();
        const now = Date.now();
        if (wasSuspended || now - lastResumeResetAt >= resumeResetDebounceMs) {
          lastResumeResetAt = now;
          activeTransport?.abort(lifecycleTransportError(reason));
        }
        armStallWatchdog();
      },
    };

    const cleanup = () => {
      if (cleanedUp) {
        return;
      }
      cleanedUp = true;
      activeRelaySessions.delete(lifecycleSession);
      details.signal?.removeEventListener('abort', onAbort);
      clearTimeout(deadlineTimer);
      clearStallWatchdog();
      notifyStateChange();
    };

    const stop = (error, cancelUpstream, notifyController = true) => {
      if (stopped) {
        return;
      }
      stopped = true;
      terminalError = error;
      activeTransport?.abort(error);
      if (cancelUpstream) {
        void cancelRelay(relayId);
      }
      if (notifyController && !settled && controllerRef) {
        settled = true;
        controllerRef.error(error);
      }
      cleanup();
    };

    const onAbort = () => stop(abortError(details.signal), true);
    if (details.signal?.aborted) {
      throw abortError(details.signal);
    }
    details.signal?.addEventListener('abort', onAbort, { once: true });
    activeRelaySessions.add(lifecycleSession);
    deadlineTimer = setTimeout(
      () => stop(retryLifetimeError(), true),
      Math.max(0, relayRetryDeadline - Date.now()),
    );

    const open = async () => {
      await waitUntilActive();
      if (stopped) {
        throw terminalError ?? abortError(details.signal);
      }
      if (retryLifetimeExpired()) {
        throw retryLifetimeError();
      }
      const transport = new AbortController();
      activeTransport = transport;
      armStallWatchdog();
      try {
        const response = await originalFetch(makeTransportRequest(details, relayId, offset, transport.signal));
        if (transport.signal.aborted) {
          throw transport.signal.reason ?? lifecycleTransportError('transport-abort');
        }
        armStallWatchdog();
        return response;
      } catch (error) {
        if (activeTransport === transport) {
          activeTransport = null;
        }
        clearStallWatchdog();
        throw error;
      }
    };

    let firstResponse;
    while (!stopped) {
      try {
        firstResponse = await open();
        break;
      } catch (error) {
        if (stopped) {
          cleanup();
          throw terminalError ?? error;
        }
        if (details.signal?.aborted) {
          void cancelRelay(relayId);
          cleanup();
          throw abortError(details.signal);
        }
        if (retryLifetimeExpired()) {
          void cancelRelay(relayId);
          cleanup();
          throw retryLifetimeError(error);
        }
        await waitUntilActive();
        await waitForRetry(retryDelays[Math.min(retryIndex, retryDelays.length - 1)]);
        if (retryLifetimeExpired()) {
          void cancelRelay(relayId);
          cleanup();
          throw retryLifetimeError(error);
        }
        retryIndex += 1;
      }
    }
    if (!firstResponse) {
      cleanup();
      throw terminalError ?? abortError(details.signal);
    }
    if (!firstResponse.ok || !firstResponse.body) {
      cleanup();
      return firstResponse;
    }

    const headers = new Headers(firstResponse.headers);
    for (const name of [
      'content-encoding',
      'content-length',
      'transfer-encoding',
      'x-st-mobile-relay-id',
      'x-st-mobile-relay-state',
    ]) {
      headers.delete(name);
    }

    const body = new ReadableStream({
      start(controller) {
        controllerRef = controller;
        const pump = async (initialResponse) => {
          let response = initialResponse;
          while (!stopped) {
            try {
              if (!response.ok || !response.body) {
                throw new Error(`Stream relay reconnect failed with HTTP ${response.status}`);
              }
              const reader = response.body.getReader();
              try {
                while (!stopped) {
                  const { done, value } = await reader.read();
                  if (done) {
                    settled = true;
                    stopped = true;
                    activeTransport = null;
                    cleanup();
                    controller.close();
                    return;
                  }
                  controller.enqueue(value);
                  offset += value.byteLength;
                  retryIndex = 0;
                  armStallWatchdog();
                }
              } finally {
                try {
                  reader.releaseLock();
                } catch {
                  // The transport abort may already have released the body.
                }
              }
            } catch (error) {
              activeTransport = null;
              clearStallWatchdog();
              if (stopped || details.signal?.aborted) {
                stop(abortError(details.signal), true);
                return;
              }
              if (retryLifetimeExpired()) {
                stop(retryLifetimeError(error), true);
                return;
              }
              await waitUntilActive();
              if (stopped) {
                return;
              }
              await waitForRetry(retryDelays[Math.min(retryIndex, retryDelays.length - 1)]);
              if (retryLifetimeExpired()) {
                stop(retryLifetimeError(error), true);
                return;
              }
              retryIndex += 1;
              try {
                response = await open();
                if (!response.ok || !response.body) {
                  stop(new Error(`Stream relay reconnect failed with HTTP ${response.status}`), false);
                  return;
                }
              } catch (reconnectError) {
                response = null;
                continue;
              }
            }
          }
        };
        void pump(firstResponse);
      },
      cancel() {
        if (!stopped) {
          settled = true;
          stop(new DOMException('The generation response body was canceled', 'AbortError'), true, false);
        }
      },
    });

    return new Response(body, {
      status: firstResponse.status,
      statusText: firstResponse.statusText,
      headers,
    });
  }

  window.fetch = async function stMobileResumableFetch(input, init) {
    const inspected = await inspectRequest(input, init);
    if (inspected.details) {
      return relayedFetch(inspected.details);
    }
    return inspected.request ? originalFetch(inspected.request) : originalFetch(input, init);
  };
})();

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

class MemoryStorage {
  #values = new Map();

  getItem(key) {
    return this.#values.has(key) ? this.#values.get(key) : null;
  }

  setItem(key, value) {
    this.#values.set(key, String(value));
  }

  removeItem(key) {
    this.#values.delete(key);
  }
}

function clientHarness(fetchImplementation) {
  const window = new EventTarget();
  const document = new EventTarget();
  document.visibilityState = 'visible';
  window.fetch = fetchImplementation;
  const context = vm.createContext({
    window,
    document,
    location: {
      href: 'https://192.168.1.215:38443/',
      origin: 'https://192.168.1.215:38443',
    },
    localStorage: new MemoryStorage(),
    crypto,
    Request,
    Response,
    Headers,
    ReadableStream,
    AbortController,
    DOMException,
    URL,
    Event,
    EventTarget,
    setTimeout,
    clearTimeout,
  });
  return { context, window, document };
}

test('native resume breaks a silent half-open body and reattaches at the exact byte offset', async () => {
  const source = await readFile(new URL('../public/stream-relay-client.js', import.meta.url), 'utf8');
  const firstChunk = new TextEncoder().encode('data: {"token":"first"}\n\n');
  const remaining = new TextEncoder().encode('data: {"token":"second"}\n\ndata: [DONE]\n\n');
  const transports = [];
  let cancelRequests = 0;

  const originalFetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    if (request.method === 'DELETE') {
      cancelRequests += 1;
      return new Response(null, { status: 204 });
    }
    assert.equal(url.pathname, '/api/backends/chat-completions/generate');
    const record = {
      relayId: request.headers.get('x-st-mobile-relay-id'),
      offset: Number(request.headers.get('x-st-mobile-relay-offset')),
      signal: request.signal,
    };
    transports.push(record);

    const body = new ReadableStream({
      start(controller) {
        if (record.offset === 0) {
          controller.enqueue(firstChunk);
          const abort = () => controller.error(request.signal.reason ?? new DOMException('aborted', 'AbortError'));
          if (request.signal.aborted) {
            abort();
          } else {
            request.signal.addEventListener('abort', abort, { once: true });
          }
          return;
        }
        assert.equal(record.offset, firstChunk.byteLength);
        controller.enqueue(remaining);
        controller.close();
      },
    });
    return new Response(body, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    });
  };

  const harness = clientHarness(originalFetch);
  vm.runInContext(source, harness.context, { filename: 'stream-relay-client.js' });

  const response = await harness.window.fetch(
    'https://192.168.1.215:38443/api/backends/chat-completions/generate',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ stream: true, prompt: 'runtime wake test' }),
    },
  );
  const reader = response.body.getReader();
  const first = await reader.read();
  assert.deepEqual(first.value, firstChunk);
  assert.equal(first.done, false);

  harness.window.dispatchEvent(new Event('stMobileHostResume'));

  const received = [first.value];
  while (true) {
    const next = await reader.read();
    if (next.done) {
      break;
    }
    received.push(next.value);
  }

  assert.deepEqual(Buffer.concat(received.map((chunk) => Buffer.from(chunk))), Buffer.concat([
    Buffer.from(firstChunk),
    Buffer.from(remaining),
  ]));
  assert.equal(transports.length, 2);
  assert.equal(transports[0].relayId, transports[1].relayId);
  assert.deepEqual(transports.map(({ offset }) => offset), [0, firstChunk.byteLength]);
  assert.equal(transports[0].signal.aborted, true);
  assert.equal(cancelRequests, 0, 'Lifecycle recovery must not cancel the server-owned generation');
});

'use strict';
/**
 * Canonical signed-message builder for arken-auth v1.
 *
 * Format — 7 newline-delimited fields:
 *   arken-auth-v1
 *   {host}         lowercase hostname of the server (e.g. "api.example.com")
 *   {METHOD}       uppercase HTTP verb
 *   {path+query}   full path including query string (e.g. "/api/v1?page=2")
 *   {bodyHash}     hex SHA-256 of raw request body, or "" for no body
 *   {nonce}        server-issued one-time nonce
 *   {expires}      Unix seconds (integer, as string) when the nonce expires
 *
 * Rules:
 *  - The SERVER always derives host/method/path from the actual incoming request.
 *    It never copies these from client-supplied header fields.
 *  - The CLIENT builds this from the URL it actually called and the challenge it received.
 *    It refuses to sign if challenge.audience ≠ URL hostname.
 *  - Both sides MUST use this exact module so the format stays in sync.
 *
 * NOTE: The Python and Rust implementations must mirror this exactly.
 */

const crypto = require('node:crypto');

/**
 * @param {object} opts
 * @param {string} opts.host      – hostname (no port, no scheme)
 * @param {string} opts.method    – HTTP method
 * @param {string} opts.path      – path + query string
 * @param {string} opts.bodyHash  – hex SHA-256 of body, or ""
 * @param {string} opts.nonce     – nonce from challenge
 * @param {number} opts.expires   – Unix seconds
 * @returns {string}
 */
function buildSignedMessage({ host, method, path, bodyHash, nonce, expires }) {
  return [
    'arken-auth-v1',
    host,
    method.toUpperCase(),
    path || '/',
    bodyHash || '',
    String(nonce),
    String(expires),
  ].join('\n');
}

/**
 * SHA-256 hex of a Buffer or string; '' for null/empty bodies.
 * @param {Buffer|string|null|undefined} body
 * @returns {string}
 */
function bodyHashOf(body) {
  if (!body) return '';
  if (Buffer.isBuffer(body) && body.length === 0) return '';
  if (typeof body === 'string' && body === '') return '';
  return crypto.createHash('sha256').update(body).digest('hex');
}

module.exports = { buildSignedMessage, bodyHashOf };

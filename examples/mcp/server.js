/**
 * MCP server protected by arken-auth
 *
 * An agent calling this server needs a did:key — no API key required.
 * The server stores no credentials. Every request is verified cryptographically.
 *
 * Usage:
 *   node server.js
 *
 * Then in another terminal:
 *   node client.js
 */

'use strict';

const express = require('express');
const { arkenAuth } = require('@arkenforge/arken-auth');

const app = express();
app.use(express.json());

// ---------------------------------------------------------------------------
// arken-auth middleware — protects all MCP tool endpoints
// ---------------------------------------------------------------------------

const auth = arkenAuth({
    statement: 'Sign to access this MCP server.'
});

// ---------------------------------------------------------------------------
// MCP tool: echo
// Returns whatever the agent sends. Proves the agent is authenticated.
// ---------------------------------------------------------------------------

app.post('/mcp/tools/echo', auth, (req, res) => {
    const { input } = req.body ?? {};
    res.json({
        tool: 'echo',
        did: req.user.did,
        result: input ?? '(no input)',
    });
});

// ---------------------------------------------------------------------------
// MCP tool: time
// Returns the current server time. Useful as a live "am I authenticated?" check.
// ---------------------------------------------------------------------------

app.get('/mcp/tools/time', auth, (req, res) => {
    res.json({
        tool: 'time',
        did: req.user.did,
        result: new Date().toISOString(),
    });
});

// ---------------------------------------------------------------------------
// MCP manifest — lists available tools (public, no auth required)
// ---------------------------------------------------------------------------

app.get('/mcp/manifest', (req, res) => {
    res.json({
        name: 'arken-example-mcp',
        version: '0.1.0',
        auth: 'arken-auth (a401)',
        tools: [
            { name: 'echo', method: 'POST', path: '/mcp/tools/echo', input: { input: 'string' } },
            { name: 'time', method: 'GET',  path: '/mcp/tools/time' },
        ],
    });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log(`MCP server listening on http://localhost:${PORT}`);
    console.log(`Manifest: http://localhost:${PORT}/mcp/manifest`);
});

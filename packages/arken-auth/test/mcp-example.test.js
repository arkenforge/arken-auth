'use strict';
// MCP example honesty tests — Phase 3, Item 11
//
// The examples/mcp/ example uses plain Express HTTP routes — it does NOT use
// the Model Context Protocol SDK or transport. Calling it an "MCP server"
// misleads readers into thinking arken-auth has MCP SDK integration.
//
// FAILING BEFORE THE FIX:
//   - "mcp-example: README disclaims it is plain HTTP, not MCP SDK"
//   - "mcp-example: server.js does not describe itself as an MCP server"
// Both fail because the current files claim to be an MCP server without any
// disclaimer that the actual MCP protocol/SDK is not in use.

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const path     = require('node:path');

const REPO_ROOT  = path.resolve(__dirname, '../../..');
const MCP_DIR    = path.join(REPO_ROOT, 'examples', 'mcp');
const README     = path.join(MCP_DIR, 'README.md');
const SERVER_JS  = path.join(MCP_DIR, 'server.js');
const CLIENT_JS  = path.join(MCP_DIR, 'client.js');

test('mcp-example: examples/mcp directory exists', () => {
    assert.ok(fs.existsSync(MCP_DIR), 'examples/mcp/ must exist');
});

test('mcp-example: README disclaims it is plain HTTP, not MCP SDK', () => {
    const md = fs.readFileSync(README, 'utf8').toLowerCase();
    // Must contain some honest signal — "plain http", "not mcp", "express http", or "http api"
    const hasDisclaimer =
        md.includes('plain http') ||
        md.includes('not the model context protocol') ||
        md.includes('not using the mcp') ||
        md.includes('http api') ||
        md.includes('express http');
    assert.ok(hasDisclaimer,
        'examples/mcp/README.md must clearly state this is a plain HTTP example, not an MCP SDK integration');
});

test('mcp-example: server.js does not describe itself as an MCP server without qualification', () => {
    const src = fs.readFileSync(SERVER_JS, 'utf8');
    // The file must contain a disclaimer comment near the top (within first 20 lines)
    const header = src.split('\n').slice(0, 20).join('\n').toLowerCase();
    const hasQualification =
        header.includes('plain http') ||
        header.includes('http api') ||
        header.includes('not mcp') ||
        header.includes('not the model context protocol') ||
        header.includes('express http');
    assert.ok(hasQualification,
        'examples/mcp/server.js must qualify that it is a plain HTTP server, not an MCP SDK server');
});

test('mcp-example: README links to or mentions the real MCP SDK', () => {
    const md = fs.readFileSync(README, 'utf8');
    // Should point readers toward real MCP if that is what they want.
    const mentionsMcpSdk =
        md.includes('modelcontextprotocol') ||
        md.includes('@modelcontextprotocol') ||
        md.includes('mcp sdk') ||
        md.toLowerCase().includes('real mcp') ||
        md.toLowerCase().includes('model context protocol sdk');
    assert.ok(mentionsMcpSdk,
        'examples/mcp/README.md should mention the real MCP SDK so readers know where to look');
});

test('mcp-example: client.js exists and uses arken-client', () => {
    const src = fs.readFileSync(CLIENT_JS, 'utf8');
    assert.ok(src.includes('arken-client') || src.includes('createClient'),
        'client.js must use arken-client');
});

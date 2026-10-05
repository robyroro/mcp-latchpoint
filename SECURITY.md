# Security policy

## Supported versions

Until the first stable release, security fixes are made on the latest `0.x` release and the default branch.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose configuration data, credentials, or files outside an allowed root. Use GitHub's private vulnerability reporting feature on the eventual public repository. If that feature is not available, contact the repository owner privately before sharing details.

Include a minimal reproduction built from synthetic data, the affected version, and the operating system. Do not send real MCP configurations, tokens, home-directory listings, or other private files.

Reasonable reports will be acknowledged when the maintainer is available. A public disclosure timeline should be agreed only after the impact and fix have been checked independently.

## Security boundaries

`mcp-latchpoint` is a static configuration auditor. It must not execute configured commands, install packages, connect to configured endpoints, or return raw configuration through MCP tools. The stdio server's allowed root is a security boundary, including for traversal and symlink resolution.

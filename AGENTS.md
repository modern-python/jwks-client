# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this
repository.

## Project Overview

`jwks-client` is an async client that fetches and caches an identity provider's JSON Web Key Set and
verifies JWTs against it; [`CONTEXT.md`](CONTEXT.md) opens with what it does and owns the
vocabulary — read it before naming a concept in code, a test name, or an issue title.

## Commands

`just` (task runner) and `uv` (package manager). The [`justfile`](justfile) is the source of truth —
`just --list`, or read it.

## Architecture

`jwks_client/client.py` fetches and caches keys, `verifier.py` fixes the claims policy on top, and
`litestar.py` and `fastapi.py` are the optional integrations: they may import their framework, the
core modules never do. Tests drive time through an injected clock and the network through
`httpx2.MockTransport`; never sleep in a test.

## Workflow

Every link in `README.md` must be absolute: `https://github.com/modern-python/<repo>/blob/main/<path>`,
or `.../tree/main/<path>` for a directory. Never a relative path: `README.md` is also the PyPI long
description, and PyPI does not rewrite relative links, so a relative one 404s on the package page.

## Agent skills

### Issue tracker

GitHub issues on `modern-python/jwks-client`, via `gh`. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical roles, each label string equal to its name. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

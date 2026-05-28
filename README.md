# C++ NAT Checker

> RFC-compliant NAT Type Detection for Linux — implementing RFC 3489, RFC 5389, and RFC 5780.

---

## Overview

A lightweight C++ tool that determines your NAT type by speaking STUN across three RFC generations. It handles classic STUN, modern STUN with Magic Cookie, and full NAT behavior discovery — all from a single binary.

---

## Protocol Support

| RFC | Name | Key Features |
|-----|------|--------------|
| [RFC 3489](https://datatracker.ietf.org/doc/html/rfc3489) | Classic STUN | `CHANGE_REQUEST`, `CHANGED_ADDRESS`, `SOURCE_ADDRESS` |
| [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) | Modern STUN | Mandatory Magic Cookie, `XOR-MAPPED-ADDRESS`, `FINGERPRINT` (CRC32) |
| [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780) | NAT Behavior Discovery | Built on RFC 5389 — adds `OTHER-ADDRESS`, `RESPONSE-ORIGIN` |

---

## Detected NAT Types

| NAT Type | Description |
|----------|-------------|
| **Open Internet** | No NAT present |
| **Full Cone NAT** | All external hosts can reach the mapped port |
| **Restricted NAT** | Only hosts the client has sent to can reply |
| **Port Restricted NAT** | Host *and* port must match a prior outbound packet |
| **Symmetric NAT** | Each destination gets a unique mapped port |
| **UDP Blocked** | UDP traffic is not passing through |

---

## Attribution

Portions of this codebase were generated with the assistance of [Claude](https://claude.ai) (Anthropic's AI assistant).

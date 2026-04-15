#!/usr/bin/env python3
"""Generate TON/TOS ecosystem map PDF from structured data (English only)."""
from fpdf import FPDF


class EcoPDF(FPDF):
    def __init__(self):
        super().__init__(orientation="L", unit="mm", format="A3")
        self.set_auto_page_break(auto=False)

    # ── drawing primitives ───────────────────────────────────────
    def _box(self, x, y, w, h, fill, border):
        self.set_fill_color(*fill)
        self.set_draw_color(*border)
        self.set_line_width(0.4)
        self.rect(x, y, w, h, "DF")

    def section(self, x, y, w, h, title, fill=(235, 245, 255)):
        self._box(x, y, w, h, fill, (100, 140, 180))
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(30, 60, 120)
        self.set_xy(x + 3, y + 1.5)
        self.cell(w - 6, 6, title)

    def card(self, x, y, w, h, title, lines,
             fill=(255, 255, 255), border=(160, 180, 210), tc=(40, 80, 140)):
        self._box(x, y, w, h, fill, border)
        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*tc)
        self.set_xy(x + 2, y + 1)
        self.cell(w - 4, 4.5, title)
        self.set_font("Helvetica", "", 6.5)
        self.set_text_color(50, 50, 50)
        for i, ln in enumerate(lines):
            self.set_xy(x + 2.5, y + 6.5 + i * 3.8)
            self.cell(w - 5, 3.5, ln)

    def heading(self, x, y, text, size=10, color=(30, 60, 120)):
        self.set_font("Helvetica", "B", size)
        self.set_text_color(*color)
        self.set_xy(x, y)
        self.cell(0, 6, text)


def build():
    pdf = EcoPDF()
    pdf.add_page()

    # ── Title ────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(20, 50, 100)
    pdf.set_xy(12, 8)
    pdf.cell(0, 10, "TON Ecosystem Tools & Libraries Distribution Map")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(130, 130, 130)
    pdf.set_xy(12, 17)
    pdf.cell(0, 5, "TOS Consolidation View  |  v1.0  |  2026-04  |  Source: ~/tos monorepo")

    # ── Layout constants ─────────────────────────────────────────
    LT = 12       # TON col x
    LR = 215      # TOS col x
    W  = 190      # col width
    Y  = 28

    # Column headers
    pdf.heading(LT + 55, Y, "TON Ecosystem (Fragmented)", 12, (180, 60, 60))
    pdf.heading(LR + 50, Y, "TOS (Consolidated / Monorepo)", 12, (40, 120, 60))
    Y += 10

    # ── Colors ───────────────────────────────────────────────────
    TON_SEC  = (255, 245, 235)
    TON_CARD = (255, 238, 232)
    TON_BDR  = (200, 145, 145)
    TOS_SEC  = (235, 255, 240)
    TOS_CARD = (232, 255, 238)
    TOS_BDR  = (140, 200, 150)
    TOS_TC   = (30, 100, 50)
    RUST_CARD = (230, 242, 255)
    RUST_BDR  = (120, 170, 210)
    RUST_TC   = (30, 70, 130)

    # ═════════════════════════════════════════════════════════════
    # Layer 6 — Wallets & DApps
    # ═════════════════════════════════════════════════════════════
    H = 30
    pdf.section(LT, Y, W, H, "Layer 6 : Wallets & DApps", TON_SEC)
    pdf.card(LT+3, Y+9, 58, 18, "tonweb (JS SDK)",
             ["Independent repo, npm publish", "Version out of sync with node"],
             TON_CARD, TON_BDR)
    pdf.card(LT+64, Y+9, 58, 18, "tonkeeper (Mobile wallet)",
             ["Closed-source, independent dev", "Depends on tonapi.io"],
             TON_CARD, TON_BDR)
    pdf.card(LT+125, Y+9, 62, 18, "ton-connect (Protocol)",
             ["Independent repo & versioning", "Each wallet implements its own"],
             TON_CARD, TON_BDR)

    pdf.section(LR, Y, W, H, "Layer 6 : Wallets & DApps", TOS_SEC)
    pdf.card(LR+3, Y+9, W-6, 18,
             "Compatible with existing wallets -- no SDK changes needed",
             ["Method names aligned with tonweb/toncenter; clients just change URL",
              "New account.capability API for standardized capability discovery"],
             TOS_CARD, TOS_BDR, TOS_TC)
    Y += H + 3

    # ═════════════════════════════════════════════════════════════
    # Layer 5 — SDKs
    # ═════════════════════════════════════════════════════════════
    H = 36
    pdf.section(LT, Y, W, H, "Layer 5 : SDKs & Client Libraries", TON_SEC)
    pdf.card(LT+3,  Y+9, 45, 24, "toncenter-sdk (JS)",
             ["Independent repo", "Depends on toncenter.com", "Version fragmentation"],
             TON_CARD, TON_BDR)
    pdf.card(LT+51, Y+9, 45, 24, "pytoniq (Python)",
             ["Independent repo", "Different maintainer", "Inconsistent API style"],
             TON_CARD, TON_BDR)
    pdf.card(LT+99, Y+9, 45, 24, "tongo (Go)",
             ["Independent repo", "Custom serialization", "Self-managed compat"],
             TON_CARD, TON_BDR)
    pdf.card(LT+147, Y+9, 40, 24, "ton-kotlin (JVM)",
             ["Independent repo", "Update lag", "JVM ecosystem"],
             TON_CARD, TON_BDR)

    pdf.section(LR, Y, W, H, "Layer 5 : SDKs & Client Libraries", TOS_SEC)
    pdf.card(LR+3,  Y+9, 60, 24, "toscenter-rs (Rust)",
             ["Vendored into monorepo", "Supply chain controlled", "Version synced with node"],
             TOS_CARD, TOS_BDR, TOS_TC)
    pdf.card(LR+66, Y+9, 60, 24, "pytosiq_core (Python)",
             ["Vendored into monorepo", "No external dependency", "Unified test coverage"],
             TOS_CARD, TOS_BDR, TOS_TC)
    pdf.card(LR+129, Y+9, 58, 24, "chain-rpc-client (Rust)",
             ["Native Rust RPC client", "Used internally by tosctl", "JSON output support"],
             TOS_CARD, TOS_BDR, TOS_TC)
    Y += H + 3

    # ═════════════════════════════════════════════════════════════
    # Layer 4 — Ops Tooling
    # ═════════════════════════════════════════════════════════════
    H = 46
    pdf.section(LT, Y, W, H, "Layer 4 : Operations Tooling", TON_SEC)
    pdf.card(LT+3,  Y+9, 60, 34, "mytonctrl (Python)",
             ["Independent repo & install", "Python scripts patchwork",
              "Depends on system Python", "No unified config mgmt",
              "No daemon mode", "No built-in alerting"],
             TON_CARD, TON_BDR)
    pdf.card(LT+66, Y+9, 60, 34, "Staking / Election scripts",
             ["Scattered across repos", "Manual validator operations",
              "Each implements own key mgmt", "No alerting integration",
              "Inconsistent documentation"],
             TON_CARD, TON_BDR)
    pdf.card(LT+129, Y+9, 58, 34, "Monitoring & Key mgmt",
             ["Prometheus: self-configured", "Keys: raw files on disk",
              "No Vault integration", "No Telegram alerts",
              "Ops knowledge: tribal"],
             TON_CARD, TON_BDR)

    pdf.section(LR, Y, W, H, "Layer 4 : Operations Tooling", TOS_SEC)
    pdf.card(LR+3, Y+9, W-6, 34,
             "tosctl  --  Rust CLI, single binary, 90 subcommands",
             ["node-control : node management (start/stop/status/logs/config)",
              "elections    : staking/elections (SingleNominator/NominatorPool/Liquid)",
              "contracts    : contract deployment & interaction wrappers",
              "secrets-vault: key management (file + HashiCorp Vault backend)",
              "daemon       : daemon process + Telegram/Webhook alerting",
              "JSON output  : 15 commands support --json, consumable by CI/CD"],
             TOS_CARD, TOS_BDR, TOS_TC)
    Y += H + 3

    # ═════════════════════════════════════════════════════════════
    # Layer 3 — API
    # ═════════════════════════════════════════════════════════════
    H = 46
    pdf.section(LT, Y, W, H, "Layer 3 : API Layer (Query & Submit)", TON_SEC)
    pdf.card(LT+3,  Y+9, 60, 34, "ton-http-api (Python)",
             ["Independent repo / process", "Requires Python runtime",
              "Needs liteserver connection", "Hosted at toncenter.com",
              "Version out of sync with node", "Extra ops maintenance"],
             TON_CARD, TON_BDR)
    pdf.card(LT+66, Y+9, 60, 34, "tonapi.io (Commercial)",
             ["Closed-source, SaaS", "Richer features but paid",
              "Vendor lock-in risk", "Not self-hostable",
              "Different API style"],
             (255, 228, 225), (200, 120, 120))
    pdf.card(LT+129, Y+9, 58, 34, "ton-http-api-cpp (3rd party)",
             ["Third-party C++ implementation", "Independent compile/deploy",
              "Needs liteserver connection", "Extra process to maintain",
              "Maintained outside core team"],
             TON_CARD, TON_BDR)

    pdf.section(LR, Y, W, H, "Layer 3 : API Layer (embedded in validator-engine)", TOS_SEC)
    pdf.card(LR+3, Y+9, W-6, 34,
             "JSON-RPC Server  --  35 methods, embedded, zero external deps",
             ["accounts     : 6 methods  (getAddressInfo/Wallet/Balance/State/TokenData)",
              "blocks       : 8 methods  (getMasterchainInfo/lookupBlock/shards/signatures)",
              "transactions : 5 methods  (getTransactions/tryLocate*/BlockTxExt)",
              "send         : 5 methods  (sendBoc/ReturnHash/NoError/sendQuery/estimateFee)",
              "runmethod + config + utils : 11 methods",
              "REST GET+POST | OpenAPI 3.1 | Prometheus | API Key | Response cache"],
             TOS_CARD, TOS_BDR, TOS_TC)
    Y += H + 3

    # ═════════════════════════════════════════════════════════════
    # Layer 2 — Node / Validator
    # ═════════════════════════════════════════════════════════════
    H = 34
    pdf.section(LT, Y, W, H, "Layer 2 : Node / Validator", TON_SEC)
    pdf.card(LT+3,  Y+9, 90, 22, "validator-engine (C++)",
             ["Independent compile, no embedded API",
              "Must run external API process",
              "Liteserver protocol for lite-client queries"],
             TON_CARD, TON_BDR)
    pdf.card(LT+96, Y+9, 90, 22, "lite-client + validator-engine-console",
             ["CLI query tool + control console",
              "Limited, no batch/automation support"],
             TON_CARD, TON_BDR)

    pdf.section(LR, Y, W, H, "Layer 2 : Node / Validator", TOS_SEC)
    pdf.card(LR+3,  Y+9, 114, 22,
             "validator-engine (C++, embedded JSON-RPC)",
             ["Consensus (Catchain BFT) + block execution + Liteserver",
              "Embedded JSON-RPC -- single process, no external API needed",
              "blockchain-explorer: HTTP block explorer"],
             TOS_CARD, TOS_BDR, TOS_TC)
    pdf.card(LR+120, Y+9, 66, 22, "lite-client + console",
             ["Query tool + control console",
              "tosctl replaces most use cases"],
             TOS_CARD, TOS_BDR, TOS_TC)
    Y += H + 3

    # ═════════════════════════════════════════════════════════════
    # Layer 1 — Protocol & VM
    # ═════════════════════════════════════════════════════════════
    H = 42
    pdf.section(LT, Y, W, H, "Layer 1 : Protocol & VM & Smart Contracts", TON_SEC)
    pdf.card(LT+3,  Y+9, 90, 30, "C++ only",
             ["TVM virtual machine (C++)", "block format (C++)",
              "crypto primitives (C++)", "FunC compiler (C++)",
              "Only C++ impl; other languages need FFI"],
             TON_CARD, TON_BDR)
    pdf.card(LT+96, Y+9, 90, 30, "emulator (C++ FFI)",
             ["Tx emulation requires C++ library call",
              "WASM available but poor performance",
              "Mobile/browser integration difficult",
              "No pure Rust/Go/Python alternative"],
             TON_CARD, TON_BDR)

    pdf.section(LR, Y, W, H, "Layer 1 : Protocol & VM & Smart Contracts", TOS_SEC)
    pdf.card(LR+3,  Y+9, 90, 30,
             "C++ Stack (native)",
             ["crypto/    : cryptographic primitives",
              "vm/        : TVM virtual machine",
              "block/     : block format",
              "emulator/  : transaction emulation",
              "tolk/      : new compiler",
              "catchain/  : consensus protocol"],
             TOS_CARD, TOS_BDR, TOS_TC)
    pdf.card(LR+96, Y+9, 90, 30,
             "Rust Stack (86K lines ported, in tosctl)",
             ["vm/        : TVM interpreter",
              "executor/  : transaction executor",
              "assembler/ : TVM assembler",
              "emulator/  : Rust emulator",
              "block/     : block parsing",
              "sandbox/   : local chain simulator"],
             RUST_CARD, RUST_BDR, RUST_TC)
    Y += H + 3

    # ═════════════════════════════════════════════════════════════
    # Layer 0 — Network
    # ═════════════════════════════════════════════════════════════
    H = 24
    pdf.section(LT, Y, W, H, "Layer 0 : Network Transport", (245, 240, 255))
    pdf.card(LT+3, Y+9, W-6, 12,
             "ADNL + RLDP + DHT  (C++ only)",
             ["Only C++ implementation; no standalone lib for other languages"],
             (242, 238, 255), (170, 150, 200), (80, 60, 130))

    pdf.section(LR, Y, W, H, "Layer 0 : Network Transport", TOS_SEC)
    pdf.card(LR+3, Y+9, W-6, 12,
             "ADNL (C++ + Rust dual impl) + RLDP/RLDP2 + DHT + QUIC + FEC",
             ["Rust ADNL enables tosctl to perform P2P communication independently"],
             TOS_CARD, TOS_BDR, TOS_TC)
    Y += H + 6

    # ═════════════════════════════════════════════════════════════
    # Summary table — page 2
    # ═════════════════════════════════════════════════════════════
    pdf.add_page()
    Y = 15
    pdf.heading(12, Y, "Key Differences Summary", 16, (20, 50, 100))
    Y += 12

    rows = [
        ("Dimension",        "TON Ecosystem",                               "TOS Consolidated"),
        ("API Layer",        "3+ independent projects (toncenter/tonapi/cpp)", "Embedded in validator-engine, single process"),
        ("Ops Tooling",      "mytonctrl (Python) + scattered scripts",       "tosctl (Rust, 90 cmds, single binary)"),
        ("SDKs",             "Each language: independent repo, versions diverge", "Vendored (toscenter-rs/pytosiq), supply chain controlled"),
        ("Virtual Machine",  "C++ only",                                     "C++ + Rust dual-stack (86K lines)"),
        ("Permission Model", "None (wallets guess)",                         "account.capability + role separation (planned)"),
        ("Repo Structure",   "10+ independent repos",                        "1 monorepo"),
        ("Deploy Complexity","Node + API + ops tools deployed separately",   "validator-engine single process + tosctl"),
    ]

    CW = [60, 170, 170]
    for i, (dim, ton, tos) in enumerate(rows):
        x = 12
        rh = 10
        if i == 0:
            pdf.set_fill_color(50, 80, 130)
            pdf.set_font("Helvetica", "B", 10)
        else:
            pdf.set_fill_color(*(245, 248, 255) if i % 2 == 0 else (255, 255, 255))
            pdf.set_font("Helvetica", "", 9)

        # dim column
        pdf.set_xy(x, Y)
        if i == 0:
            pdf.set_text_color(255, 255, 255)
        else:
            pdf.set_text_color(30, 30, 30)
            pdf.set_font("Helvetica", "B", 9)
        pdf.cell(CW[0], rh, dim, border=1, fill=True)

        # TON column
        if i == 0:
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 10)
        else:
            pdf.set_text_color(160, 60, 60)
            pdf.set_font("Helvetica", "", 9)
        pdf.cell(CW[1], rh, ton, border=1, fill=True)

        # TOS column
        if i == 0:
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 10)
        else:
            pdf.set_text_color(40, 120, 60)
            pdf.set_font("Helvetica", "", 9)
        pdf.cell(CW[2], rh, tos, border=1, fill=True)
        Y += rh

    return pdf


if __name__ == "__main__":
    p = build()
    out = "/home/tomi/tos/doc/tos-ecosystem-map.pdf"
    p.output(out)
    print(f"OK -> {out}")

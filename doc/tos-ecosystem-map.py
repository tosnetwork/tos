#!/usr/bin/env python3
"""Generate Legacy/TOS ecosystem map PDF."""

from pathlib import Path

from fpdf import FPDF, XPos, YPos

FONT_REGULAR = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

class EcoPDF(FPDF):
    def __init__(self):
        super().__init__(orientation="L", unit="mm", format="A3")
        self.add_font("Eco", "", FONT_REGULAR)
        self.add_font("Eco", "B", FONT_BOLD)
        self.set_auto_page_break(auto=False)

    # ── drawing helpers ──────────────────────────────────────────────
    def section_box(self, x, y, w, h, title, fill=(235, 245, 255)):
        self.set_fill_color(*fill)
        self.set_draw_color(100, 140, 180)
        self.set_line_width(0.4)
        self.rect(x, y, w, h, "DF")
        self.set_font("Eco", "B", 11)
        self.set_text_color(30, 60, 120)
        self.set_xy(x + 2, y + 1.5)
        self.cell(w - 4, 6, title, new_x=XPos.RIGHT, new_y=YPos.TOP)

    def inner_box(self, x, y, w, h, title, lines, fill=(255, 255, 255),
                  border_color=(160, 180, 210), title_color=(40, 80, 140)):
        self.set_fill_color(*fill)
        self.set_draw_color(*border_color)
        self.set_line_width(0.3)
        self.rect(x, y, w, h, "DF")
        self.set_font("Eco", "B", 8.5)
        self.set_text_color(*title_color)
        self.set_xy(x + 1.5, y + 1)
        self.cell(w - 3, 5, title, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Eco", "", 7.5)
        self.set_text_color(50, 50, 50)
        for i, line in enumerate(lines):
            self.set_xy(x + 2.5, y + 7 + i * 4.2)
            self.cell(w - 5, 4, line, new_x=XPos.RIGHT, new_y=YPos.TOP)

    def arrow_down(self, x, y1, y2):
        self.set_draw_color(120, 120, 120)
        self.set_line_width(0.3)
        self.line(x, y1, x, y2)
        self.line(x, y2, x - 1.5, y2 - 3)
        self.line(x, y2, x + 1.5, y2 - 3)

    def label(self, x, y, text, size=7, color=(100, 100, 100)):
        self.set_font("Eco", "", size)
        self.set_text_color(*color)
        self.set_xy(x, y)
        self.cell(0, 4, text, new_x=XPos.RIGHT, new_y=YPos.TOP)


def build_pdf():
    pdf = EcoPDF()
    pdf.add_page()

    # ── Page title ───────────────────────────────────────────────────
    pdf.set_font("Eco", "B", 18)
    pdf.set_text_color(20, 50, 100)
    pdf.set_xy(10, 8)
    pdf.cell(
        0,
        10,
        "Legacy Ecosystem Tools & Libraries Map  (TOS Comparison / Consolidated View)",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_font("Eco", "", 9)
    pdf.set_text_color(120, 120, 120)
    pdf.set_xy(10, 18)
    pdf.cell(
        0,
        5,
        "Version 1.0  |  Generated from ~/tos monorepo analysis  |  2026-04",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )

    TOP = 28
    LEFT_LEGACY = 12       # source column x
    LEFT_TOS = 215      # TOS column x
    W_LEGACY = 190         # source column width
    W_TOS = 190         # TOS column width

    # Column headers
    pdf.set_font("Eco", "B", 12)
    pdf.set_text_color(180, 60, 60)
    pdf.set_xy(LEFT_LEGACY + 50, TOP)
    pdf.cell(0, 7, "Legacy Ecosystem (Fragmented)", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_text_color(40, 120, 60)
    pdf.set_xy(LEFT_TOS + 55, TOP)
    pdf.cell(0, 7, "TOS Consolidated (Monorepo)", new_x=XPos.RIGHT, new_y=YPos.TOP)

    row_y = TOP + 10

    # ═══════════════════════════════════════════════════════════════
    # Layer 6: Wallets & DApps
    # ═══════════════════════════════════════════════════════════════
    h = 32
    pdf.section_box(LEFT_LEGACY, row_y, W_LEGACY, h,
                    "Layer 6: Wallets & DApps", fill=(255, 245, 235))
    pdf.inner_box(LEFT_LEGACY + 4, row_y + 9, 55, 20, "legacy web SDK",
                  ["Standalone repo, npm release", "Version not synced with node"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_LEGACY + 63, row_y + 9, 55, 20, "Legacy mobile wallet",
                  ["Closed source, independent", "Depends on hosted API"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_LEGACY + 122, row_y + 9, 64, 20, "connect protocol",
                  ["Standalone repo/version", "Each wallet implements its own"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))

    pdf.section_box(LEFT_TOS, row_y, W_TOS, h,
                    "Layer 6: Wallets & DApps", fill=(235, 255, 240))
    pdf.inner_box(LEFT_TOS + 4, row_y + 9, W_TOS - 8, 20,
                  "Compatible with existing wallets -- no SDK changes",
                  ["Method names match legacy web/API; clients only change URL",
                   "New account.capability API for standardized capability discovery"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))

    row_y += h + 4

    # ═══════════════════════════════════════════════════════════════
    # Layer 5: SDK & Client Libraries
    # ═══════════════════════════════════════════════════════════════
    h = 40
    pdf.section_box(LEFT_LEGACY, row_y, W_LEGACY, h,
                    "Layer 5: SDK & Client Libraries", fill=(255, 245, 235))
    pdf.inner_box(LEFT_LEGACY + 4, row_y + 9, 44, 28, "legacy API SDK",
                  ["JS/TS, standalone repo", "Hosted API dependency", "Fragmented versions"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_LEGACY + 52, row_y + 9, 44, 28, "Python SDK",
                  ["Standalone repo", "Different maintainers", "Inconsistent API styles"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_LEGACY + 100, row_y + 9, 44, 28, "Go SDK",
                  ["Standalone repo", "Custom serialization", "Compatibility self-managed"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_LEGACY + 148, row_y + 9, 38, 28, "Kotlin SDK",
                  ["Standalone repo", "Language ecosystem", "Lagging updates"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))

    pdf.section_box(LEFT_TOS, row_y, W_TOS, h,
                    "Layer 5: SDK & Client Libraries", fill=(235, 255, 240))
    pdf.inner_box(LEFT_TOS + 4, row_y + 9, 60, 28, "toscenter-rs (Rust)",
                  ["Vendored into monorepo", "Controlled supply chain", "Node-synced versions"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))
    pdf.inner_box(LEFT_TOS + 68, row_y + 9, 60, 28, "pytosiq_core (Python)",
                  ["Vendored into monorepo", "No external runtime deps", "Unified test coverage"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))
    pdf.inner_box(LEFT_TOS + 132, row_y + 9, 54, 28, "chain-rpc-client",
                  ["Native Rust RPC client", "Used internally by tosctl", "JSON output support"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))

    row_y += h + 4

    # ═══════════════════════════════════════════════════════════════
    # Layer 4: Operations Tools
    # ═══════════════════════════════════════════════════════════════
    h = 48
    pdf.section_box(LEFT_LEGACY, row_y, W_LEGACY, h,
                    "Layer 4: Operations Tools", fill=(255, 245, 235))
    pdf.inner_box(LEFT_LEGACY + 4, row_y + 9, 58, 36, "Legacy ops controller",
                  ["Standalone repo/install", "Ad-hoc Python scripts", "Depends on system Python",
                   "No unified config", "No daemon mode"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_LEGACY + 66, row_y + 9, 58, 36, "Staking/election scripts",
                  ["Scattered across repos", "Manual validator operations", "Key management varies",
                   "No alerting integration", "Inconsistent docs"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_LEGACY + 128, row_y + 9, 58, 36, "Monitoring & Keys",
                  ["Prometheus configured manually", "Key files stored raw on disk", "No Vault integration",
                   "No Telegram alerts", "Ops knowledge is informal"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))

    pdf.section_box(LEFT_TOS, row_y, W_TOS, h,
                    "Layer 4: Operations Tools", fill=(235, 255, 240))
    pdf.inner_box(LEFT_TOS + 4, row_y + 9, W_TOS - 8, 36,
                  "tosctl (Rust CLI, single binary, 90 subcommands)",
                  ["node-control: node management (start/stop/status/logs/config)",
                   "elections: staking/elections/nomination pools (SingleNominator/NominatorPool/Liquid)",
                   "contracts: contract deployment and interaction wrappers",
                   "secrets-vault: key management (files + HashiCorp Vault backend)",
                   "daemon: daemon mode + Telegram/Webhook alerts",
                   "JSON output: 15 commands support --json for CI/CD"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))

    row_y += h + 4

    # ═══════════════════════════════════════════════════════════════
    # Layer 3: API Layer
    # ═══════════════════════════════════════════════════════════════
    h = 50
    pdf.section_box(LEFT_LEGACY, row_y, W_LEGACY, h,
                    "Layer 3: API Layer (Queries & Submission)", fill=(255, 245, 235))
    pdf.inner_box(LEFT_LEGACY + 4, row_y + 9, 58, 38, "HTTP API Service",
                  ["Standalone repo/process", "Requires Python runtime", "Needs liteserver connection",
                   "Hosted API service", "Version not synced with node",
                   "Extra ops maintenance"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_LEGACY + 66, row_y + 9, 58, 38, "Commercial API",
                  ["Closed source, SaaS service", "More features but paid", "Vendor lock-in risk",
                   "Not self-hostable", "API style differs"],
                  fill=(255, 225, 220), border_color=(200, 120, 120))
    pdf.inner_box(LEFT_LEGACY + 128, row_y + 9, 58, 38, "HTTP API C++ Service",
                  ["Third-party C++ implementation", "Separate build/deployment", "Needs liteserver connection",
                   "Extra process", "Maintained outside core team"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))

    pdf.section_box(LEFT_TOS, row_y, W_TOS, h,
                    "Layer 3: API Layer (Embedded in validator-engine)", fill=(235, 255, 240))
    pdf.inner_box(LEFT_TOS + 4, row_y + 9, W_TOS - 8, 38,
                  "JSON-RPC Server (35 methods, embedded, zero external deps)",
                  ["accounts: 6 methods (getAddressInfo/Wallet/Balance/State/TokenData)",
                   "blocks: 8 methods (getMasterchainInfo/lookupBlock/shards/signatures)",
                   "transactions: 5 methods (getTransactions/tryLocate*/BlockTxExt)",
                   "send: 5 methods (sendBoc/ReturnHash/NoError/sendQuery/estimateFee)",
                   "runmethod + config + utils: 8 methods",
                   "REST GET + POST + OpenAPI 3.1 + Prometheus + API Key + cache"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))

    row_y += h + 4

    # ═══════════════════════════════════════════════════════════════
    # Layer 2: Nodes / Validators
    # ═══════════════════════════════════════════════════════════════
    h = 38
    pdf.section_box(LEFT_LEGACY, row_y, W_LEGACY, h,
                    "Layer 2: Nodes / Validators", fill=(255, 245, 235))
    pdf.inner_box(LEFT_LEGACY + 4, row_y + 9, 88, 26, "validator-engine (C++)",
                  ["Standalone build, no embedded API", "External API-layer process required",
                   "liteserver protocol for lite-client queries"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_LEGACY + 96, row_y + 9, 90, 26, "lite-client + console",
                  ["lite-client: command-line query tool", "validator-engine-console: console",
                   "Limited features, no batch/automation support"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))

    pdf.section_box(LEFT_TOS, row_y, W_TOS, h,
                    "Layer 2: Nodes / Validators", fill=(235, 255, 240))
    pdf.inner_box(LEFT_TOS + 4, row_y + 9, 110, 26,
                  "validator-engine (C++, embedded JSON-RPC)",
                  ["Consensus (Catchain BFT) + block execution + Liteserver",
                   "Embedded JSON-RPC -- single process, no external API",
                   "blockchain-explorer: HTTP block explorer"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))
    pdf.inner_box(LEFT_TOS + 118, row_y + 9, 68, 26,
                  "lite-client + console",
                  ["lite-client: query tool", "validator-engine-console: console",
                   "tosctl replaces most use cases"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))

    row_y += h + 4

    # ═══════════════════════════════════════════════════════════════
    # Layer 1: Protocol & VM & Smart Contracts
    # ═══════════════════════════════════════════════════════════════
    h = 45
    pdf.section_box(LEFT_LEGACY, row_y, W_LEGACY, h,
                    "Layer 1: Protocol & VM & Smart Contracts", fill=(255, 245, 235))
    pdf.inner_box(LEFT_LEGACY + 4, row_y + 9, 88, 33, "C++ only",
                  ["TVM virtual machine (C++)", "block format (C++)",
                   "crypto primitives (C++)", "FunC compiler (C++)",
                   "C++ only; other languages need FFI"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_LEGACY + 96, row_y + 9, 90, 33, "emulator (C++ FFI)",
                  ["Transaction simulation requires C++ libs", "WASM build exists but is slow",
                   "Mobile/browser integration is difficult", "No pure Rust/Go/Python alternative"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))

    pdf.section_box(LEFT_TOS, row_y, W_TOS, h,
                    "Layer 1: Protocol & VM & Smart Contracts", fill=(235, 255, 240))
    pdf.inner_box(LEFT_TOS + 4, row_y + 9, 88, 33,
                  "C++ Stack (Native)",
                  ["crypto/ cryptographic primitives", "vm/ TVM virtual machine",
                   "block/ block format", "emulator/ transaction simulation",
                   "tol/ new compiler, catchain/ consensus"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))
    pdf.inner_box(LEFT_TOS + 96, row_y + 9, 90, 33,
                  "Rust Stack (86K-line port inside tosctl)",
                  ["vm/ TVM interpreter", "executor/ transaction executor",
                   "assembler/ TVM assembler", "emulator/ Rust emulator",
                   "block/ block parsing, sandbox/ local-chain simulation"],
                  fill=(220, 245, 255), border_color=(120, 170, 200))

    row_y += h + 4

    # ═══════════════════════════════════════════════════════════════
    # Layer 0: Network Transport
    # ═══════════════════════════════════════════════════════════════
    h = 28
    pdf.section_box(LEFT_LEGACY, row_y, W_LEGACY, h,
                    "Layer 0: Network Transport", fill=(245, 240, 255))
    pdf.inner_box(LEFT_LEGACY + 4, row_y + 9, W_LEGACY - 8, 16, "ADNL + RLDP + DHT (C++ only)",
                  ["Only C++ implementation; no standalone library for other languages"],
                  fill=(240, 235, 255), border_color=(170, 150, 200))

    pdf.section_box(LEFT_TOS, row_y, W_TOS, h,
                    "Layer 0: Network Transport", fill=(235, 255, 240))
    pdf.inner_box(LEFT_TOS + 4, row_y + 9, W_TOS - 8, 16,
                  "ADNL (C++ + Rust implementations) + RLDP/RLDP2 + DHT + QUIC + FEC",
                  ["Rust ADNL implementation lets tosctl perform P2P independently"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))

    row_y += h + 8

    # ═══════════════════════════════════════════════════════════════
    # Summary table
    # ═══════════════════════════════════════════════════════════════
    pdf.set_font("Eco", "B", 13)
    pdf.set_text_color(20, 50, 100)
    pdf.set_xy(12, row_y)
    pdf.cell(0, 8, "Core Differences Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    row_y += 10

    table_data = [
        ("Dimension",     "Legacy Ecosystem",                  "TOS Consolidated"),
        ("API Layer",     "3+ standalone projects (hosted API / commercial API / C++)", "Embedded in validator-engine, single process"),
        ("Operations",    "Legacy Python ops controller + scattered scripts", "tosctl (Rust, 90 commands, single binary)"),
        ("SDK",           "Separate repo per language, independent versions", "vendored (toscenter-rs/pytosiq), controlled supply chain"),
        ("Virtual Machine", "C++ only",                         "C++ + Rust dual stack (86K lines)"),
        ("Permission Model", "None (wallets infer behavior)",   "account.capability + role separation (planned)"),
        ("Repo Structure", "10+ standalone repos",              "1 monorepo"),
        ("Deployment",    "Node + API + ops tools deployed separately", "single validator-engine process + tosctl"),
    ]

    col_widths = [50, 150, 190]
    for i, (dim, legacy, tos_val) in enumerate(table_data):
        x = 12
        if i == 0:
            pdf.set_fill_color(60, 90, 140)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Eco", "B", 9)
        elif i % 2 == 0:
            pdf.set_fill_color(245, 248, 255)
            pdf.set_text_color(40, 40, 40)
            pdf.set_font("Eco", "", 8.5)
        else:
            pdf.set_fill_color(255, 255, 255)
            pdf.set_text_color(40, 40, 40)
            pdf.set_font("Eco", "", 8.5)

        h_row = 7
        pdf.set_xy(x, row_y)
        if i == 0:
            pdf.set_font("Eco", "B", 9)
        else:
            pdf.set_font("Eco", "B", 8.5)
        pdf.cell(col_widths[0], h_row, dim, border=1, fill=True)

        if i == 0:
            pdf.set_font("Eco", "B", 9)
        else:
            pdf.set_font("Eco", "", 8.5)
            pdf.set_text_color(160, 60, 60) if i > 0 else None
        pdf.cell(col_widths[1], h_row, legacy, border=1, fill=True)

        if i > 0:
            pdf.set_text_color(40, 120, 60)
        pdf.cell(col_widths[2], h_row, tos_val, border=1, fill=True)
        row_y += h_row

    return pdf


if __name__ == "__main__":
    pdf = build_pdf()
    out = Path(__file__).resolve().with_name("tos-ecosystem-map.pdf")
    pdf.output(out)
    print(f"PDF saved to {out}")

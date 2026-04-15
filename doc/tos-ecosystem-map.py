#!/usr/bin/env python3
"""Generate TON/TOS ecosystem map PDF with Chinese support."""

from fpdf import FPDF

FONT_PATH = "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf"

class EcoPDF(FPDF):
    def __init__(self):
        super().__init__(orientation="L", unit="mm", format="A3")
        self.add_font("CJK", "", FONT_PATH)
        self.add_font("CJK", "B", FONT_PATH)
        self.set_auto_page_break(auto=False)

    # ── drawing helpers ──────────────────────────────────────────────
    def section_box(self, x, y, w, h, title, fill=(235, 245, 255)):
        self.set_fill_color(*fill)
        self.set_draw_color(100, 140, 180)
        self.set_line_width(0.4)
        self.rect(x, y, w, h, "DF")
        self.set_font("CJK", "B", 11)
        self.set_text_color(30, 60, 120)
        self.set_xy(x + 2, y + 1.5)
        self.cell(w - 4, 6, title, ln=0)

    def inner_box(self, x, y, w, h, title, lines, fill=(255, 255, 255),
                  border_color=(160, 180, 210), title_color=(40, 80, 140)):
        self.set_fill_color(*fill)
        self.set_draw_color(*border_color)
        self.set_line_width(0.3)
        self.rect(x, y, w, h, "DF")
        self.set_font("CJK", "B", 8.5)
        self.set_text_color(*title_color)
        self.set_xy(x + 1.5, y + 1)
        self.cell(w - 3, 5, title, ln=0)
        self.set_font("CJK", "", 7.5)
        self.set_text_color(50, 50, 50)
        for i, line in enumerate(lines):
            self.set_xy(x + 2.5, y + 7 + i * 4.2)
            self.cell(w - 5, 4, line, ln=0)

    def arrow_down(self, x, y1, y2):
        self.set_draw_color(120, 120, 120)
        self.set_line_width(0.3)
        self.line(x, y1, x, y2)
        self.line(x, y2, x - 1.5, y2 - 3)
        self.line(x, y2, x + 1.5, y2 - 3)

    def label(self, x, y, text, size=7, color=(100, 100, 100)):
        self.set_font("CJK", "", size)
        self.set_text_color(*color)
        self.set_xy(x, y)
        self.cell(0, 4, text, ln=0)


def build_pdf():
    pdf = EcoPDF()
    pdf.add_page()

    # ── Page title ───────────────────────────────────────────────────
    pdf.set_font("CJK", "B", 18)
    pdf.set_text_color(20, 50, 100)
    pdf.set_xy(10, 8)
    pdf.cell(0, 10, "TON 生态工具 & 库分布全景图  (TOS 对照 / 整合视图)", ln=1)
    pdf.set_font("CJK", "", 9)
    pdf.set_text_color(120, 120, 120)
    pdf.set_xy(10, 18)
    pdf.cell(0, 5, "Version 1.0  |  Generated from ~/tos monorepo analysis  |  2026-04", ln=1)

    TOP = 28
    LEFT_TON = 12       # TON column x
    LEFT_TOS = 215      # TOS column x
    W_TON = 190         # TON column width
    W_TOS = 190         # TOS column width

    # Column headers
    pdf.set_font("CJK", "B", 12)
    pdf.set_text_color(180, 60, 60)
    pdf.set_xy(LEFT_TON + 50, TOP)
    pdf.cell(0, 7, "TON 生态 (分散)", ln=0)
    pdf.set_text_color(40, 120, 60)
    pdf.set_xy(LEFT_TOS + 55, TOP)
    pdf.cell(0, 7, "TOS 整合 (Monorepo)", ln=0)

    row_y = TOP + 10

    # ═══════════════════════════════════════════════════════════════
    # Layer 6: 钱包 & DApp
    # ═══════════════════════════════════════════════════════════════
    h = 32
    pdf.section_box(LEFT_TON, row_y, W_TON, h,
                    "Layer 6: 钱包 & DApp", fill=(255, 245, 235))
    pdf.inner_box(LEFT_TON + 4, row_y + 9, 55, 20, "tonweb (JS SDK)",
                  ["独立仓库, npm 发布", "版本与节点不同步"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_TON + 63, row_y + 9, 55, 20, "tonkeeper (移动钱包)",
                  ["闭源, 独立开发", "API 依赖 tonapi.io"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_TON + 122, row_y + 9, 64, 20, "ton-connect (协议)",
                  ["独立仓库, 独立版本", "钱包各自实现"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))

    pdf.section_box(LEFT_TOS, row_y, W_TOS, h,
                    "Layer 6: 钱包 & DApp", fill=(235, 255, 240))
    pdf.inner_box(LEFT_TOS + 4, row_y + 9, W_TOS - 8, 20,
                  "兼容现有钱包 — 无需修改 SDK",
                  ["方法名与 tonweb/toncenter 对齐, 客户端只需换 URL",
                   "新增 account.capability API 提供标准化能力发现"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))

    row_y += h + 4

    # ═══════════════════════════════════════════════════════════════
    # Layer 5: SDK & 客户端库
    # ═══════════════════════════════════════════════════════════════
    h = 40
    pdf.section_box(LEFT_TON, row_y, W_TON, h,
                    "Layer 5: SDK & 客户端库", fill=(255, 245, 235))
    pdf.inner_box(LEFT_TON + 4, row_y + 9, 44, 28, "toncenter-sdk",
                  ["JS/TS, 独立仓库", "依赖 toncenter.com", "版本碎片化"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_TON + 52, row_y + 9, 44, 28, "pytoniq (Python)",
                  ["独立仓库", "维护者不同", "API 风格不统一"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_TON + 100, row_y + 9, 44, 28, "tongo (Go)",
                  ["独立仓库", "自定义序列化", "兼容性自行保证"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_TON + 148, row_y + 9, 38, 28, "ton-kotlin",
                  ["独立仓库", "JVM 生态", "更新滞后"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))

    pdf.section_box(LEFT_TOS, row_y, W_TOS, h,
                    "Layer 5: SDK & 客户端库", fill=(235, 255, 240))
    pdf.inner_box(LEFT_TOS + 4, row_y + 9, 60, 28, "toscenter-rs (Rust)",
                  ["vendored 进 monorepo", "供应链可控", "版本与节点同步"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))
    pdf.inner_box(LEFT_TOS + 68, row_y + 9, 60, 28, "pytosiq_core (Python)",
                  ["vendored 进 monorepo", "直接使用不外部依赖", "测试覆盖统一"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))
    pdf.inner_box(LEFT_TOS + 132, row_y + 9, 54, 28, "chain-rpc-client",
                  ["原生 Rust RPC 客户端", "tosctl 内部使用", "JSON 输出支持"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))

    row_y += h + 4

    # ═══════════════════════════════════════════════════════════════
    # Layer 4: 运维工具
    # ═══════════════════════════════════════════════════════════════
    h = 48
    pdf.section_box(LEFT_TON, row_y, W_TON, h,
                    "Layer 4: 运维工具", fill=(255, 245, 235))
    pdf.inner_box(LEFT_TON + 4, row_y + 9, 58, 36, "mytonctrl (Python)",
                  ["独立仓库, 独立安装", "Python 脚本拼凑", "依赖系统 Python 环境",
                   "无统一配置管理", "无守护进程模式"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_TON + 66, row_y + 9, 58, 36, "质押/选举脚本",
                  ["散落在多个仓库", "validator 操作手动", "密钥管理各自实现",
                   "无告警集成", "文档不一致"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_TON + 128, row_y + 9, 58, 36, "监控 & 密钥",
                  ["Prometheus 需自己配", "密钥文件裸存磁盘", "无 Vault 集成",
                   "无 Telegram 告警", "运维经验口口相传"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))

    pdf.section_box(LEFT_TOS, row_y, W_TOS, h,
                    "Layer 4: 运维工具", fill=(235, 255, 240))
    pdf.inner_box(LEFT_TOS + 4, row_y + 9, W_TOS - 8, 36,
                  "tosctl (Rust CLI, 单二进制, 90 个子命令)",
                  ["node-control: 节点管理 (启动/停止/状态/日志/配置)",
                   "elections: 质押/选举/提名池 (SingleNominator/NominatorPool/Liquid)",
                   "contracts: 合约部署与交互封装",
                   "secrets-vault: 密钥管理 (文件 + HashiCorp Vault 后端)",
                   "daemon: 守护进程 + Telegram/Webhook 告警",
                   "JSON 输出: 15 个命令支持 --json, 可被 CI/CD 消费"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))

    row_y += h + 4

    # ═══════════════════════════════════════════════════════════════
    # Layer 3: API 层
    # ═══════════════════════════════════════════════════════════════
    h = 50
    pdf.section_box(LEFT_TON, row_y, W_TON, h,
                    "Layer 3: API 层 (查询 & 提交)", fill=(255, 245, 235))
    pdf.inner_box(LEFT_TON + 4, row_y + 9, 58, 38, "ton-http-api (Python)",
                  ["独立仓库/进程", "需要 Python 运行时", "需连接 liteserver",
                   "toncenter.com 托管", "版本与节点不同步",
                   "运维需额外维护"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_TON + 66, row_y + 9, 58, 38, "tonapi.io (商业)",
                  ["闭源, SaaS 服务", "功能更丰富但收费", "供应商锁定风险",
                   "不可自托管", "API 风格不同于其他"],
                  fill=(255, 225, 220), border_color=(200, 120, 120))
    pdf.inner_box(LEFT_TON + 128, row_y + 9, 58, 38, "ton-http-api-cpp",
                  ["第三方 C++ 实现", "独立编译/部署", "需连接 liteserver",
                   "额外进程", "维护独立于核心团队"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))

    pdf.section_box(LEFT_TOS, row_y, W_TOS, h,
                    "Layer 3: API 层 (内嵌于 validator-engine)", fill=(235, 255, 240))
    pdf.inner_box(LEFT_TOS + 4, row_y + 9, W_TOS - 8, 38,
                  "JSON-RPC Server (35 个方法, 内嵌, 零外部依赖)",
                  ["accounts: 6 个方法 (getAddressInfo/Wallet/Balance/State/TokenData)",
                   "blocks: 8 个方法 (getMasterchainInfo/lookupBlock/shards/signatures)",
                   "transactions: 5 个方法 (getTransactions/tryLocate*/BlockTxExt)",
                   "send: 5 个方法 (sendBoc/ReturnHash/NoError/sendQuery/estimateFee)",
                   "runmethod + config + utils: 8 个方法",
                   "REST GET + POST + OpenAPI 3.1 + Prometheus + API Key + 缓存"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))

    row_y += h + 4

    # ═══════════════════════════════════════════════════════════════
    # Layer 2: 节点/验证器
    # ═══════════════════════════════════════════════════════════════
    h = 38
    pdf.section_box(LEFT_TON, row_y, W_TON, h,
                    "Layer 2: 节点 / 验证器", fill=(255, 245, 235))
    pdf.inner_box(LEFT_TON + 4, row_y + 9, 88, 26, "validator-engine (C++)",
                  ["独立编译, 无内嵌 API", "必须外挂 API 层进程",
                   "liteserver 协议供 lite-client 查询"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_TON + 96, row_y + 9, 90, 26, "lite-client + console",
                  ["lite-client: 命令行查询工具", "validator-engine-console: 控制台",
                   "功能有限, 无批量/自动化支持"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))

    pdf.section_box(LEFT_TOS, row_y, W_TOS, h,
                    "Layer 2: 节点 / 验证器", fill=(235, 255, 240))
    pdf.inner_box(LEFT_TOS + 4, row_y + 9, 110, 26,
                  "validator-engine (C++, 内嵌 JSON-RPC)",
                  ["共识 (Catchain BFT) + 区块执行 + Liteserver",
                   "内嵌 JSON-RPC — 单进程, 无需外挂 API",
                   "blockchain-explorer: HTTP 区块浏览器"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))
    pdf.inner_box(LEFT_TOS + 118, row_y + 9, 68, 26,
                  "lite-client + console",
                  ["lite-client: 查询工具", "validator-engine-console: 控制台",
                   "tosctl 替代大部分使用场景"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))

    row_y += h + 4

    # ═══════════════════════════════════════════════════════════════
    # Layer 1: 协议 & VM & 智能合约
    # ═══════════════════════════════════════════════════════════════
    h = 45
    pdf.section_box(LEFT_TON, row_y, W_TON, h,
                    "Layer 1: 协议 & 虚拟机 & 智能合约", fill=(255, 245, 235))
    pdf.inner_box(LEFT_TON + 4, row_y + 9, 88, 33, "C++ only",
                  ["TVM 虚拟机 (C++)", "block 区块格式 (C++)",
                   "crypto 密码学 (C++)", "FunC 编译器 (C++)",
                   "只有 C++ 实现, 其他语言需 FFI"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))
    pdf.inner_box(LEFT_TON + 96, row_y + 9, 90, 33, "emulator (C++ FFI)",
                  ["交易模拟需调用 C++ 库", "WASM 编译可用但性能差",
                   "移动端/浏览器集成困难", "没有纯 Rust/Go/Python 替代"],
                  fill=(255, 235, 230), border_color=(200, 140, 140))

    pdf.section_box(LEFT_TOS, row_y, W_TOS, h,
                    "Layer 1: 协议 & 虚拟机 & 智能合约", fill=(235, 255, 240))
    pdf.inner_box(LEFT_TOS + 4, row_y + 9, 88, 33,
                  "C++ 栈 (原生)",
                  ["crypto/ 密码学原语", "vm/ TVM 虚拟机",
                   "block/ 区块格式", "emulator/ 交易模拟",
                   "tolk/ 新编译器, catchain/ 共识"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))
    pdf.inner_box(LEFT_TOS + 96, row_y + 9, 90, 33,
                  "Rust 栈 (86K 行移植, tosctl 内)",
                  ["vm/ TVM 解释器", "executor/ 交易执行器",
                   "assembler/ TVM 汇编器", "emulator/ Rust 模拟器",
                   "block/ 区块解析, sandbox/ 本地链模拟"],
                  fill=(220, 245, 255), border_color=(120, 170, 200))

    row_y += h + 4

    # ═══════════════════════════════════════════════════════════════
    # Layer 0: 网络传输
    # ═══════════════════════════════════════════════════════════════
    h = 28
    pdf.section_box(LEFT_TON, row_y, W_TON, h,
                    "Layer 0: 网络传输", fill=(245, 240, 255))
    pdf.inner_box(LEFT_TON + 4, row_y + 9, W_TON - 8, 16, "ADNL + RLDP + DHT (C++ only)",
                  ["只有 C++ 实现, 无独立库可供其他语言使用"],
                  fill=(240, 235, 255), border_color=(170, 150, 200))

    pdf.section_box(LEFT_TOS, row_y, W_TOS, h,
                    "Layer 0: 网络传输", fill=(235, 255, 240))
    pdf.inner_box(LEFT_TOS + 4, row_y + 9, W_TOS - 8, 16,
                  "ADNL (C++ + Rust 双实现) + RLDP/RLDP2 + DHT + QUIC + FEC",
                  ["Rust ADNL 实现使 tosctl 可独立进行 P2P 通信"],
                  fill=(230, 255, 235), border_color=(140, 200, 150))

    row_y += h + 8

    # ═══════════════════════════════════════════════════════════════
    # Summary table
    # ═══════════════════════════════════════════════════════════════
    pdf.set_font("CJK", "B", 13)
    pdf.set_text_color(20, 50, 100)
    pdf.set_xy(12, row_y)
    pdf.cell(0, 8, "核心差异总结", ln=1)
    row_y += 10

    table_data = [
        ("维度",          "TON 生态",                          "TOS 整合"),
        ("API 层",        "3+ 独立项目 (toncenter/tonapi/cpp)", "内嵌 validator-engine, 单进程"),
        ("运维工具",      "mytonctrl (Python) + 散落脚本",      "tosctl (Rust, 90 命令, 单二进制)"),
        ("SDK",           "每种语言独立仓库, 版本各自为政",      "vendored (toscenter-rs/pytosiq), 供应链可控"),
        ("虚拟机",        "只有 C++",                           "C++ + Rust 双栈 (86K 行)"),
        ("权限模型",      "无 (钱包自己猜)",                    "account.capability + 角色分离 (规划中)"),
        ("仓库结构",      "10+ 独立仓库",                       "1 个 monorepo"),
        ("部署复杂度",    "节点 + API + 运维工具分别部署",       "validator-engine 单进程 + tosctl"),
    ]

    col_widths = [50, 150, 190]
    for i, (dim, ton, tos_val) in enumerate(table_data):
        x = 12
        if i == 0:
            pdf.set_fill_color(60, 90, 140)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("CJK", "B", 9)
        elif i % 2 == 0:
            pdf.set_fill_color(245, 248, 255)
            pdf.set_text_color(40, 40, 40)
            pdf.set_font("CJK", "", 8.5)
        else:
            pdf.set_fill_color(255, 255, 255)
            pdf.set_text_color(40, 40, 40)
            pdf.set_font("CJK", "", 8.5)

        h_row = 7
        pdf.set_xy(x, row_y)
        if i == 0:
            pdf.set_font("CJK", "B", 9)
        else:
            pdf.set_font("CJK", "B", 8.5)
        pdf.cell(col_widths[0], h_row, dim, border=1, fill=True)

        if i == 0:
            pdf.set_font("CJK", "B", 9)
        else:
            pdf.set_font("CJK", "", 8.5)
            pdf.set_text_color(160, 60, 60) if i > 0 else None
        pdf.cell(col_widths[1], h_row, ton, border=1, fill=True)

        if i > 0:
            pdf.set_text_color(40, 120, 60)
        pdf.cell(col_widths[2], h_row, tos_val, border=1, fill=True)
        row_y += h_row

    return pdf


if __name__ == "__main__":
    pdf = build_pdf()
    out = "/home/tomi/tos/doc/ton-ecosystem-map.pdf"
    pdf.output(out)
    print(f"PDF saved to {out}")

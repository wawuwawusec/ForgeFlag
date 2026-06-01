# ForgeFlag 协作规则

这份文档约定多台电脑、多个 Codex 会话或多人一起开发 ForgeFlag 时的基本流程。目标是让大家可以并行推进功能，同时尽量避免覆盖彼此的代码。

## 基本原则

- 不要多端同时直接修改并推送 `main`。
- 每个功能、修复或实验都使用独立分支。
- 开始写代码前先同步远端。
- 推送前先跑测试，并确认本地工作区只包含本次任务的改动。
- 如果远端已经有新提交，先 rebase 或 merge，再继续开发。

## 分支命名

推荐使用能看出任务范围的分支名：

```bash
codex/<功能名>
feat/<功能名>
fix/<问题名>
docs/<文档名>
```

示例：

```bash
codex/collaboration-guide
feat/web-ui
feat/solver-traffic-scapy
fix/llm-config-error
docs/tooling-notes
```

## 开始工作前

每次继续开发前，先检查远端和本地状态：

```bash
git fetch origin
git status --branch --short
git log --oneline --decorate -5
```

如果当前工作基于 `main`，先更新本地 `main`：

```bash
git checkout main
git pull --rebase origin main
```

然后创建或切换到任务分支：

```bash
git checkout -b codex/<功能名>
```

如果分支已经存在：

```bash
git checkout codex/<功能名>
git rebase main
```

## 提交前检查

提交前至少跑一次本地 smoke test：

```bash
make smoke
```

改动范围较大，或触碰共享模块时，跑完整测试：

```bash
.venv/bin/python -m unittest discover -s tests
```

提交前检查本次改动：

```bash
git status --short
git diff
```

## 推送流程

推送前再同步一次远端，确认没有新的 `main` 提交落后：

```bash
git fetch origin
git checkout main
git pull --rebase origin main
git checkout -
git rebase main
```

如果测试通过，提交并推送任务分支：

```bash
git add <files>
git commit -m "简短描述本次修改"
git push -u origin <branch>
```

然后在 GitHub 上开 Pull Request 合并到 `main`。

## 冲突处理原则

- 不使用 `git reset --hard`、`git checkout -- <file>` 或强推来处理不确定的冲突，除非明确知道会丢弃什么。
- 冲突文件先读懂双方改动，再合并。
- 如果另一台电脑正在改同一块功能，先沟通任务边界，再继续。
- 冲突解决后重新跑相关测试。

常见冲突处理流程：

```bash
git fetch origin
git rebase origin/main
# 解决冲突
git status --short
git add <resolved-files>
git rebase --continue
make smoke
```

## 容易冲突的目录

这些路径经常被多个功能同时触碰，开工前最好先确认另一台电脑是否也在改：

- `src/forgeflag/solvers/*`
- `src/forgeflag/tools/*`
- `src/forgeflag/webapp.py`
- `src/forgeflag/manager.py`
- `src/forgeflag/notebook.py`
- `docs/codex-handoff.md`
- `README.md`
- `tests/test_*.py`

## 功能拆分建议

并行开发时尽量按模块拆分任务：

- WebSolver / `ffuf` 路径发现
- Crypto / RSA / hash workflows
- Traffic / Scapy / PCAP workflows
- Web UI
- MCP wrappers
- Forensics / archive / image stego
- Pwn / Reverse / IDA MCP

如果两台电脑都要做 solver，优先分配到不同 solver 或不同工具 wrapper。必须改同一模块时，先让其中一边完成并推送，再由另一边拉取后继续。

## 本机 Web UI 协作访问

本机默认 Web UI 只监听 `127.0.0.1`，另一台电脑或手机无法访问。需要局域网访问时，用：

```bash
FORGEFLAG_WEB_HOST=0.0.0.0 FORGEFLAG_WEB_PORT=8080 scripts/forgeflag-control restart
```

同一 Wi-Fi 下访问运行机器的局域网 IP，例如：

```text
http://192.168.1.7:8080/
```

如果访问失败，检查两台设备是否在同一网络，以及 macOS 防火墙是否允许 Python 或终端接受入站连接。

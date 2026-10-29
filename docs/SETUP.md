# PrivacyLens: manual setup for both laptops

Do everything in this file **before** you run any prompt. It takes about 1–2 hours the first time, mostly downloads.

## How the work is split

| | **LNX** (Linux Mint, 8 GB RAM) | **WIN** (Windows, 32 GB RAM, 8 GB VRAM) |
|---|---|---|
| Why | Native Linux kernel: the reference for gVisor, eBPF, `memfd_secret`. Little RAM, so light-compute work. | Lots of RAM and GPU: models, training, local LLM, big evaluation runs. |
| Builds | Isolation and platform, `vault`, `gate`, `ledger`, the `core` shell (Chrome, capture, actuator), crypto, the whole dashboard (Tauri, X-ray mode) | Detection + sanitization inside `core`, Fourier, the `agent`, scenario pages, synthetic data, training, evolved attacks, RAG, Gromov–Wasserstein, evaluation |

**The conflict problem is solved by making both laptops the same:** Windows runs everything inside WSL2 (a real Linux kernel), both machines use Docker Engine + gVisor, and every build runs in the same pinned container. On top of that, every file in the repo has exactly one owner machine, enforced by a git hook, so the two Claude sessions can never edit the same file.

Repo: **https://github.com/PECathon-2026/Team-PF-HUTJS9** (public, empty until Part E).

## Order to follow

You can do both laptops at the same time, except Windows must wait for Mint's Part E before cloning.

**Mint laptop**
1. Part B (B1–B7)
2. Part C (Docker, gVisor, NVIDIA toolkit)
3. Part D (GitHub login, git settings, secrets folder, Hugging Face)
4. Part E (unzip the bootstrap and push it)

**Windows laptop**
1. Part A, steps A1–A8
2. Part C (inside WSL Ubuntu)
3. Part D (inside WSL Ubuntu)
4. **Wait until Mint has finished Part E**, then A9 (clone) and A10

Then Part F tells you how to start Claude on each laptop.

---

## Part A: Windows laptop (WIN)

Run PowerShell commands in **PowerShell as Administrator**. Run Linux commands inside the **Ubuntu** terminal.

### A1. Before you start
1. **Virtualization on:** Task Manager → Performance → CPU → "Virtualization: Enabled". If it says Disabled, enable Intel VT-x in the BIOS.
2. **Uninstall Docker Desktop** if you have it (Settings → Apps). It conflicts with Docker Engine inside WSL.
3. **NVIDIA driver:** install the latest Windows driver from nvidia.com (or the NVIDIA app). Never install an NVIDIA driver inside WSL; WSL uses the Windows one.

### A2. Install WSL2 with Ubuntu 24.04 (PowerShell, admin)
```powershell
wsl --install -d Ubuntu-24.04
wsl --update
```
Reboot if asked. Open "Ubuntu 24.04" from the Start menu and create your Linux username and password.

### A3. Give WSL enough memory
In PowerShell (normal, not admin), run `notepad "$env:USERPROFILE\.wslconfig"`, let it create the file, and paste:
```ini
[wsl2]
memory=24GB
swap=8GB
```
Save and close. (Opening it this way avoids Notepad saving it as `.wslconfig.txt`, which WSL would ignore.) Then in PowerShell: `wsl --shutdown`, and reopen Ubuntu. Check it worked inside Ubuntu with `free -g` (total should be about 23–24).

### A4. Enable systemd inside WSL (Ubuntu terminal)
```bash
cat /etc/wsl.conf
```
Ubuntu 24.04 usually has `systemd=true` already. If it doesn't, **append** it (don't overwrite the file; it may hold your default-user setting):
```bash
grep -q '^systemd=true' /etc/wsl.conf || printf '\n[boot]\nsystemd=true\n' | sudo tee -a /etc/wsl.conf
```
Then `wsl --shutdown` in PowerShell and reopen Ubuntu. Check: `systemctl is-system-running` should print `running` or `degraded` (both are fine).

### A5. Base packages (Ubuntu)
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git make curl wget ca-certificates gnupg build-essential jq unzip
```

### A6. Docker Engine, gVisor, NVIDIA Container Toolkit
Do **Part C** (it's identical on both laptops), then come back.

### A7. Check the GPU is visible in WSL
```bash
nvidia-smi
docker run --rm --gpus all ubuntu:24.04 nvidia-smi
```
Both should show your GPU.

### A8. Claude Code inside WSL
Your current Claude Code runs on the Windows side. For this project, install it **inside Ubuntu**:
```bash
curl -fsSL https://claude.ai/install.sh | bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
claude --version
```

### A9. VS Code connected to WSL
1. In VS Code on Windows, install the **WSL** extension (by Microsoft).
2. Your existing Windows clone of the repo: if it has unpushed changes, push them first. Then rename that folder (e.g. `Team-PF-HUTJS9-OLD-DO-NOT-USE`) so you never open it by mistake. **Never use it again.**
3. Clone inside WSL, **after** the bootstrap commit in Part E is pushed (the repo is empty until then):
   ```bash
   cd ~
   git clone https://github.com/PECathon-2026/Team-PF-HUTJS9.git
   cd Team-PF-HUTJS9
   code .
   ```
   VS Code opens with "WSL: Ubuntu-24.04" in the bottom-left corner. Always open the project this way.

### A10. Tell Claude which machine this is
```bash
cd ~/Team-PF-HUTJS9
echo WIN > .pl-machine
```

---

## Part B: Linux Mint laptop (LNX)

### B1. Update and NVIDIA driver
```bash
sudo apt update && sudo apt upgrade -y
```
Open **Driver Manager**, select the recommended NVIDIA proprietary driver, apply, reboot. Then:
```bash
nvidia-smi
```

### B2. Base packages
```bash
sudo apt install -y git make curl wget ca-certificates gnupg build-essential jq unzip file
```

### B3. Compressed RAM swap (important with 8 GB)
zram adds swap that lives in compressed RAM, not on disk.
```bash
sudo apt install -y zram-tools
printf 'ALGO=zstd\nPERCENT=50\n' | sudo tee /etc/default/zramswap
sudo systemctl restart zramswap
swapon --show
```

### B4. Docker Engine, gVisor, NVIDIA Container Toolkit
Do **Part C**, then come back.

### B5. Dashboard toolchain (Tauri v2: Rust + Node)
```bash
sudo apt install -y libwebkit2gtk-4.1-dev libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
source ~/.bashrc
nvm install 22
corepack enable
rustc --version && node --version && pnpm --version
```

### B6. Kernel features check
```bash
uname -r
ls /sys/kernel/btf/vmlinux && echo "BTF ok"
sudo aa-status | head -3
```
Just note the output; the LNX prompt's capability probe handles anything missing.

### B7. Claude Code and the repo
Claude Code is already installed: run `claude update`. Your repo is already cloned (it's still empty, which is fine):
```bash
cd ~/Team-PF-HUTJS9
echo LNX > .pl-machine
```

---

## Part C: Docker Engine + gVisor + NVIDIA toolkit (same on both laptops)

Run on **Mint** and inside **WSL Ubuntu**.

### C1. Remove conflicting packages
```bash
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove -y $pkg; done
```

### C2. Docker Engine
```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
```
Log out and back in (WSL: `wsl --shutdown` in PowerShell, reopen Ubuntu). Then:
```bash
docker run --rm hello-world
```

### C3. gVisor
```bash
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc
sudo runsc install
sudo systemctl restart docker
docker run --rm --runtime=runsc hello-world
```

### C4. NVIDIA Container Toolkit
```bash
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker
```

### C5. Verify both runtimes are registered
```bash
cat /etc/docker/daemon.json
```
It must list **both** `runsc` and `nvidia` under `"runtimes"`. If one is missing, re-run its configure command (C3 `runsc install` or C4 `nvidia-ctk`), then `sudo systemctl restart docker`.

```bash
docker run --rm --runtime=runsc hello-world
docker run --rm --gpus all ubuntu:24.04 nvidia-smi
docker compose version
```
If `runsc hello-world` fails inside WSL, note the error and continue; WIN's Phase 0/2 deals with it.

---

## Part D: Accounts and tokens

### D1. GitHub CLI (both laptops)
```bash
sudo mkdir -p -m 755 /etc/apt/keyrings
wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null
sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update && sudo apt install -y gh
gh auth login          # GitHub.com → HTTPS → login with browser
gh auth setup-git
```

### D2. Git settings (both laptops)
```bash
git config --global user.name "Rajvir Singh"
git config --global user.email "<the email on your GitHub account>"
git config --global pull.rebase true
git config --global rebase.autoStash true
git config --global core.autocrlf false
git config --global init.defaultBranch main
```

### D3. Private secrets folder (both laptops)
```bash
mkdir -p ~/.privacylens/secrets ~/.privacylens/keys
chmod 700 ~/.privacylens ~/.privacylens/secrets ~/.privacylens/keys
```

### D4. Hugging Face (both laptops)
Some pretrained models (Prompt Guard especially) are downloaded from their original source instead of being re-published in your public repo, so both laptops need the token.
1. Create a free account at huggingface.co (one account is enough for both laptops).
2. Open the **meta-llama/Llama-Prompt-Guard-2-86M** model page and accept Meta's license (approval can take a while; do it early).
3. Settings → Access Tokens → create a **read** token. On **each** laptop, save it without it appearing in your shell history:
   ```bash
   read -rsp "HF token: " T && printf '%s' "$T" > ~/.privacylens/secrets/hf_token && unset T && chmod 600 ~/.privacylens/secrets/hf_token && echo
   ```

### D5. Anthropic API key (optional)
Only if you want the cloud AI lane as well as local Ollama. It costs money per request; everything works without it.
```bash
read -rsp "Anthropic API key: " T && printf '%s' "$T" > ~/.privacylens/secrets/anthropic_api_key && unset T && chmod 600 ~/.privacylens/secrets/anthropic_api_key && echo
```

### D6. Branch protection (optional, needs repo admin)
GitHub → repo → Settings → Branches → add a rule for `main`: require a pull request and require status checks to pass. The git hook and CI already enforce the rules; this is an extra safety net.

---

## Part E: The bootstrap commit (do this once, on the Mint laptop)

The GitHub repo is currently **empty** and **public**. This first commit creates `main`. It's the only time anyone commits to `main` directly.

Because the repo is public, everything you push (code, results, release assets) is visible to anyone. The rules already keep secrets and real data out; just never paste a token into a file in the repo.

1. Download `privacylens-bootstrap.zip` to `~/Downloads` on the Mint laptop.
2. Make sure your Mint clone points at the right repo:
   ```bash
   cd ~/Team-PF-HUTJS9 && git remote -v
   ```
   Both lines must show `https://github.com/PECathon-2026/Team-PF-HUTJS9.git`. If they show anything else:
   ```bash
   git remote set-url origin https://github.com/PECathon-2026/Team-PF-HUTJS9.git
   ```
   If `~/Team-PF-HUTJS9` doesn't exist at all: `cd ~ && git clone https://github.com/PECathon-2026/Team-PF-HUTJS9.git`, then `cd Team-PF-HUTJS9 && echo LNX > .pl-machine`.
3. Unzip it into the repo root:
   ```bash
   cd ~/Team-PF-HUTJS9
   unzip -o ~/Downloads/privacylens-bootstrap.zip -d .
   ls -A    # you should see .claude .git .gitattributes .gitignore .pl-machine CLAUDE.md docs
   ```
   The zip contains `CLAUDE.md`, `docs/PrivacyLens_Features.md` (your latest spec), `docs/SETUP.md` (this file), `docs/prompts/{SHARED,WIN,LNX}.md`, `.gitattributes`, `.gitignore` and `.claude/settings.json`.
4. If you have `pl_fourier.py` (the Fourier module with 21 tests), copy it in now:
   ```bash
   mkdir -p ml/reference && cp /path/to/pl_fourier.py ml/reference/
   ```
5. Commit and push:
   ```bash
   git add -A
   git status            # check: .pl-machine is NOT listed, no secrets, no big files
   git commit -m "Bootstrap: spec, Claude Code prompts, repo rules"
   git branch -M main
   git push -u origin main
   ```
6. Now do Part A9 step 3 on the **Windows laptop** (clone inside WSL), then A10.

---

## Part F: Running the build

### Starting Claude Code
On each laptop, open the repo in VS Code (on Windows: from the WSL Ubuntu terminal, `cd ~/Team-PF-HUTJS9 && code .`), open the terminal and run:
```bash
claude --model opus
```
(or start `claude` and pick Opus with `/model`). Accept the "trust this folder" prompt. Then type the commands below exactly.

### Run order
"Both" means run on each laptop at the same time.

| # | LNX (Mint) | WIN (Windows / WSL) |
|---|---|---|
| 1 | `Run Phase 0` | wait for LNX to finish |
| 2 | — | `Run Phase 0` |
| 3 | `Run Gate 0` | `Run Gate 0` |
| 4 | `Run Phase 1` | `Run Phase 1` |
| 5 | `Run Gate 1` | `Run Gate 1` |
| 6 | `Run Phase 2` | `Run Phase 2` |
| 7 | `Run Gate 2` | `Run Gate 2` |
| 8 | `Run Phase 3` | `Run Phase 3` |
| 9 | `Run Gate 3` | `Run Gate 3` |
| 10 | `Run Phase 4` | `Run Phase 4` |
| 11 | `Run Gate 4` | `Run Gate 4` (installs the Windows dashboard) |
| 12 | `Run Phase 5` | `Run Phase 5` |
| 13 | `Run Gate 5` | `Run Gate 5` |
| 14 | `Run Phase 6` | `Run Phase 6` |
| 15 | `Run Gate 6` | `Run Gate 6` |
| 16 | `Run Phase 7` | `Run Phase 7` |
| 17 | `Run Gate 7` | `Run Gate 7` |
| 18 | `Finish the release (Phase 7 step 6)` | — |

Run a **Gate** only after **both** laptops have finished the phase before it. Start the next phase only after **both** gates pass. Claude checks the tags itself and will tell you if you're too early.

### During a phase
- Phases are long. Claude commits and merges each step as it goes, and keeps progress in `docs/status/<win|lnx>.md`.
- **If you hit a usage limit or the context gets long:** type `/clear`, then `Resume`.
- **If Claude says it's blocked on the other laptop:** run what it names on the other laptop, then come back and type `Resume`.
- **If Claude asks you to do something by hand** (accept a license, install a driver, swap the WSL kernel), it will also be listed in `docs/requests/to-user-<win|lnx>.md`.
- **Permission prompts:** common commands are pre-approved in `.claude/settings.json`. For anything else, read it before approving. Never approve a push straight to `main` or anything with `--no-verify`.
- If both laptops use the **same Claude account**, they share one usage limit. Running both at once uses it up twice as fast.

### If you want to change a prompt or the spec later
Those files belong to you, so the hook blocks Claude from touching them. To change one yourself (on either laptop, with Claude not mid-commit):
```bash
git switch main && git pull
git switch -c user/update-prompts
# edit the file(s)
git add -A && PL_USER_COMMIT=1 git commit -m "Update prompts"
git push -u origin HEAD && gh pr create --fill && gh pr merge --squash --delete-branch
```
Then `git pull` on the other laptop and tell both Claude sessions to re-read their prompt file.

### Watching progress
```bash
git fetch --tags && git tag -l 'p*' 'g*'      # which phases and gates are done
git log --oneline --graph -20 origin/main
```
Or look at the repo's Pull Requests and Actions tabs on GitHub.

---

## Part G: Troubleshooting

| Problem | Fix |
|---|---|
| `permission denied ... docker.sock` | You haven't re-logged in since `usermod`. Mint: log out/in. WSL: `wsl --shutdown` in PowerShell, reopen Ubuntu. |
| `docker run --gpus all` fails in WSL | Update the **Windows** NVIDIA driver, `wsl --update`, `wsl --shutdown`, retry. |
| `runsc` fails in WSL | Note the error and start anyway; WIN Phase 0 records it and Phase 2 fixes it (custom WSL kernel or a documented fallback). |
| Windows dashboard can't connect to the appliance | Add `networkingMode=mirrored` under `[wsl2]` in `.wslconfig`, then `wsl --shutdown`. |
| Git hook rejects a commit | That's the ownership guard working: the file belongs to the other laptop. Claude should file a request instead. |
| CRLF / `bad interpreter` errors | Someone edited files from Windows outside the WSL window. Only ever open the project with `code .` from the WSL terminal. |
| Mint runs out of memory | Close extra Chrome/VS Code windows; check `swapon --show` shows zram; tell the LNX session so it can lower limits. |
| Claude seems lost after a long session | `/clear`, then `Resume`. The status file and git history carry the state. |

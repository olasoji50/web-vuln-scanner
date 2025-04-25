#!/usr/bin/env python3
import os
import subprocess
import shutil

# ------------------------
# CLI Colors
# ------------------------

RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

# ------------------------
# Tool Config
# ------------------------

REQUIRED_TOOLS = {
    "subdominator": "pip3 install subdominator --break-system-packages",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
    "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
    "gauplus": "go install github.com/bp0lr/gauplus@latest",
    "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
    "p1radup": "pip3 install p1radup --break-system-packages",
    "tqdm": "pip3 install tqdm --break-system-packages",
    "argparse": "pip3 install argparse --break-system-packages",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "httprobe": "go install -v github.com/tomnomnom/httprobe@master",
    "anew": "go install -v github.com/tomnomnom/anew@master",
    "shodan": "pip3 install shodan --break-system-packages",
    "mmh3": "pip3 install mmh3 --break-system-packages",
}

# ------------------------
# Utilities
# ------------------------

def is_tool_installed(tool):
    return shutil.which(tool) is not None

def install_system_packages():
    print(f"\n Installing essential system dependencies...\n")
    packages = ["python3-pip", "git", "curl", "wget", "tar", "build-essential", "cmake"]
    if shutil.which("apt"):
        try:
            subprocess.run(["sudo", "apt", "update"], check=True)
            subprocess.run(["sudo", "apt", "install", "-y"] + packages, check=True)
            print(f"{GREEN}[✓] System dependencies installed.{RESET}")
        except subprocess.CalledProcessError:
            print(f"{RED}[✗] Failed to install system packages.{RESET}")
    else:
        print(f"{RED}[!] Unsupported OS. Install required packages manually: {', '.join(packages)}{RESET}")

def install_extra_system_packages():
    print(f"\n[+] Installing additional system tools: cargo, jq, lolcat")
    try:
        subprocess.run("sudo apt install -y cargo jq lolcat", shell=True, check=True)
        print(f"{GREEN}[✓] Extra system tools installed.{RESET}")
    except subprocess.CalledProcessError:
        print(f"{RED}[✗] Failed to install extra tools.{RESET}")

def prepare_for_subdominator():
    print(f"\n[+] Preparing environment for subdominator...")
    try:
        subprocess.run("sudo apt remove python3-rich -y", shell=True, check=True)
        subprocess.run("pip3 install rich aiosqlite --break-system-packages", shell=True, check=True)
        subprocess.run("sudo apt install libpango-1.0-0 libpango1.0-dev libcairo2 libcairo2-dev libgdk-pixbuf2.0-dev libffi-dev -y", shell=True, check=True)
        print(f"{GREEN}[✓] Environment prepared for subdominator.{RESET}")
    except subprocess.CalledProcessError:
        print(f"{RED}[✗] Failed during subdominator pre-installation steps.{RESET}")

def install_tool(tool, command):
    print(f"[+] Installing: {tool}")
    try:
        subprocess.run(command, shell=True, check=True, executable="/bin/bash")
        print(f"{GREEN}[✓] {tool} installed successfully.{RESET}")
    except subprocess.CalledProcessError:
        print(f"{RED}[✗] Failed to install {tool}.{RESET}")

def install_go():
    go_bin_path = "/usr/local/go/bin/go"
    if os.path.isfile(go_bin_path):
        print(f"{GREEN}[✓] Go is already installed at {go_bin_path}. Skipping installation.{RESET}")
        return
    print("[+] Installing Go 1.24.2...")
    subprocess.run("wget https://go.dev/dl/go1.24.2.linux-amd64.tar.gz", shell=True, check=True)
    subprocess.run("rm -rf /usr/local/go", shell=True, check=True)
    subprocess.run("tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz", shell=True, check=True)
    bashrc_path = os.path.expanduser("~/.bashrc")
    go_path_line = f'export PATH=$PATH:/usr/local/go/bin:{os.path.expanduser("~/go/bin")}'
    with open(bashrc_path, 'r') as file:
        contents = file.read()
    if go_path_line not in contents:
        with open(bashrc_path, 'a') as bashrc_file:
            bashrc_file.write(f"\n{go_path_line}\n")
        print(f"{GREEN}[✓] Go path appended to .bashrc.{RESET}")
    else:
        print(f"{GREEN}[✓] Go path already in .bashrc.{RESET}")
    print(f"{GREEN}[✓] Go 1.24.2 installed. Run 'source ~/.bashrc' or restart your terminal.{RESET}")

def install_rustscan():
    print("[+] Installing rustscan via cargo...")

    # Check if rustup and cargo are installed
    if not shutil.which("cargo"):
        print("[+] Installing rustup and cargo...")
        try:
            subprocess.run("curl https://sh.rustup.rs -sSf | sh -s -- -y", shell=True, check=True)
            os.environ['PATH'] += os.pathsep + os.path.expanduser("~/.cargo/bin")
            print(f"{GREEN}[✓] Rust installed successfully.{RESET}")
        except subprocess.CalledProcessError:
            print(f"{RED}[✗] Failed to install rustup/cargo.{RESET}")
            return

    bashrc_path = os.path.expanduser("~/.bashrc")
    cargo_path_line = 'export PATH="$PATH:$HOME/.cargo/bin"'
    with open(bashrc_path, "r") as file:
        if cargo_path_line not in file.read():
            with open(bashrc_path, "a") as bashrc:
                bashrc.write(f"\n{cargo_path_line}\n")
            print(f"{GREEN}[✓] ~/.cargo/bin path added to .bashrc.{RESET}")

    # Try installing RustScan with nightly toolchain
    try:
        subprocess.run("rustup install nightly", shell=True, check=True)
        subprocess.run("cargo +nightly install rustscan --locked", shell=True, check=True)
        print(f"{GREEN}[✓] rustscan installed using nightly toolchain.{RESET}")
    except subprocess.CalledProcessError:
        print(f"{RED}[!] Failed with nightly. Trying stable RustScan v2.3.0...{RESET}")
        try:
            subprocess.run("cargo install rustscan --locked --version 2.3.0", shell=True, check=True)
            print(f"{GREEN}[✓] rustscan v2.3.0 installed with stable cargo.{RESET}")
        except subprocess.CalledProcessError:
            print(f"{RED}[✗] Failed to install rustscan with both nightly and fallback version.{RESET}")


def install_autopoisoner():
    repo = "https://github.com/Th0h0/autopoisoner.git"
    dest = os.path.join(os.getcwd(), "tools", "autopoisoner")
    script = os.path.join(dest, "autopoisoner.py")
    if not os.path.exists(dest):
        subprocess.run(["git", "clone", repo, dest], check=True)
    if os.path.isfile(script):
        subprocess.run(["chmod", "+x", script])
        print(f"{GREEN}[✓] autopoisoner installed at {script}.{RESET}")

def install_urldedupe():
    repo = "https://github.com/ameenmaali/urldedupe.git"
    dest = os.path.join(os.getcwd(), "tools", "urldedupe")
    if not os.path.exists(dest):
        subprocess.run(["git", "clone", repo, dest], check=True)
    subprocess.run(f"cd {dest} && cmake . && make", shell=True, check=True)
    if os.path.exists(os.path.join(dest, "urldedupe")):
        subprocess.run(f"sudo cp {os.path.join(dest, 'urldedupe')} /usr/local/bin/", shell=True, check=True)
        print(f"{GREEN}[✓] urldedupe installed globally.{RESET}")

def install_interlace():
    repo = "https://github.com/codingo/Interlace.git"
    dest = os.path.join(os.getcwd(), "tools", "Interlace")
    if not os.path.exists(dest):
        subprocess.run(["git", "clone", repo, dest], check=True)
        subprocess.run(f"cd {dest} && sudo python3 setup.py install", shell=True, check=True)
    print(f"{GREEN}[✓] Interlace installed.{RESET}")

def install_sipg():
    repo = "https://github.com/emptymahbob/sipg.git"
    dest = os.path.join(os.getcwd(), "tools", "sipg")
    if not os.path.exists(dest):
        subprocess.run(["git", "clone", repo, dest], check=True)
    try:
        subprocess.run(f"cd {dest} && pip3 install -r requirements.txt --break-system-packages", shell=True, check=True)
        print(f"{GREEN}[✓] sipg dependencies installed.{RESET}")
    except subprocess.CalledProcessError:
        print(f"{RED}[✗] Failed installing sipg dependencies.{RESET}")

def rename_nuclei_templates():
    src = os.path.join(os.getcwd(), "nuclei-templates")
    dest = os.path.join(os.getcwd(), "scanner-templates")
    if os.path.exists(src):
        try:
            os.rename(src, dest)
            print(f"{GREEN}[✓] Moved 'nuclei-templates' to 'scanner-templates'.{RESET}")
        except Exception as e:
            print(f"{RED}[✗] Failed to move: {e}{RESET}")
    else:
        print(f"{RED}[!] 'nuclei-templates' not found. Skipping rename.{RESET}")

# ------------------------
# Entry Point
# ------------------------

def main():
    print("Starting Recon Setup...\n")
    install_system_packages()
    install_extra_system_packages()
    install_go()

    if not is_tool_installed("subdominator"):
        prepare_for_subdominator()

    for tool, command in REQUIRED_TOOLS.items():
        if not is_tool_installed(tool):
            install_tool(tool, command)
        else:
            print(f"{GREEN}[✓] {tool} is already installed.{RESET}")

    install_autopoisoner()
    install_urldedupe()
    install_rustscan()
    install_interlace()
    install_sipg()
    rename_nuclei_templates()

    print("\n [✓] Setup Complete!")

if __name__ == "__main__":
    main()

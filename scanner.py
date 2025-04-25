
import os
import subprocess
import argparse
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import re
import datetime
from pathlib import Path
import json
from ipaddress import ip_address, ip_network
import time

def timed_execution(label, function, *args, **kwargs):
    start = time.time()
    print(f"[+] Starting {label}...")
    result = function(*args, **kwargs)
    end = time.time()
    duration = round(end - start, 2)
    print(f"[✓] {label} completed in {duration} seconds.\n")
    return result

def run_command(command, output_file=None):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        print(f"Error: {stderr.decode()}")

    if output_file:
        with open(output_file, 'w') as f:
            f.write(stdout.decode())
        print(f"Output saved to {output_file}")

    return stdout.decode()

def create_output_dir():
    output_dir = os.path.join(os.getcwd(), 'output')
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def find_subdomains(domain, output_file):
    command = ['subdominator', '-d', domain]
    run_command(command, output_file)
    print(f"Subdomains saved to {output_file}")

def discover_parameters(subdomain, all_urls, progress_bar):
    subdomain = subdomain.strip()

    for tool in ['waybackurls', 'gau', 'gauplus']:
        command = [tool, subdomain]
        urls = run_command(command).splitlines()
        all_urls.extend(urls)
        progress_bar.update(1)

    command = ['katana', '-u', subdomain, '-o', '/tmp/katana_output']
    run_command(command)
    with open('/tmp/katana_output', 'r') as f:
        all_urls.extend(f.readlines())
    progress_bar.update(1)

def discover_parameters_for_all_subdomains(subdomains, output_file):
    all_urls = []
    with tqdm(total=len(subdomains), desc="Discovering Parameters", unit="subdomain") as progress_bar:
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(discover_parameters, subdomain, all_urls, progress_bar) for subdomain in subdomains]
            for _ in as_completed(futures):
                pass
    with open(output_file, 'w') as f:
        f.write("\n".join(all_urls))
    print(f"Discovered parameters saved to {output_file}")

def deduplicate_urls(input_file, output_file, num_threads=4):
    with open(input_file, 'r') as f:
        urls = f.readlines()

    chunk_size = len(urls) // num_threads
    chunks = [urls[i:i + chunk_size] for i in range(0, len(urls), chunk_size)]

    def process_chunk(chunk):
        return set(url.strip() for url in chunk)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(process_chunk, chunk) for chunk in chunks]
        unique_urls = set()
        for future in as_completed(futures):
            unique_urls.update(future.result())

    with open(output_file, 'w') as f:
        f.write("\n".join(unique_urls))
    print(f"Deduplicated URLs saved to {output_file}")

def run_urldedupe(input_file, output_file):
    command = ['urldedupe', '-u', input_file]
    run_command(command, output_file)

def run_p1radup(input_file, output_file):
    command = ['p1radup', '-i', input_file]
    run_command(command, output_file)

def word_count(file_path):
    with open(file_path, 'r') as f:
        return len(f.readlines())

def discover_xss(input_file, output_dir):
    output_file = os.path.join(output_dir, 'xss_results.txt')
    command = ['dalfox', 'file', input_file, '--silence']
    result = run_command(command)

    with open(output_file, 'w') as f:
        f.write(result)

    print("XSS Discovery Results:")
    print(result)
    print(f"XSS results saved to {output_file}")

def security_headers(domain, output_file):
    template_path = os.path.join(os.getcwd(), 'scanner-templates', 'http', 'misconfiguration', 'http-missing-security-headers.yaml')
    command = ['nuclei', '-u', domain, '-t', template_path, '-silent']
    output = run_command(command)

    # Save raw output
    with open(output_file, 'w') as f:
        f.write(output)

    # Parse and format
    results = defaultdict(list)
    for line in output.strip().split('\n'):
        line = line.strip()
        if not line:
            continue

        finding_match = re.match(r'\[([^\]]+)\]', line)
        url_match = re.search(r'(https?://[^\s]+)$', line)

        if finding_match and url_match:
            finding = finding_match.group(1)
            url = url_match.group(1)
            results[url].append(finding)

    formatted_output_file = output_file.replace('.txt', '_formatted.txt')
    with open(formatted_output_file, 'w') as f_out:
        for url, findings in results.items():
            f_out.write(f"{url}\n")
            for finding in findings:
                f_out.write(f"  - {finding}\n")

    if os.path.exists(output_file):
        os.remove(output_file)
        print(f"Deleted temporary file: {output_file}")

    print("Security Headers Scan Results:")
    with open(formatted_output_file, 'r') as f:
        print(f.read())

    print(f"Formatted security header results saved to {formatted_output_file}")

def subdomain_takeover(subdomain_file, output_dir):
    template_path = os.path.join(os.getcwd(), 'scanner-templates', 'http', 'takeovers')
    output_file = os.path.join(output_dir, 'subdomain_takeover.txt')

    command = ['nuclei', '-l', subdomain_file, '-t', template_path, '-silent']
    result = run_command(command)

    with open(output_file, 'w') as f:
        f.write(result)

    print("\nSubdomain Takeover Scan Results:")
    print(result)
    print(f"Subdomain takeover results saved to {output_file}")

def run_webcache_poisoning(input_file, output_dir):
    script_path = os.path.join(os.getcwd(), 'tools', 'autopoisoner', 'autopoisoner.py')
    output_file = os.path.join(output_dir, 'webcache_poisoning.txt')
    command = ['python3', script_path, '--file', input_file]
    
    result = run_command(command)

    with open(output_file, 'w') as f:
        f.write(result)

    print("\nWeb Cache Poisoning Scan Results:")
    print(result)
    print(f"Web Cache Poisoning results saved to {output_file}")

# === Shodan Automation ===
WAF_IP_RANGES = [
    "104.16.0.0/12", "205.251.192.0/19", "108.162.192.0/18",
    "185.31.17.0/24", "162.247.240.0/22", "52.46.0.0/18"
]

def is_waf_ip(ip):
    """Check if an IP is behind a WAF."""
    for range_str in WAF_IP_RANGES:
        try:
            if ip_address(ip) in ip_network(range_str):
                return True
        except ValueError:
            continue
    return False

def write_config_json():
    """Write config.json for SIPG API."""
    with open("config.json", "w") as f:
        json.dump({"api_key": "P0ttHSrF6FIzrxEnxB8YvOJ847ibmOSG"}, f)

def extract_ips_from_sipg_output(file):
    """Extract IPs from SIPG output."""
    ips = set()
    with open(file) as f:
        for line in f:
            match = re.search(r'https?://([\d]+\.[\d]+\.[\d]+\.[\d]+)', line)
            if match:
                ips.add(match.group(1))
    return list(ips)

def run_shodan_automation(domain, output_dir):
    """Run Shodan automation for finding open ports and vulnerabilities."""
    censys_dir = os.path.join(output_dir, 'censysshodan')
    os.makedirs(censys_dir, exist_ok=True)
    sipg_output_file = os.path.join(censys_dir, f"{domain}_sipg_ips.txt")
    shodan_result_file = os.path.join(censys_dir, f"{domain}_shodan.txt")
    shodan_nuclei_file = os.path.join(censys_dir, f"{domain}_nuclei_shodan.txt")

    write_config_json()
    query = f'Ssl.cert.subject.CN:"*.{domain}"'
    path = os.path.join(os.getcwd(), 'tools', 'sipg', 'sipg.py')
    run_command(['python3', path, '-q', query], output_file=sipg_output_file)
    

    ips = extract_ips_from_sipg_output(sipg_output_file)
    if not ips:
        print("[!] No IPs found.")
        return

    filtered_ips = [ip for ip in ips if not is_waf_ip(ip)]
    if not filtered_ips:
        print("[!] All IPs are behind WAFs.")
        return

    with open(sipg_output_file, 'w') as f:
        f.write('\n'.join(filtered_ips))

    print("[+] Running rustscan...")
    rustscan_out = run_command(['rustscan', '-a', sipg_output_file, '-r', '1-10000'])
    open_lines = [line for line in rustscan_out.splitlines() if line.startswith("Open")]
    with open(shodan_result_file, 'w') as f:
        f.write('\n'.join(open_lines))

    cleaned_hosts = [line.replace("Open ", "").strip() for line in open_lines]
    temp_httpx_input = os.path.join(censys_dir, 'shodan_cleaned_hosts.txt')
    with open(temp_httpx_input, 'w') as f:
        f.write('\n'.join(cleaned_hosts))

    print("[+] Running httpx + nuclei...")
    path = os.path.join(os.getcwd(), 'scanner-templates')
    httpx_cmd = f"cat {temp_httpx_input} | nuclei -t {path} -silent"
    nuclei_output = subprocess.getoutput(httpx_cmd)

    with open(shodan_nuclei_file, 'w') as f:
        f.write(nuclei_output)

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True, help="Target domain (e.g. example.com)")
    return parser.parse_args()


def main():
    """Main function to run all recon steps."""
    args = parse_args()
    domain = args.target
    output_dir = create_output_dir()

    subdomain_file = os.path.join(output_dir, 'subdomains.txt')
    parameters_file = os.path.join(output_dir, 'parameters.txt')
    deduped_urldedupe = os.path.join(output_dir, 'deduplicated_params_urldedupe.txt')
    xss_params_file = os.path.join(output_dir, 'xss_params.txt')
    missing_headers_file = os.path.join(output_dir, 'missing_headers.txt')

    timed_execution("Step 1: Finding Subdomains", find_subdomains, domain, subdomain_file)

    with open(subdomain_file, 'r') as f:
        subdomains = f.readlines()
    timed_execution("Step 2: Discovering Parameters", discover_parameters_for_all_subdomains, subdomains, parameters_file)

    timed_execution("Step 3: Deduplicating URLs using urldedupe", run_urldedupe, parameters_file, deduped_urldedupe)
    print(f"Word count after urldedupe: {word_count(deduped_urldedupe)}")

    timed_execution("Step 4: Deduplicating URLs using p1radup", run_p1radup, deduped_urldedupe, xss_params_file)
    print(f"Word count after p1radup: {word_count(xss_params_file)}")

    timed_execution("Step 5: XSS Discovery", discover_xss, xss_params_file, output_dir)

    timed_execution("Step 6: Security Headers", security_headers, domain, missing_headers_file)

    timed_execution("Step 7: Subdomain Takeover", subdomain_takeover, subdomain_file, output_dir)

    timed_execution("Step 8: Web Cache Poisoning", run_webcache_poisoning, xss_params_file, output_dir)

    timed_execution("Step 9: Shodan Automation", run_shodan_automation, domain, output_dir)

    print("\n✅ Scan Completed!")


if __name__ == "__main__":
    main()
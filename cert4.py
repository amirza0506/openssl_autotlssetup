import os
import json
import subprocess
import re
import csv
import sys

DOMAIN_DIR = "domain"
RESULT_DIR = "result"
ERROR_DIR = os.path.join(RESULT_DIR, "error")

os.makedirs(RESULT_DIR, exist_ok=True)
os.makedirs(ERROR_DIR, exist_ok=True)

RE_CIPHER = re.compile(r"Cipher *: *([A-Za-z0-9_\-]+)")
RE_TLS_VERSION = re.compile(r"Protocol *: *([A-Za-z0-9\.\-]+)")
RE_SIG_TYPE = re.compile(r"Peer signature type: (.*)")
RE_SIG_DIGEST = re.compile(r"Peer signing digest: (.*)")
RE_TEMP_KEY = re.compile(r"Peer Temp Key: (.*)")
RE_NEGO_GROUP = re.compile(r"Negotiated TLS1.3 group: (.*)")
RE_SUBJECT = re.compile(r"subject= *(.*)")
RE_ISSUER = re.compile(r"issuer= *(.*)")


def run_sclient(domain):
    try:
        cmd = [
            "openssl", "s_client",
            "-connect", f"{domain}:443",
        ]

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        try:
            stdout, stderr = proc.communicate(input=b"\n", timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()

        return stdout.decode(errors="ignore") + stderr.decode(errors="ignore")

    except Exception as e:
        return f"ERROR: {str(e)}"


def parse_output(text):
    return {
        "tls_version": RE_TLS_VERSION.search(text).group(1) if RE_TLS_VERSION.search(text) else None,
        "cipher": RE_CIPHER.search(text).group(1) if RE_CIPHER.search(text) else None,
        "peer_signature_type": RE_SIG_TYPE.search(text).group(1) if RE_SIG_TYPE.search(text) else None,
        "peer_signing_digest": RE_SIG_DIGEST.search(text).group(1) if RE_SIG_DIGEST.search(text) else None,
        "peer_temp_key": RE_TEMP_KEY.search(text).group(1) if RE_TEMP_KEY.search(text) else None,
        "negotiated_group": RE_NEGO_GROUP.search(text).group(1) if RE_NEGO_GROUP.search(text) else None,
        "subject": RE_SUBJECT.search(text).group(1) if RE_SUBJECT.search(text) else None,
        "issuer": RE_ISSUER.search(text).group(1) if RE_ISSUER.search(text) else None,
    }


def try_connect(domain):
    output = run_sclient(domain)
    success = ("CONNECTED" in output) or ("subject=" in output)
    return success, output, (parse_output(output) if success else None)


def process_domain(domain):
    domain = domain.strip()
    print(f"Scanning: {domain}")

    ok, output, parsed = try_connect(domain)

    if not ok:

        alt = f"www.{domain}"
        print(f" → Failed. Trying {alt} ...")
        ok_alt, output2, parsed2 = try_connect(alt)

        if ok_alt:
            result = {
                "domain": domain,
                "used_target": alt,
                "status": "success",
                "data": parsed2
            }
            save_path = os.path.join(RESULT_DIR, f"{domain}.json")

        else:
            result = {
                "domain": domain,
                "status": "error",
                "error": "Unable to connect with TLS on base or www",
                "Output": output + "\n" + output2
            }
            save_path = os.path.join(ERROR_DIR, f"{domain}.json")

            with open(os.path.join(ERROR_DIR, "error_list.txt"), "a") as errf:
                errf.write(domain + "\n")

    else:

        result = {
            "domain": domain,
            "used_target": domain,
            "status": "success",
            "data": parsed
        }
        save_path = os.path.join(RESULT_DIR, f"{domain}.json")

    with open(save_path, "w") as f:
        json.dump(result, f, indent=4)

    return result


def read_csv_domains(path):
    domains = []
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if row and row[0].strip():
                domains.append(row[0].strip())
    return domains


def main():
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <csv_name>")
        print("Example: python scanner.py com_6")
        return

    csv_file = sys.argv[1] + ".csv"
    csv_path = os.path.join(DOMAIN_DIR, csv_file)

    if not os.path.exists(csv_path):
        print(f"ERROR: CSV file not found: {csv_path}")
        return

    print(f"Loading file: {csv_path}")
    domains = read_csv_domains(csv_path)

    print(f"Total domains: {len(domains)}\n")

    for dom in domains:
        process_domain(dom)

    print("\nScan completed.")


if __name__ == "__main__":
    main()

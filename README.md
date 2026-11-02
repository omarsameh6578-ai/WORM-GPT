
import os
import re
import json
import hashlib
import ipaddress
from datetime import datetime
from urllib.parse import urlparse
from collections import Counter
from colorama import Fore, init

init(autoreset=True)

R = Fore.RED
G = Fore.GREEN
Y = Fore.YELLOW
C = Fore.CYAN
W = Fore.WHITE

ROOT = os.path.dirname(os.path.abspath(__file__))
REPORTS = os.path.join(ROOT, "reports")
DB = os.path.join(REPORTS, "max_history.json")

os.makedirs(REPORTS, exist_ok=True)


def banner():
    os.system("clear")
    print(R + r"""
╔══════════════════════════════════╗
║       WORM GPT V999999           ║
║          MAX EDITION             ║
║      DIGITAL FORENSICS LAB       ║
╚══════════════════════════════════╝
""")


def load_db():
    if not os.path.exists(DB):
        return []
    try:
        with open(DB, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def save_report(report):
    history = load_db()
    report["timestamp"] = datetime.now().isoformat()
    history.append(report)

    with open(DB, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=4, ensure_ascii=False)

    filename = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(REPORTS, filename + ".json")

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    print(G + "\n[+] Report saved:", path)


def extract_iocs(text):
    urls = re.findall(
        r'https?://[^\s<>"\']+',
        text,
        re.I
    )

    emails = re.findall(
        r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}',
        text
    )

    ips = re.findall(
        r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])',
        text
    )

    valid_ips = []

    for item in ips:
        try:
            valid_ips.append(str(ipaddress.ip_address(item)))
        except ValueError:
            pass

    return {
        "urls": list(dict.fromkeys(urls)),
        "emails": list(dict.fromkeys(emails)),
        "ips": list(dict.fromkeys(valid_ips))
    }


def score_text(text):
    rules = {
        "Password request": r'password|passwd|كلمة المرور|باسورد',
        "Urgent request": r'urgent|immediately|عاجل|فورا',
        "Fake prize": r'winner|free prize|جائزة|ربحت',
        "Bank request": r'credit card|bank account|بطاقة بنكية',
        "Verification": r'verify|verification|تحقق',
        "Suspicious attachment": r'\.(exe|scr|bat|cmd|js)\b'
    }

    findings = []

    for name, pattern in rules.items():
        if re.search(pattern, text, re.I):
            findings.append(name)

    score = len(findings)

    level = (
        "HIGH" if score >= 4
        else "MEDIUM" if score >= 2
        else "LOW"
    )

    return findings, score, level


def email_analysis():
    banner()
    print(C + "[ EMAIL FORENSICS MAX ]")

    text = input("\nPaste email text: ")

    findings, score, level = score_text(text)
    iocs = extract_iocs(text)

    print(Y + "\nRisk:", level)
    print("Score:", score)

    for finding in findings:
        print(R + "[!] " + finding)

    print(C + "\nExtracted indicators:")

    for category, values in iocs.items():
        print("\n" + category.upper())

        for value in values:
            print(W + " - " + value)

    save_report({
        "type": "email",
        "risk": level,
        "score": score,
        "findings": findings,
        "indicators": iocs
    })


def url_analysis():
    banner()
    print(C + "[ URL INTELLIGENCE MAX ]")

    value = input("\nURL: ").strip()

    if not value:
        return

    if not re.match(r'^https?://', value, re.I):
        value = "https://" + value

    parsed = urlparse(value)
    host = parsed.hostname

    if not host:
        print(R + "Invalid URL")
        return

    findings = []

    if parsed.scheme != "https":
        findings.append("HTTPS not used")

    if parsed.username or parsed.password:
        findings.append("Embedded credentials")

    if "@" in parsed.netloc:
        findings.append("Potential deceptive URL")

    try:
        address = ipaddress.ip_address(host)
        findings.append("IP address used as hostname")

        if not address.is_global:
            findings.append("Non-public IP")

    except ValueError:
        if host.startswith("xn--") or ".xn--" in host:
            findings.append("Internationalized hostname")

        if len(host) > 50:
            findings.append("Unusually long hostname")

        if host.count("-") >= 4:
            findings.append("Many hyphens")

    print(G + "\nHostname:", host)
    print("Scheme:", parsed.scheme)

    for finding in findings:
        print(Y + "[!] " + finding)

    if not findings:
        print(G + "No obvious warning detected")

    save_report({
        "type": "url",
        "host": host,
        "findings": findings
    })


def ip_analysis():
    banner()
    value = input("IP address: ").strip()

    try:
        ip = ipaddress.ip_address(value)

        print(G + "\nValid IP")
        print("Version:", ip.version)
        print("Global:", ip.is_global)
        print("Private:", ip.is_private)
        print("Loopback:", ip.is_loopback)
        print("Multicast:", ip.is_multicast)

        save_report({
            "type": "ip",
            "address": str(ip),
            "global": ip.is_global
        })

    except ValueError:
        print(R + "Invalid IP")


def file_analysis():
    banner()
    path = input("File path: ").strip()

    if not os.path.isfile(path):
        print(R + "File not found")
        return

    sha = hashlib.sha256()
    size = os.path.getsize(path)

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)

    digest = sha.hexdigest()

    print(G + "\nFile:", os.path.basename(path))
    print("Size:", size)
    print("SHA256:", digest)

    save_report({
        "type": "file",
        "name": os.path.basename(path),
        "size": size,
        "sha256": digest
    })


def history():
    banner()
    records = load_db()

    print(C + "TOTAL INVESTIGATIONS:", len(records))

    for record in records[-15:]:
        print(Y + "\n" + json.dumps(
            record,
            ensure_ascii=False,
            indent=2
        ))


def dashboard():
    banner()
    records = load_db()

    counts = Counter(
        item.get("type", "unknown")
        for item in records
    )

    print(C + "INVESTIGATION DASHBOARD")
    print(W + "\nTotal reports:", len(records))

    for category, count in counts.items():
        print(G + category, ":", count)


def main():
    while True:
        banner()

        print(C + """
[1] Email Forensics
[2] URL Intelligence
[3] IP Intelligence
[4] File Forensics
[5] Investigation History
[6] MAX Dashboard
[7] Exit
""")

        choice = input(G + "WORM MAX >> ")

        actions = {
            "1": email_analysis,
            "2": url_analysis,
            "3": ip_analysis,
            "4": file_analysis,
            "5": history,
            "6": dashboard
        }

        if choice == "7":
            break

        action = actions.get(choice)

        if action:
            try:
                action()
            except Exception as error:
                print(R + "Error:", error)
        else:
            print(R + "Invalid option")

        input("\nPress Enter...")


if __name__ == "__main__":
    main()

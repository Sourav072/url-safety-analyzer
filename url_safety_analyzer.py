import requests
from bs4 import BeautifulSoup
import whois
import matplotlib.pyplot as plt
from urllib.parse import urlparse
import ssl
import socket
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os

# Load environment variables from vt.env
load_dotenv("vt.env")

# Retrieve API key from vt.env
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if not VIRUSTOTAL_API_KEY:
    raise ValueError("VirusTotal API Key is not set in vt.env.")

# Encrypted name and encryption key
ENCRYPTION_KEY = b'OZg8igPAngJpnZdIvWGqzU15A9-pdZlLy7WQqVW-WoE='
ENCRYPTED_NAME = b'gAAAAABnOw9RgUfjUoQZlcj8bKTLh0Z5Ttvv65Y6pqtGUUZq_AESYdz6Hl7aB80oIgIeMF3nv3ugPtS2rGSGE1_BkDHl1n7u0DxVdIhsET2RfAzoLMiojhc='


def decrypt_name(encrypted_name, key):
    """
    Decrypt the encrypted name using the provided key.
    """
    try:
        fernet = Fernet(key)
        decrypted_name = fernet.decrypt(encrypted_name).decode()
        return decrypted_name
    except Exception as e:
        return "[Error: Unable to decrypt name]"


def fetch_url_content(url):
    """
    Fetch the HTML content of the provided URL.
    """
    try:
        print("[*] Fetching website content...")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        print("[+] Website fetched successfully.")
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching website: {e}")
        return None


def analyze_security(url):
    """
    Perform security checks including domain age and SSL validity.
    """
    scores = []
    descriptions = []

    try:
        # Check domain age using WHOIS
        print("[*] Analyzing domain age...")
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)
        if domain_info.creation_date:
            print(f"[+] Domain Creation Date: {domain_info.creation_date}")
            scores.append(30)
            descriptions.append("Domain Age (Valid)")
        else:
            print("[-] Domain age not found.")
            scores.append(10)
            descriptions.append("Domain Age (Unknown)")

        # Check SSL certificate validity
        print("[*] Checking SSL certificate...")
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
            if cert:
                print("[+] SSL certificate is valid.")
                scores.append(40)
                descriptions.append("SSL Certificate (Valid)")
            else:
                print("[-] SSL certificate is invalid.")
                scores.append(10)
                descriptions.append("SSL Certificate (Invalid)")

    except Exception as e:
        print(f"[-] Security analysis error: {e}")
        scores.extend([10, 10])  # Reduced penalty for failed checks
        descriptions.extend(["Domain Age (Error)", "SSL Certificate (Error)"])

    return scores, descriptions


def check_with_virustotal(url):
    """
    Scan the URL using VirusTotal API for malicious activity.
    """
    try:
        print("[*] Checking URL with VirusTotal...")
        api_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        data = {"url": url}
        response = requests.post(api_url, headers=headers, data=data)
        response.raise_for_status()

        # Retrieve URL scan results
        analysis_id = response.json()["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_response = requests.get(analysis_url, headers=headers)
        analysis_response.raise_for_status()

        stats = analysis_response.json()["data"]["attributes"]["stats"]
        malicious_votes = stats["malicious"]
        harmless_votes = stats.get("harmless", 0)

        # Adjust scoring
        if malicious_votes == 0:
            print("[+] VirusTotal reports the URL as clean.")
            return 30, "VirusTotal (Clean)"
        else:
            print(f"[-] VirusTotal detected {malicious_votes} malicious votes.")
            return max(0, 30 - malicious_votes * 10), "VirusTotal (Malicious)"
    except Exception as e:
        print(f"[-] VirusTotal API error: {e}")
        return 10, "VirusTotal (Error)"


def generate_pie_chart(scores, descriptions):
    """
    Create a pie chart visualization of the analysis results.
    """
    print("[*] Generating visual representation...")
    plt.figure(figsize=(8, 6))
    plt.pie(
        scores,
        labels=descriptions,
        autopct='%1.1f%%',
        startangle=140,
        wedgeprops={'edgecolor': 'black'}
    )
    plt.title("URL Safety Analysis")
    plt.show()


def main():
    """
    Main function to orchestrate the analysis.
    """
    print("=== Welcome to the URL Safety Analyzer ===")
    url = input("Enter the URL to analyze: ").strip()

    if not url.startswith("http"):
        url = "http://" + url  # Add scheme if missing

    print(f"\nAnalyzing: {url}\n")

    # Step 1: Fetch URL Content
    html_content = fetch_url_content(url)
    if not html_content:
        print("[-] Unable to analyze the URL. Exiting.")
        return

    # Step 2: Perform Security Analysis
    security_scores, descriptions = analyze_security(url)

    # Step 3: Check with VirusTotal
    virustotal_score, virustotal_description = check_with_virustotal(url)
    security_scores.append(virustotal_score)
    descriptions.append(virustotal_description)

    # Step 4: Calculate Total Score
    total_score = sum(security_scores)
    print("\n=== Analysis Results ===")
    print(f"Total Security Score: {total_score}/100")
    if total_score > 50:
        print("Recommendation: The link appears relatively safe to use.")
    else:
        print("Recommendation: Avoid using this link or sharing personal details.")

    # Step 5: Display Pie Chart
    generate_pie_chart(security_scores, descriptions)

    # Step 6: Display Decrypted Name
    decrypted_name = decrypt_name(ENCRYPTED_NAME, ENCRYPTION_KEY)
    print(f"\nAnalysis conducted by: {decrypted_name}")


if __name__ == "__main__":
    main()

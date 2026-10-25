#!/usr/bin/env python3
"""
Parrot Recon - Mailgun Email Notification Dispatcher
Sends executive completion summaries and findings reports via Mailgun API.
Uses Python standard library (no pip dependencies required).
"""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders


def build_fallback_body(domain, scan_type, status, results_dir):
    return f"""Parrot Recon Scan Completed
Target Domain: {domain}
Scan Type:     {scan_type}
Status:        {status}
Results Dir:   {results_dir}

Full scan artifacts and reports are available in the results directory.
"""


def send_mailgun_message(api_key, mailgun_domain, to_email, subject, text_body, html_body=None, attachment_path=None, region="us"):
    base_host = "api.eu.mailgun.net" if region.lower() == "eu" else "api.mailgun.net"
    endpoint = f"https://{base_host}/v3/{mailgun_domain}/messages"

    from_address = os.environ.get("MAILGUN_FROM", f"Parrot Recon <recon@{mailgun_domain}>")

    boundary = f"----ParrotReconBoundary{os.urandom(16).hex()}"
    parts = []

    def add_field(name, value):
        parts.append(f"--{boundary}\r\n".encode("utf-8"))
        parts.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        parts.append(f"{value}\r\n".encode("utf-8"))

    add_field("from", from_address)
    add_field("to", to_email)
    add_field("subject", subject)
    add_field("text", text_body)

    if html_body:
        add_field("html", html_body)

    if attachment_path and os.path.isfile(attachment_path):
        filename = os.path.basename(attachment_path)
        try:
            with open(attachment_path, "rb") as f:
                file_bytes = f.read()
            parts.append(f"--{boundary}\r\n".encode("utf-8"))
            parts.append(f'Content-Disposition: form-data; name="attachment"; filename="{filename}"\r\n'.encode("utf-8"))
            parts.append(b"Content-Type: application/octet-stream\r\n\r\n")
            parts.append(file_bytes)
            parts.append(b"\r\n")
        except Exception as e:
            print(f"[!] Warning: Could not attach {attachment_path}: {e}", file=sys.stderr)

    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    payload = b"".join(parts)

    auth_str = f"api:{api_key}"
    auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")

    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "Authorization": f"Basic {auth_b64}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "Parrot-Recon-Mailer/2.0",
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_data = resp.read().decode("utf-8")
            status_code = resp.getcode()
            if status_code in (200, 201):
                return True, resp_data
            return False, f"HTTP {status_code}: {resp_data}"
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        return False, f"HTTP Error {e.code}: {e.reason} ({error_body})"
    except urllib.error.URLError as e:
        return False, f"Network Error: {e.reason}"
    except Exception as e:
        return False, str(e)


def main():
    parser = argparse.ArgumentParser(description="Send Parrot Recon completion notifications via Mailgun")
    parser.add_argument("-d", "--domain", default=os.environ.get("RECON_DOMAIN", "target"), help="Scanned target domain")
    parser.add_argument("-t", "--scan-type", default=os.environ.get("RECON_TYPE", "ALL"), help="Scan type executed (WEB, API, ALL)")
    parser.add_argument("-s", "--status", default="Completed", help="Scan status")
    parser.add_argument("-m", "--to", default=os.environ.get("MAILGUN_TO"), help="Recipient email address")
    parser.add_argument("-k", "--api-key", default=os.environ.get("MAILGUN_API_KEY"), help="Mailgun API Key")
    parser.add_argument("-g", "--mailgun-domain", default=os.environ.get("MAILGUN_DOMAIN"), help="Mailgun sending domain")
    parser.add_argument("-r", "--region", default=os.environ.get("MAILGUN_REGION", "us"), choices=["us", "eu"], help="Mailgun region (us or eu)")
    parser.add_argument("--summary-file", help="Path to Markdown summary report file")
    parser.add_argument("--html-file", help="Path to HTML summary report file")
    parser.add_argument("--results-dir", default="results", help="Results directory path")
    parser.add_argument("--dry-run", action="store_true", help="Print email details without sending")

    args = parser.parse_args()

    to_addr = args.to
    api_key = args.api_key
    mg_domain = args.mailgun_domain

    if not to_addr:
        print("[-] Error: No recipient email specified (use -m or set MAILGUN_TO)", file=sys.stderr)
        sys.exit(1)

    if not api_key or not mg_domain:
        if args.dry_run:
            print("[*] Dry run mode: Missing Mailgun credentials, but continuing simulation.")
            api_key = api_key or "dryrun_key"
            mg_domain = mg_domain or "example.mailgun.org"
        else:
            print("[-] Error: Mailgun credentials missing.", file=sys.stderr)
            print("    Please set MAILGUN_API_KEY and MAILGUN_DOMAIN environment variables, or pass --api-key and --mailgun-domain.", file=sys.stderr)
            sys.exit(1)

    subject = f"[Parrot Recon] Scan Finished: {args.domain} ({args.scan_type.upper()})"

    text_body = ""
    attachment_path = None
    if args.summary_file and os.path.isfile(args.summary_file):
        try:
            with open(args.summary_file, "r", encoding="utf-8", errors="replace") as f:
                text_body = f.read()
            attachment_path = args.summary_file
        except Exception as e:
            text_body = f"Failed to read summary file: {e}\n"

    if not text_body:
        text_body = build_fallback_body(args.domain, args.scan_type, args.status, args.results_dir)

    html_body = None
    if args.html_file and os.path.isfile(args.html_file):
        try:
            with open(args.html_file, "r", encoding="utf-8", errors="replace") as f:
                html_body = f.read()
        except Exception as e:
            html_body = None

    if args.dry_run:
        print("[*] --- DRY RUN EMAIL PREVIEW ---")
        print(f"To:      {to_addr}")
        print(f"Domain:  {mg_domain} (Region: {args.region})")
        print(f"Subject: {subject}")
        print(f"Attachment: {attachment_path}")
        print("Body Snippet:")
        print("\n".join(text_body.splitlines()[:15]))
        print("[*] --- END DRY RUN ---")
        sys.exit(0)

    print(f"[*] Sending scan completion notification to {to_addr} via Mailgun ({mg_domain})...")
    success, detail = send_mailgun_message(
        api_key=api_key,
        mailgun_domain=mg_domain,
        to_email=to_addr,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
        attachment_path=attachment_path,
        region=args.region
    )

    if success:
        print(f"[+] Email successfully dispatched to {to_addr}")
        sys.exit(0)
    else:
        print(f"[-] Failed to dispatch email via Mailgun: {detail}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()

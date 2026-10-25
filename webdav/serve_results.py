#!/usr/bin/env python3
"""
Parrot Recon - Results Web Server & WebDAV Explorer
Provides a modern, lightweight web dashboard and WebDAV interface
to browse, preview, and download scan results.
Zero external dependencies required (uses Python standard library).
"""

import argparse
import html
import http.server
import json
import mimetypes
import os
import socket
import socketserver
import sys
import threading
import time
from urllib.parse import unquote, urlparse


DEFAULT_PORT = 8098
DEFAULT_HOST = "127.0.0.1"


def get_file_metadata(filepath):
    stat = os.stat(filepath)
    size = stat.st_size
    if size < 1024:
        size_str = f"{size} B"
    elif size < 1024 * 1024:
        size_str = f"{size / 1024:.1f} KB"
    else:
        size_str = f"{size / (1024 * 1024):.2f} MB"
    mod_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime))
    return size, size_str, mod_time


def identify_tool(filename):
    fn = filename.lower()
    if "tcp-scan" in fn or "udp-scan" in fn or "nmap" in fn:
        return "Nmap Port Scan", "nmap"
    if "dork" in fn:
        return "OSINT Search Dorking", "dork"
    if "subdomains" in fn:
        return "Subdomain Enumeration", "subdomains"
    if "takeover" in fn:
        return "Subdomain Takeover", "takeover"
    if "sqlerror" in fn or "sqli" in fn:
        return "SQL Injection Probe", "sqli"
    if "wafw00f" in fn:
        return "WAF / IDS Detection", "waf"
    if "nikto" in fn:
        return "Nikto Web Vulnerabilities", "nikto"
    if "cmsenum" in fn or "cmsmap" in fn:
        return "CMS Enumeration", "cms"
    if "sslyze" in fn:
        return "SSL/TLS Security Analysis", "ssl"
    if "nuclei" in fn:
        return "Nuclei Template Findings", "nuclei"
    if "shcheck" in fn:
        return "Security Headers Check", "headers"
    if "cors" in fn:
        return "CORS Misconfiguration Scan", "cors"
    if "headi" in fn:
        return "HTTP Header Injection", "headi"
    if "content-discovery" in fn or "ffuf" in fn or "dirsearch" in fn:
        return "Content Discovery / Fuzzing", "content"
    if "api-urls" in fn:
        return "Extracted API Endpoints", "api"
    if "api-authcheck" in fn:
        return "API Authentication Bypass Check", "api"
    if "summary" in fn:
        return "Executive Scan Summary", "summary"
    return "Artifact", "general"


def render_dashboard_html(results_dir, target_filter=None):
    files_data = []
    if os.path.exists(results_dir):
        for entry in sorted(os.listdir(results_dir)):
            full_path = os.path.join(results_dir, entry)
            if os.path.isfile(full_path):
                if target_filter and target_filter not in entry:
                    continue
                size, size_str, mod_time = get_file_metadata(full_path)
                tool_name, tool_tag = identify_tool(entry)
                files_data.append({
                    "name": entry,
                    "tool": tool_name,
                    "tag": tool_tag,
                    "size": size_str,
                    "bytes": size,
                    "mtime": mod_time
                })

    # Summary counts
    total_files = len(files_data)
    total_bytes = sum(f["bytes"] for f in files_data)
    if total_bytes < 1024 * 1024:
        total_size_str = f"{total_bytes / 1024:.1f} KB"
    else:
        total_size_str = f"{total_bytes / (1024 * 1024):.2f} MB"

    rows_html = ""
    for f in files_data:
        is_viewable = f["name"].endswith((".txt", ".md", ".json", ".csv", ".nmap", ".gnmap", ".xml", ".html"))
        view_btn = f'''<button class="btn btn-view" onclick="viewFile('{html.escape(f["name"])}')">Preview</button>''' if is_viewable else ""
        download_btn = f'''<a class="btn btn-dl" href="/raw/{html.escape(f["name"])}" download>Download</a>'''
        badge_cls = f"badge-{f['tag']}"
        rows_html += f"""
        <tr>
            <td class="filename"><strong>{html.escape(f["name"])}</strong></td>
            <td><span class="badge {badge_cls}">{html.escape(f["tool"])}</span></td>
            <td>{html.escape(f["size"])}</td>
            <td class="mtime">{html.escape(f["mtime"])}</td>
            <td class="actions">{view_btn} {download_btn}</td>
        </tr>
        """

    if not rows_html:
        rows_html = '<tr><td colspan="5" class="empty">No scan results found in directory. Run a scan to populate findings.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Parrot Recon - Results Explorer</title>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --surface-hover: #1c2128;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --primary: #58a6ff;
            --primary-hover: #79c0ff;
            --accent: #238636;
            --danger: #f85149;
            --warning: #d29922;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 24px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding-bottom: 20px;
            margin-bottom: 24px;
            border-bottom: 1px solid var(--border);
        }}
        .brand {{ display: flex; align-items: center; gap: 14px; }}
        .brand h1 {{
            font-size: 24px;
            color: #f0f6fc;
            letter-spacing: -0.5px;
        }}
        .brand span.tagline {{
            color: var(--text-muted);
            font-size: 14px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px;
        }}
        .stat-card .label {{ color: var(--text-muted); font-size: 12px; text-transform: uppercase; font-weight: 600; }}
        .stat-card .val {{ font-size: 24px; font-weight: 700; color: #f0f6fc; margin-top: 4px; }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            overflow: hidden;
            margin-bottom: 24px;
        }}
        .card-header {{
            padding: 14px 18px;
            background: #19202a;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .card-header h2 {{ font-size: 16px; font-weight: 600; color: #f0f6fc; }}
        .search-box {{
            padding: 6px 12px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 4px;
            color: var(--text);
            font-size: 13px;
            width: 250px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
            text-align: left;
        }}
        th {{
            background: #13171e;
            padding: 10px 18px;
            color: var(--text-muted);
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            border-bottom: 1px solid var(--border);
        }}
        td {{
            padding: 12px 18px;
            border-bottom: 1px solid var(--border);
        }}
        tr:hover td {{ background: var(--surface-hover); }}
        .filename {{ font-family: monospace; font-size: 13px; color: #58a6ff; }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            background: #21262d;
            color: var(--text);
        }}
        .badge-summary {{ background: #238636; color: #fff; }}
        .badge-nmap {{ background: #1f6feb; color: #fff; }}
        .badge-nuclei {{ background: #8957e5; color: #fff; }}
        .badge-nikto {{ background: #d29922; color: #fff; }}
        .badge-subdomains {{ background: #388bfd; color: #fff; }}
        .badge-takeover {{ background: #f85149; color: #fff; }}
        .actions {{ display: flex; gap: 8px; }}
        .btn {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            text-decoration: none;
            cursor: pointer;
            border: 1px solid var(--border);
            font-weight: 500;
            background: #21262d;
            color: var(--text);
            transition: all 0.15s ease;
        }}
        .btn:hover {{ background: #30363d; border-color: #8b949e; }}
        .btn-view {{ background: #1f6feb; border-color: #1f6feb; color: white; }}
        .btn-view:hover {{ background: #388bfd; border-color: #388bfd; }}
        .btn-dl {{ background: #238636; border-color: #238636; color: white; }}
        .btn-dl:hover {{ background: #2ea043; border-color: #2ea043; }}
        .empty {{ text-align: center; padding: 40px; color: var(--text-muted); }}

        /* Modal Preview */
        .modal-bg {{
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(4px);
            z-index: 1000;
            padding: 40px;
        }}
        .modal {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            max-width: 1000px;
            height: 80vh;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            box-shadow: 0 16px 32px rgba(0,0,0,0.5);
        }}
        .modal-header {{
            padding: 14px 20px;
            background: #19202a;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .modal-title {{ font-size: 15px; font-weight: 600; color: #f0f6fc; font-family: monospace; }}
        .modal-close {{
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-size: 20px;
            cursor: pointer;
        }}
        .modal-close:hover {{ color: #f0f6fc; }}
        .modal-body {{
            padding: 20px;
            overflow-y: auto;
            flex: 1;
            background: #0d1117;
        }}
        pre.preview-code {{
            color: #e6edf3;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
            font-size: 13px;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .webdav-banner {{
            background: #161b22;
            border: 1px dashed var(--border);
            border-radius: 6px;
            padding: 12px 18px;
            font-size: 13px;
            color: var(--text-muted);
            margin-top: 16px;
        }}
        .webdav-banner strong {{ color: #f0f6fc; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div>
                    <h1>🦜 Parrot Recon <span style="font-size:16px; color:#58a6ff; font-weight:400;">Results Explorer</span></h1>
                    <span class="tagline">Automated Reconnaissance & Vulnerability Assessment Dashboard</span>
                </div>
            </div>
            <div>
                <a class="btn btn-dl" href="/results-archive.tar.gz" style="padding:6px 14px; font-size:13px;">Export All (.tar.gz)</a>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Total Scan Artifacts</div>
                <div class="val">{total_files}</div>
            </div>
            <div class="stat-card">
                <div class="label">Storage Consumed</div>
                <div class="val">{total_size_str}</div>
            </div>
            <div class="stat-card">
                <div class="label">Active Directory</div>
                <div class="val" style="font-size:14px; font-family:monospace; margin-top:8px; color:#58a6ff;">{html.escape(results_dir)}</div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h2>Generated Scan Findings & Artifacts</h2>
                <input type="text" id="filterInput" class="search-box" placeholder="Filter files or tools..." onkeyup="filterTable()">
            </div>
            <table id="resultsTable">
                <thead>
                    <tr>
                        <th>File Name</th>
                        <th>Scan Module</th>
                        <th>Size</th>
                        <th>Last Modified</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>

        <div class="webdav-banner">
            <strong>WebDAV Access:</strong> You can mount this server directly in your operating system's file manager at <code>http://{DEFAULT_HOST}:{DEFAULT_PORT}/</code> or configure WsgiDAV for native OS drive mapping.
        </div>
    </div>

    <!-- Modal for previewing text reports -->
    <div id="previewModal" class="modal-bg" onclick="closeModalOnBg(event)">
        <div class="modal">
            <div class="modal-header">
                <span id="modalFilename" class="modal-title">filename</span>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body">
                <pre id="modalContent" class="preview-code">Loading...</pre>
            </div>
        </div>
    </div>

    <script>
        function filterTable() {{
            const val = document.getElementById('filterInput').value.toLowerCase();
            const rows = document.querySelectorAll('#resultsTable tbody tr');
            rows.forEach(r => {{
                const text = r.textContent.toLowerCase();
                r.style.display = text.includes(val) ? '' : 'none';
            }});
        }}

        function viewFile(name) {{
            document.getElementById('modalFilename').textContent = name;
            document.getElementById('modalContent').textContent = "Loading file content...";
            document.getElementById('previewModal').style.display = 'block';
            fetch('/raw/' + encodeURIComponent(name))
                .then(r => r.text())
                .then(t => {{
                    document.getElementById('modalContent').textContent = t;
                }})
                .catch(err => {{
                    document.getElementById('modalContent').textContent = "Failed to load preview: " + err;
                }});
        }}

        function closeModal() {{
            document.getElementById('previewModal').style.display = 'none';
        }}

        function closeModalOnBg(e) {{
            if (e.target.id === 'previewModal') {{
                closeModal();
            }}
        }}

        document.addEventListener('keydown', e => {{
            if (e.key === 'Escape') closeModal();
        }});
    </script>
</body>
</html>
"""


class ResultsHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    results_dir = "results"

    def do_OPTIONS(self):
        # WebDAV options probe response
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS, PROPFIND")
        self.send_header("DAV", "1, 2")
        self.send_header("MS-Author-Via", "DAV")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PROPFIND(self):
        # Fallback WebDAV PROPFIND response if client mounts via WebDAV
        self.send_response(207, "Multi-Status")
        self.send_header("Content-Type", "application/xml; charset=utf-8")
        xml_resp = """<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"""
        body_bytes = xml_resp.encode("utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)

        if path in ("/", "/index.html", "/dashboard"):
            dashboard_html = render_dashboard_html(self.results_dir)
            body = dashboard_html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/files":
            files_meta = []
            if os.path.isdir(self.results_dir):
                for f in sorted(os.listdir(self.results_dir)):
                    full = os.path.join(self.results_dir, f)
                    if os.path.isfile(full):
                        size, size_str, mod_time = get_file_metadata(full)
                        tool_name, tool_tag = identify_tool(f)
                        files_meta.append({
                            "name": f,
                            "tool": tool_name,
                            "tag": tool_tag,
                            "size_bytes": size,
                            "size_formatted": size_str,
                            "modified": mod_time
                        })
            body = json.dumps(files_meta, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path.startswith("/raw/"):
            filename = os.path.basename(path[5:])
            file_path = os.path.join(self.results_dir, filename)
            if not os.path.isfile(file_path):
                self.send_error(404, f"File {filename} not found")
                return

            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                mime, _ = mimetypes.guess_type(file_path)
                if not mime:
                    mime = "text/plain; charset=utf-8" if file_path.endswith((".txt", ".md", ".nmap", ".gnmap")) else "application/octet-stream"
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            except Exception as e:
                self.send_error(500, f"Error reading file: {e}")
                return

        # Direct static file access
        clean_path = path.lstrip("/")
        file_path = os.path.join(self.results_dir, clean_path)
        if os.path.isfile(file_path):
            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                mime, _ = mimetypes.guess_type(file_path) or ("text/plain", None)
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            except Exception as e:
                self.send_error(500, f"Error reading file: {e}")
                return

        self.send_error(404, "Endpoint or file not found")


def start_server(host=DEFAULT_HOST, port=DEFAULT_PORT, results_dir="results"):
    os.makedirs(results_dir, exist_ok=True)
    ResultsHTTPRequestHandler.results_dir = os.path.abspath(results_dir)

    # Check if wsgidav is available; if so, notify user
    wsgidav_available = False
    try:
        import wsgidav  # noqa
        wsgidav_available = True
    except ImportError:
        wsgidav_available = False

    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    server = ReusableTCPServer((host, port), ResultsHTTPRequestHandler)
    print(f"\n=======================================================")
    print(f"🦜 Parrot Recon Results Web Server Running")
    print(f"=======================================================")
    print(f"[*] Serving results from: {os.path.abspath(results_dir)}")
    print(f"[+] Web Dashboard:        http://{host}:{port}/")
    print(f"[+] API JSON Feed:        http://{host}:{port}/api/files")
    if wsgidav_available:
        print(f"[+] WebDAV Support:       Enabled (WsgiDAV available)")
    else:
        print(f"[*] Native WebDAV:        Web client active (install 'wsgidav' for full OS mount)")
    print(f"[*] Press Ctrl+C to stop the server\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping results server...")
        server.shutdown()
        server.server_close()
        print("[+] Server stopped.")


def main():
    parser = argparse.ArgumentParser(description="Parrot Recon Results Web Server & WebDAV Browser")
    parser.add_argument("-p", "--port", type=int, default=int(os.environ.get("RECON_PORT", DEFAULT_PORT)), help="Port to bind (default: 8098)")
    parser.add_argument("-H", "--host", default=os.environ.get("RECON_HOST", DEFAULT_HOST), help="Host address to bind (default: 127.0.0.1)")
    parser.add_argument("-d", "--dir", default=os.environ.get("RECON_RESULTS_DIR", "results"), help="Results directory (default: results)")
    parser.add_argument("--daemon", action="store_true", help="Run server in background daemon thread")

    args = parser.parse_args()

    if args.daemon:
        t = threading.Thread(target=start_server, args=(args.host, args.port, args.dir), daemon=True)
        t.start()
        print(f"[+] Daemon started on http://{args.host}:{args.port}/")
        return

    start_server(args.host, args.port, args.dir)


if __name__ == "__main__":
    main()

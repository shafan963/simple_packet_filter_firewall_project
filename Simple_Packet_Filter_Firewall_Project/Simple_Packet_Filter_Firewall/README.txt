SENTINEL - SIMPLE PACKET FILTER / FIREWALL RULES ENGINE v1.1.0
=======================================================

PROJECT CONTENTS
----------------
src/server.c       Main C backend: HTTP server, firewall rule engine, packet evaluator
public/index.html  Dashboard structure
public/style.css   Dark cybersecurity theme, responsive styling and animations
public/app.js      Frontend interactions and API calls
build.bat          Windows GCC build script

REQUIREMENTS
------------
1. Windows 10/11
2. Visual Studio Code
3. GCC compiler (MinGW-w64 / MSYS2)
4. A modern browser

BUILD AND RUN (WINDOWS)
-----------------------
1. Extract this folder.
2. Open the folder in VS Code.
3. Install GCC (MinGW-w64). Ensure gcc is available in PATH.
4. Open VS Code Terminal (Terminal > New Terminal).
5. Run:
      gcc --version
   If a version appears, GCC is ready.
6. Build:
      gcc src/server.c -o server.exe -lws2_32 -Wall
   Or double-click build.bat.
7. Start the backend:
      .\server.exe
8. Keep the terminal open.
9. Open http://localhost:8080 in your browser.

The server serves the dashboard and API from the same origin. It binds only to
127.0.0.1; do not change this to a public network interface.

TEMPORARY PUBLIC DEMO (CLOUDFLARE QUICK TUNNEL)
------------------------------------------------
For a temporary, shareable HTTPS link, install cloudflared from Cloudflare's
official documentation, start server.exe, then run in a second terminal:
      & "${env:ProgramFiles(x86)}\cloudflared\cloudflared.exe" tunnel --url http://127.0.0.1:8080
Share only the https://*.trycloudflare.com link printed by cloudflared. Keep
both processes running; stopping either one takes the demo offline. The URL is
temporary and may change each time. Anyone with the link can use the demo,
including adding and deleting in-memory rules. Restarting the server resets
rules and packet statistics. The public link exposes only this simulator; it
does not provide real network or Windows Firewall access.

The public demo has request-size and rate limits, input validation, strict
same-origin API access, security headers, and socket timeouts. It is still an
educational demo, not a production service; stop the tunnel when finished.

TEST CASES
----------
Protocol  Port   Expected result   Reason
TCP       443    ALLOW              HTTPS allow rule
TCP       80     ALLOW              HTTP allow rule
UDP       53     ALLOW              DNS allow rule
TCP       23     BLOCK              Telnet block rule
TCP       8081   BLOCK              Suspicious port block rule
TCP       22     BLOCK              No matching rule; default deny
ICMP      0      BLOCK              No matching rule; default deny

HOW THE C ENGINE WORKS
----------------------
1. The browser collects packet attributes.
2. JavaScript sends a JSON request to the C backend.
3. The C server reads protocol and destination port.
4. The filtering engine checks enabled rules in order.
5. The first matching rule determines ALLOW or BLOCK.
6. If no rule matches, the default policy is BLOCK.
7. The C server returns a JSON decision.
8. The dashboard updates the result, statistics and activity log.

IMPORTANT TECHNICAL NOTE
-----------------------
This is a learning/demo packet-filtering simulator. It does NOT capture real
network packets, inspect live traffic, or change Windows Firewall rules.
The HTTP server binds to localhost and is intended for local demonstration only.
For a production project, add robust HTTP parsing, request-size/body-length
handling, authentication, persistence, validation, and a mature server stack.

# Documents To Go (com.dataviz.docstogo) – Proof‑of‑Concept Notes

No specific, public CVEs could be attributed to this APK or its bundled components based on the evidence gathered (manifest‑level inspection, absence of native libraries, and targeted web search).

Because no concrete CVEs are identified, **no CVE‑tied PoCs** are provided here.

However, from a general security‑testing perspective, the following **generic test ideas** may be useful when manually assessing this app (not tied to any known CVE):

1. **Malicious Office / Excel document parsing**
   - Since the app registers VIEW/EDIT intents for Excel and related formats, craft malformed or oversized `.xls` / `.xlsx` / macro‑enabled files and open them via:
     - Email attachments (using apps that can share with Documents To Go)
     - File manager VIEW intents
   - Watch for crashes, memory issues, or unexpected behavior.

2. **External storage document handling**
   - Place crafted files on shared external storage and trigger the app to open them.
   - Check for path‑traversal‑like issues or insecure temporary file handling.

3. **Network communication tests**
   - Because the app uses `INTERNET` and the legacy `org.apache.http.legacy`, test for:
     - Insecure TLS validation (MITM with custom certificate)
     - Cleartext traffic (even though `usesCleartextTraffic` is allowed, per manifest)

These are **generic hardening / assessment ideas**, not PoCs for any specific identified vulnerability.
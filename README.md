# Nmap-Post-Port-Scans
Comprehensive Nmap post-scan recon using -sV, -O, -sC, --script, --traceroute, and -oA to enumerate service versions, OS fingerprints, and vulnerabilities for structured threat analysis.

By Ramyar Daneshgar


# Post-Scan Host Enumeration using Nmap

After identifying responsive hosts and open TCP ports during the initial reconnaissance phase, I transitioned into post-scan enumeration using Nmap’s extended modules. This phase focused on gathering deeper contextual data tied to each exposed service, extracting protocol-level metadata, fingerprinting operating systems based on network behavior, and identifying scripts capable of revealing misconfigurations, insecure defaults, or known vulnerabilities. Additionally, I ensured the output was persisted in formats conducive to both human review and automated ingestion.

---

## Phase 1: Service and Version Detection (`-sV` with Version Tuning)

Command used:

```bash
sudo nmap -sV --version-light 10.10.160.16
```

Once ports were identified, I launched Nmap’s service detection module to transition from a port-state view to a service-level view. The `-sV` flag instructed Nmap to engage in full TCP handshakes with each open port and interact directly with the application-layer protocol. This enabled banner grabbing and protocol fingerprinting through prebuilt probes. I used `--version-light` to balance discovery fidelity with low network noise, which is crucial in stealth-sensitive environments or when operating within limited time windows.

The scan returned identifiable software packages for services such as:

* `OpenSSH` running on port 22 with a version banner of `6.7p1 Debian`
* `nginx 1.6.2` on port 80 with standard HTTP responses
* `Dovecot imapd` on port 143

However, the version for `rpcbind` on port 111 was not returned—this is expected behavior under lighter probing levels, as certain daemons intentionally suppress version strings or delay responses that low-intensity scans won’t elicit. This informed a decision point: if vulnerability mapping against `rpcbind` were a priority, I would escalate intensity using `--version-all`.

---

## Phase 2: OS Detection and Network Topology Discovery (`-O`, `--traceroute`)

OS fingerprinting provides foundational intelligence for shaping subsequent engagement steps. I launched:

```bash
sudo nmap -sS -O 10.10.160.16
```

This leveraged TCP/IP stack signature analysis—comparing response patterns such as TCP initial sequence numbers, window sizes, and IP ID behavior against Nmap’s OS database. The scan identified the target as a Linux machine, specifically fingerprinting kernel 3.13. While the host was actually running 3.16, the proximity confirmed that Nmap’s fingerprint database had a reliable match. These results are often sufficient to determine exploit compatibility, particularly when kernel-specific modules or memory layout assumptions are required.

I also mapped the path to the target:

```bash
sudo nmap -sS --traceroute 10.10.160.16
```

Nmap’s traceroute implementation decreases TTL values from a maximum, unlike the traditional increasing TTL method. In this case, the traceroute revealed a single-hop connection, confirming the host resides on the same broadcast domain or subnet as the scanner. No intermediary routers or NAT boundaries were present, suggesting lateral movement paths would be viable without additional segmentation controls. This is a valuable insight when assessing east-west movement feasibility in a compromise scenario.

---

## Phase 3: Nmap Scripting Engine (NSE) – Protocol-Specific Attack Surface Mapping

Command used:

```bash
sudo nmap -sS -sC 10.10.160.16
```

The Nmap Scripting Engine expands static enumeration into dynamic, protocol-aware reconnaissance. With `-sC`, I triggered the default set of scripts—preselected by Nmap to provide general but safe reconnaissance output. These scripts identified exposed cryptographic material, service banners, and protocol capabilities:

* **SSH (`ssh-hostkey`)**: Returned all supported host key algorithms including:

  * 1024-bit DSA
  * 2048-bit RSA
  * 256-bit ECDSA and Ed25519
    This level of granularity is essential for analyzing the cryptographic posture of SSH implementations, particularly when validating compliance with NIST SP 800-131A or preparing for downgrade or key exhaustion scenarios.

* **SMTP (`smtp-commands`, `ssl-cert`)**: Extracted full SMTP verb support, including STARTTLS, and certificate metadata such as CN and expiration window. This supports MTA-to-MTA encryption analysis and client certificate trust boundary validation.

* **HTTP (`http-title`)**: Retrieved the default web server banner indicating a non-customized nginx welcome page. This signals likely misconfiguration or lack of hardening on the web layer.

To further extend scan capabilities, I ran:

```bash
sudo nmap -sS -n --script "http-date" 10.10.160.16
```

This script confirmed the HTTP server time and measured drift relative to the scanner host. Clock drift analysis is a subtle but important vector in scenarios involving Kerberos-based SSO, time-sensitive tokens, or anomaly detection based on log timelines.

While browsing NSE scripts under `/usr/share/nmap/scripts`, I also scoped out advanced script usage:

* `http-robots.txt`: For identifying crawler exclusions that may unintentionally expose hidden paths
* `http-vuln-cve2015-1635`: Scans for remote code execution via buffer overflow in HTTP.sys (used in vulnerable Windows IIS builds)
* `ssh2-enum-algos`: Enumerates supported SSH2 algorithms, including MAC, encryption, and compression options. The target advertised support for `rsa-sha2-512`, indicating modern cryptographic support.

These scripts can be selectively loaded using:

```bash
--script=<script-name>
```

or grouped by category:

```bash
--script=default,vuln
```

Allowing flexibility in balancing scan aggressiveness with informational value.

---

## Phase 4: Exporting Results for Audit, Triage, and Automation

Preserving reconnaissance output in structured formats is critical for repeatability, audit trails, and integration into broader toolchains. I used:

```bash
nmap -sS -sV -O -oA MACHINE_IP_scan 10.10.160.16
```

This generated:

* `MACHINE_IP_scan.nmap`: Full human-readable report
* `MACHINE_IP_scan.gnmap`: Grep-friendly output for scripting
* `MACHINE_IP_scan.xml`: Structured XML for import into tools like Splunk, ELK, or vulnerability management platforms

To extract targeted indicators across hosts, I ran:

```bash
grep http MACHINE_IP_scan.gnmap
```

This revealed host IP, port, protocol, service, and version—all within a single line. In contrast, `.nmap` output is multiline and not suited for regex-based workflows. The `.xml` format allows parsing using XSLT, Python scripts, or native SIEM connectors.

Lastly, I pulled stored artifacts from the target VM using:

```bash
scp pentester@10.10.160.16:/home/pentester/* .
```

Credentials: `THM17577`

Reviewing the downloaded logs, I confirmed:

* **Three distinct hosts were running HTTPS (port 443)**
* **Port 8089** was exposed by **172.17.20.147**, a port commonly associated with Splunk Web or other admin interfaces. This endpoint should be prioritized for further analysis or password spraying if permitted by scope.

---

## Key Lessons Reinforced

* Service enumeration must account for connection-based probing; version detection relies on handshake completion and protocol compliance.
* OS fingerprinting accuracy improves significantly when closed ports are accessible—Nmap uses them to observe how the host responds to invalid requests, a method harder to spoof.
* NSE provides highly modular recon capabilities—its strength lies in combining precision-targeted scripts with protocol-specific knowledge. Scripts must be reviewed for intrusiveness before use, especially in production or scoped engagements.
* Structured output formats (`-oA`) are essential for maintaining analysis integrity across tools, collaborators, or phases of engagement.
* Lateral risk can be inferred from traceroute outputs, open management ports, and lack of segmentation.

This engagement demonstrated how layered recon, when properly configured and interpreted, forms the foundation of technical threat modeling and infrastructure discovery. I leveraged Nmap not just as a scanner, but as a modular intelligence collection tool that ties network observations to exploitable conditions, misconfigurations, and detection gaps.

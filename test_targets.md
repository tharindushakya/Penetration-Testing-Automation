# Safe Test Targets for Penetration Testing

## Legal Testing Targets (Always Safe)

### 1. Local Testing
- `localhost` / `127.0.0.1` - Your own machine
- `192.168.1.1` - Your router (if you own it)
- Virtual machines you control

### 2. Intentionally Vulnerable Applications
- **DVWA** (Damn Vulnerable Web Application)
  - URL: http://www.dvwa.co.uk/
  - Local setup for web app testing
  
- **Metasploitable** 
  - Intentionally vulnerable Linux VM
  - Download from Rapid7
  
- **VulnHub VMs**
  - URL: https://www.vulnhub.com/
  - Free vulnerable VMs for practice

### 3. Online Practice Platforms
- **HackTheBox** (hackthebox.eu)
  - Retired machines section (free)
  - Active lab (subscription)
  
- **TryHackMe** (tryhackme.com)
  - Free learning paths
  - Practice rooms

### 4. Demo/Example Domains (Read-only testing)
- `example.com` - IANA reserved domain
- `httpbin.org` - HTTP testing service
- `jsonplaceholder.typicode.com` - Fake REST API

## NEVER Test Without Permission
- Any website/server you don't own
- Corporate networks
- Government sites
- Production systems

## Legal Notes
- Always get written permission
- Only test systems you own or have explicit authorization
- Check local laws and regulations
- Consider bug bounty programs for legitimate testing

## Quick Test Commands
```bash
# Test local machine
./pentest.exe
# Enter: localhost

# Test example domain (safe)
./pentest.exe  
# Enter: example.com
```

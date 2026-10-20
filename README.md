# SSH Log Analyzer

A Python script that reads a Linux `auth.log` file and finds SSH brute force attempts. I wrote it after the Linux and Intro to Cybersecurity courses to practice reading real system logs.

## What it does
- Counts failed SSH logins for each IP
- Shows which usernames each IP tried (attackers usually try `admin`, `root`, `test`...)
- Flags IPs with too many failed attempts
- Warns if an IP with many failures later logged in successfully (could mean the password was guessed)
- Prints `ufw` commands to block the suspicious IPs

## Usage
```bash
python analyzer.py /var/log/auth.log
python analyzer.py sample_auth.log --limit 5
```
On Linux you may need `sudo` to read `/var/log/auth.log`.

## Example output
```
=== Failed logins by IP ===
45.33.12.8         12 attempts  users: admin, oracle, pi, test  <-- possible brute force
103.77.21.4         7 attempts  users: root  <-- possible brute force
192.168.1.15        1 attempts  users: khalid

=== Successful logins ===
Oct 18 03:29:40  root       from 103.77.21.4  <-- WARNING: this ip had failed attempts
Oct 18 09:05:20  khalid     from 192.168.1.15

2 suspicious IPs

To block them with ufw:
  sudo ufw deny from 45.33.12.8
  sudo ufw deny from 103.77.21.4
```

`sample_auth.log` is a small test log so you can try it without a server.

## How to protect a server from this
- Use SSH keys and disable password login (`PasswordAuthentication no`)
- Disable root login (`PermitRootLogin no`)
- Use fail2ban to block IPs automatically

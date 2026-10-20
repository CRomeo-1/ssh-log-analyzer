import argparse
import re
from collections import Counter, defaultdict

FAILED = re.compile(r"Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
ACCEPTED = re.compile(r"Accepted \S+ for (\S+) from (\d+\.\d+\.\d+\.\d+)")


def analyze(path):
    failed_by_ip = Counter()
    users_by_ip = defaultdict(set)
    logins = []

    with open(path, errors="ignore") as f:
        for line in f:
            m = FAILED.search(line)
            if m:
                user, ip = m.group(2), m.group(3)
                failed_by_ip[ip] += 1
                users_by_ip[ip].add(user)
                continue

            m = ACCEPTED.search(line)
            if m:
                logins.append((m.group(1), m.group(2), line[:15]))

    return failed_by_ip, users_by_ip, logins


def main():
    parser = argparse.ArgumentParser(description="Detect SSH brute force attempts from auth.log")
    parser.add_argument("logfile", help="path to auth.log")
    parser.add_argument("--limit", type=int, default=5, help="failed attempts before an ip is flagged")
    args = parser.parse_args()

    failed, users, logins = analyze(args.logfile)

    print("=== Failed logins by IP ===")
    for ip, count in failed.most_common():
        flag = "  <-- possible brute force" if count >= args.limit else ""
        print(f"{ip:<16} {count:>4} attempts  users: {', '.join(sorted(users[ip]))[:40]}{flag}")

    print("\n=== Successful logins ===")
    for user, ip, time in logins:
        # a successful login from an ip that also failed a lot is suspicious
        warn = "  <-- WARNING: this ip had failed attempts" if failed[ip] >= args.limit else ""
        print(f"{time}  {user:<10} from {ip}{warn}")

    flagged = [ip for ip, c in failed.items() if c >= args.limit]
    print(f"\n{len(flagged)} suspicious IPs")
    if flagged:
        print("\nTo block them with ufw:")
        for ip in flagged:
            print(f"  sudo ufw deny from {ip}")


if __name__ == "__main__":
    main()

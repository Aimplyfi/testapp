import time
import requests

SERVER = "https://vuln-server-service/run"

# Simple safe command
payload = "uname"

while True:
    try:
        r = requests.get(SERVER, params={"cmd": payload}, verify=False)
        print("Response from server:")
        print(r.text)
    except Exception as e:
        print("Error:", e)

    time.sleep(15)
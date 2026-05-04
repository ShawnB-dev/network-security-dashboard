import redis
import json

def inspect_nvd_cache():
    print("[*] Inspecting Redis DB 1 (NVD Cache)...")
    try:
        # Connect to DB 1 where we store security findings
        client = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        
        # Scan for NVD cache keys
        keys = client.keys("nvd_cache:*")
        
        if not keys:
            print("[!] The NVD cache is currently empty. Run a scan with fingerprinting enabled.")
            return

        print(f"[*] Found {len(keys)} entries in cache:\n")
        for key in keys:
            # Extract the service keyword from the key name
            keyword = key.replace("nvd_cache:", "")
            data = client.get(key)
            findings = json.loads(data)
            
            print(f"--- Service: {keyword} ---")
            for f in findings:
                print(f"  - [{f['severity']}] {f['title']}")
            if not findings:
                print("  (Empty list cached - negative caching active)")
            print()

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    inspect_nvd_cache()
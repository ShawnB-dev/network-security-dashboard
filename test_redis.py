import redis

def check_redis():
    print("[*] Attempting to connect to Redis at localhost:6379...")
    try:
        # Check DB 0 (Celery Broker/Backend)
        client_db0 = redis.Redis(host='localhost', port=6379, db=0, socket_timeout=2)
        if client_db0.ping():
            print("✅ Success: Redis DB 0 (Celery) is active.")
        
        # Check DB 1 (Security Engine Cache)
        client_db1 = redis.Redis(host='localhost', port=6379, db=1, socket_timeout=2)
        if client_db1.ping():
            print("✅ Success: Redis DB 1 (Cache) is active.")
            
        print("\n[!] Connectivity confirmed: Windows can reach WSL Redis via localhost.")

    except redis.exceptions.ConnectionError:
        print("❌ Error: Connection failed.")
        print("    1. Ensure 'sudo service redis-server start' was run in WSL.")
        print("    2. Check if Redis is bound to 127.0.0.1 in /etc/redis/redis.conf.")
        print("    3. Try running 'Test-NetConnection -ComputerName localhost -Port 6379' in PowerShell.")
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")

if __name__ == "__main__":
    check_redis()
import math
import hashlib
import sys

def calculate_entropy(password):
    pool_size = 0
    if any(c.islower() for c in password): pool_size += 26
    if any(c.isupper() for c in password): pool_size += 26
    if any(c.isdigit() for c in password): pool_size += 10
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password): pool_size += 32

    if pool_size == 0 or len(password) == 0:
        return 0, 0

    entropy = len(password) * math.log2(pool_size)
    combinations = pool_size ** len(password)
    return entropy, combinations

def simulate_dictionary_attack(target_hash, wordlist):
    print("\n--- ⚡ Simulating Hash Crack Attack ---")
    for word in wordlist:
        hashed = hashlib.sha256(word.encode('utf-8')).hexdigest()
        if hashed == target_hash:
            return True, word
    return False, None

def evaluate_password(password):
    entropy, combinations = calculate_entropy(password)
    print("=" * 60)
    print(f"🔐 Password Security Audit")
    print("=" * 60)
    print(f"Password Length: {len(password)} characters")
    print(f"Entropy Score : {entropy:.2f} bits")
    print(f"Search Space  : {combinations:.2e} total combinations")
    
    if entropy < 28:
        strength = "VERY WEAK 🔴 (Instant Crack)"
    elif entropy < 36:
        strength = "WEAK 🟠 (Cracked in minutes)"
    elif entropy < 60:
        strength = "MODERATE 🟡 (Cracked in days/weeks)"
    elif entropy < 80:
        strength = "STRONG 🟢 (Resistant to brute-force)"
    else:
        strength = "VERY STRONG 🟢 (Cryptographically Secure)"
        
    print(f"Rating        : {strength}")
    print("=" * 60)

    # Demo hash attack
    demo_secret = "admin123"
    target_hash = hashlib.sha256(demo_secret.encode()).hexdigest()
    common_passwords = ["123456", "password", "admin", "welcome", "admin123", "letmein"]
    
    print(f"Target SHA-256 Hash: {target_hash}")
    found, word = simulate_dictionary_attack(target_hash, common_passwords)
    if found:
        print(f"🎯 Hash Match Found! Plaintext: '{word}'")

def main():
    sample_pass = sys.argv[1] if len(sys.argv) > 1 else "P@ssw0rd2026!Secure"
    evaluate_password(sample_pass)

if __name__ == "__main__":
    main()

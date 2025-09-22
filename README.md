# rsa-secure-communication
Python project for RSA key generation, encryption, and decryption.
import random
from math import gcd

# ---------------------------
# Helper Functions
# ---------------------------

# Check if a number is prime
def is_prime(n):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

# Generate a random prime number in a given range
def generate_prime(start=100, end=300):
    while True:
        num = random.randint(start, end)
        if is_prime(num):
            return num

# Compute modular inverse using Extended Euclidean Algorithm
def mod_inverse(e, phi):
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

    g, x, _ = egcd(e, phi)
    if g != 1:
        return None
    return x % phi

# ---------------------------
# RSA Key Generation
# ---------------------------
def generate_rsa_keys():
    print("\n[+] Generating RSA keys...")

    # 1. Generate two distinct prime numbers
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()

    # 2. Compute n = p * q
    n = p * q

    # 3. Compute phi(n) = (p - 1) * (q - 1)
    phi = (p - 1) * (q - 1)

    # 4. Choose e (1 < e < phi) such that gcd(e, phi) = 1
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    # 5. Compute d such that (d * e) % phi = 1
    d = mod_inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)

    print(f"Generated primes p={p}, q={q}")
    print(f"Public Key (e, n): {public_key}")
    print(f"Private Key (d, n): {private_key}")

    return public_key, private_key

# ---------------------------
# Encryption and Decryption
# ---------------------------
def encrypt(message, public_key):
    e, n = public_key
    encrypted = [pow(ord(char), e, n) for char in message]
    return encrypted

def decrypt(ciphertext, private_key):
    d, n = private_key
    decrypted = ''.join(chr(pow(char, d, n)) for char in ciphertext)
    return decrypted

# ---------------------------
# Main Program
# ---------------------------
def main():
    print("=== RSA Secure Communication Tool ===")

    # Generate RSA keys
    public_key, private_key = generate_rsa_keys()

    # Sender encrypts a message
    message = input("\nEnter a message to encrypt: ")
    ciphertext = encrypt(message, public_key)
    print("\nEncrypted message:", ciphertext)

    # Receiver decrypts the message
    decrypted_message = decrypt(ciphertext, private_key)
    print("Decrypted message:", decrypted_message)

    # Verify
    if decrypted_message == message:
        print("\n[+] Secure communication successful!")
    else:
        print("\n[-] Something went wrong!")

if __name__ == "__main__":
    main()

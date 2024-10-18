import sympy
import random

def is_prime(n):
    """sympy kütüphanesiyle sayının asal olup olmadığını kontrol eder."""
    return sympy.isprime(n)

def generate_large_prime(bits=256):
    """Verilen bit sayısına göre büyük bir asal sayı üretir."""
    return sympy.randprime(2**(bits-1), 2**bits)

def generate_two_large_primes(bits=256):
    """Verilen bit sayısına göre iki farklı büyük asal sayı üretir."""
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    
    while p == q:
        q = generate_large_prime(bits)
        
    return p, q

def n_number(p, q):
    """Verilen p ve q asal sayılarının çarpımını döndürür."""
    n = p * q
    return n

def euler_totient(p, q):
    """Verilen p ve q asal sayılarıyla Euler Totient fonksiyonunu hesaplar."""
    t = (p - 1) * (q - 1)
    return t

def generate_e(t):
    """1 ile Euler Totient arasında rastgele bir e değeri seçer ve gcd(t, e) = 1 olana kadar tekrarlar."""
    while True:
        e = random.randint(2, t - 1)
        if sympy.gcd(t, e) == 1:
            return e

def find_mod_inverse(e, t):
    """Verilen e sayısının t moduna göre tersini bulur."""
    d = sympy.mod_inverse(e, t)
    return d

def encrypt_message(m, e, n):
    """Mesajı public key (e, n) ile şifreler: c = m^e mod n."""
    c = pow(m, e, n)  # Python'da pow(m, e, n) ile m^e mod n hesaplanır
    return c

def decrypt_message(c, d, n):
    """Decrypt the ciphertext c using private key (d, n)."""
    return pow(c, d, n)

def string_to_number(message):
    """Metni sayıya dönüştürür (UTF-8 encoding kullanarak)."""
    return int.from_bytes(message.encode(), 'big')

def number_to_string(number):
    """Sayıyı tekrar metne dönüştürür."""
    return number.to_bytes((number.bit_length() + 7) // 8, 'big').decode()

def main():
    # 256 bitlik iki büyük asal sayı üretelim
    p, q = generate_two_large_primes(bits=256)
    print(f"p = {p}")
    print(f"q = {q}")

    # Asallık kontrolü yapalım
    print(f"Checking if p = {p} is prime...")
    if is_prime(p):
        print(f"{p} IS PRIME.")
    else:
        print(f"{p} IS NOT PRIME.")
    
    print(f"Checking if q = {q} is prime...")
    if is_prime(q):
        print(f"{q} IS PRIME.")
    else:
        print(f"{q} IS NOT PRIME.")
    
    # n = p * q sonucunu yazdıralım
    n = n_number(p, q)
    print(f"n = p * q = {n}")
    
    # Euler Totient fonksiyonu hesaplayalım
    t = euler_totient(p, q)
    print(f"Euler Totient sonucu: {t}")
    
    # Gcd(t, e) = 1 olana kadar e seçelim
    e = generate_e(t)
    print(f"Seçilen public key (e): {e}")
    
    # e'nin t moduna göre tersini (d) hesaplayalım
    d = find_mod_inverse(e, t)
    print(f"Seçilen private key (d): {d}")
    
    # Kullanıcıdan mesajı alalım (string olarak)
    message = input("Lütfen bir mesaj girin: ")
    
    # Mesajı sayıya dönüştürelim
    m = string_to_number(message)
    
    if m <= 0 or m >= n:
        print(f"Geçersiz mesaj! 0 < m < {n} aralığında olmalıdır.")
        return
    
    # Mesajı şifreleyelim
    c = encrypt_message(m, e, n)
    print(f"Şifrelenmiş mesaj (ciphertext) c = {c}")

    # Decrypt message
    decrypted_m = decrypt_message(c, d, n)
    decrypted_message = number_to_string(decrypted_m)
    print(f"Decrypted message: {decrypted_message}")

if __name__ == "__main__":
    main()

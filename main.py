# RSA (in theory, not in practice)

import random
import math

def generate_primes():
    """we only only generate some low primes for demo purposes. We are not concerned with hackers.
    the low primes that will be chosen (p,q) from this list limit the number of distinguishable messages
    (encoded as numbers) that can be sent in a block to the modulus (p*q) size. Our block size will only
    be one letter so we don't need large primes for that reason either."""
    primes = []
    for prime_check in range(2, 1000):
        prime = True
        for div_check in range(2, int(prime_check ** (1 / 2)+1)):
            if prime_check % div_check == 0:
                prime = False
                break
        if prime:
            primes.append(prime_check)
    return primes

def choose_two_primes(primes):
    """we don't choose primes that are too small because we need the modulus (p*q) to be greater than
    each character encoded as a number."""
    p_idx = random.randint(20,len(primes)-1)
    q_idx = random.randint(20,len(primes)-1)
    if p_idx == q_idx:
        q_idx -= 1
    p = primes[p_idx]
    q = primes[q_idx]
    return p,q

def create_modulus(p,q):
    n = p*q
    return n

def calculate_totient_of_modulus(p,q):
    """totient of n is the number of positive integers less than n that are relatively prime to it.
    because the modulus is a semiprime the totient calculation is easy"""
    totient = (p-1)*(q-1)
    return totient

def gcdExtended(a,b):
    """Extended Euclidean GCD algorithm calculates the GCD. It also finds integer coefficients
    such that c_a*a + c_b*b = gcd(a, b)"""
    if a == 0:
        return b, 0, 1
    gcd,c_a1,c_b1 = gcdExtended(b%a,a)
    c_a = c_b1-(b//a)*c_a1
    c_b = c_a1
    return gcd, c_a, c_b

def generate_an_e_and_d(p,q):
    """e (with n) is the encryption (public) key and d is the decryption (private) key. both are
    used as exponents in the encryption/decryption function."""
    totient = calculate_totient_of_modulus(p, q)
    while True:
        e = random.randint(2,totient)
        gcd,c_e,c_totient = gcdExtended(e, calculate_totient_of_modulus(p,q))
        if gcd==1 and c_e>0:
            # if c_e*e + c_totient*totient = 1, then c_e*e=1 in a mod(totient of the mod) world
            # when doing modular arithmetic, exponents live in a mod(totient of the mod) world
            # e is our encryption key/exponent, and c_e is used as our decryption key d
            return e,c_e

def get_keys(primes):
    p,q = choose_two_primes(primes)
    n = create_modulus(p,q)
    e,d = generate_an_e_and_d(p,q)
    return e,n,d

def encrypt_and_decrypt(m_or_c,e_or_d,n):
    """encryption and decryption involves exponentiation. we don't do the exponentiation all
    at once due to exponent size. mod allows us to keep the running product less than the mod.
    we use the square-and-multiply method to compute (m**e)%n in log time."""
    exp_binary = bin(e_or_d)[2:]  # drop the 0b prefix from this string
    result = m_or_c
    for bit in range(1,len(exp_binary)):
        if exp_binary[bit] == "0":
            result **= 2
            result %= n
        else:  # bit is "1"
            result **= 2
            result *= m_or_c
            result %= n
    return result

def convertToNumber(s):
    """Converts a string to a number"""
    return int.from_bytes(s.encode(),'little')

def convertFromNumber(n):
    """Converts a number to a string"""
    return n.to_bytes(math.ceil(n.bit_length()/8),'little').decode()

def convert_message_to_numbers(message):
    """Alice will transmit the message one letter at a time."""
    return [convertToNumber(letter) for letter in message]

def transmission_and_reception():
    """Alice has a private message to send to Bob.
    They will both generate public & private key pairs.
    They will keep their private key d and share their public key (e,n).
    Alice will use Bob's public key to encode and send her message.
    Alice will also use her own private key to sign her name "A"
    Bob will use his private key to decode the cypher text.
    Bob will use Alice's public key to verify that Alice was the sender."""

    message = "You're the antenna catching vibration. I'm the transmitter. Here's information!"
    print("[private] Alice's message:", message)

    primes = generate_primes()
    m_list = convert_message_to_numbers(message)

    # Bob collects his message in a list and then concatenates it
    decoded_message = []

    for i, m in enumerate(m_list):
        # Alice and Bob use unique keys for each block to avoid patterns in the cypher text
        e_a, n_a, d_a = get_keys(primes)
        e_b, n_b, d_b = get_keys(primes)

        # Alice encrypts the message into a cypher text c using Bob's public key (e and n)
        # Alice does not have access to Bob's private key d_b
        # Alice also signs the message using her private key d_a
        c = encrypt_and_decrypt(m, e_b, n_b)
        # a digital signature is actually not an encryption on an "Alice" or "A"
        # it is another round of encryption applied to c
        signature = encrypt_and_decrypt(convertToNumber("A"), d_a, n_a)

        # Alice transmits the cypher text for Eve and everyone to see
        # Eve tries to guess the message. She'll know if she can generate c
        print(f"[public] Alice's {i+1}th message & signature block to Bob is:", (c,signature))

        # Bob authenticates the message with Alice's public key
        # And then Bob decrypts the cypher text block w/ his private key
        if convertFromNumber(encrypt_and_decrypt(signature, e_a, n_a))=="A":
            decrypted_number = encrypt_and_decrypt(c, d_b, n_b)

        # Bob converts the number back into a letter and adds it to his private list
        decoded_message.append(convertFromNumber(int(decrypted_number)))

    print("[private] Bob's decoded message from Alice:", "".join(decoded_message))

transmission_and_reception()
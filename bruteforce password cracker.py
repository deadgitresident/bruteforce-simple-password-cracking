import argparse
import hashlib
import itertools
import json
import string
import time
import multiprocessing
from tqdm import tqdm

def generate_password_candidates(charset, length):
   
    
    password_candidates = [''.join(p) for p in itertools.product(charset, repeat=length)]
    return password_candidates


def check_password(attempt_str, password_hash, hash_algorithm, salt=None):
    
    if salt:
        attempt_str = salt + attempt_str
    attempt_hash = getattr(hashlib, hash_algorithm)(attempt_str.encode()).hexdigest()
    return attempt_hash == password_hash


def bruteforce_cracker(password_hash, charset, min_length, max_length, hash_algorithm, salt=None, num_workers=4):
    
    
    with multiprocessing.Pool(processes=num_workers) as pool:
        results = []
        for length in range(min_length, max_length + 1):
            password_candidates = generate_password_candidates(charset, length)
            for attempt_str in password_candidates:
                results.append(pool.apply_async(check_password, (attempt_str, password_hash, hash_algorithm, salt)))
        for result in results:
            if result.get():
                return result.get()
    return None

def get_charset(charset_name):
    
    charsets = {
        'alpha': string.ascii_letters,
        'alphanumeric': string.ascii_letters + string.digits,
        'all': string.printable,
        'special': string.punctuation,
        'unicode': ''.join(chr(i) for i in range(128, 65537))
    }
    return charsets.get(charset_name)

def get_hash_algorithms():
    return [alg for alg in dir(hashlib) if not alg.startswith('_') and alg.islower()]

def load_config(config_file):
    with open(config_file, 'r') as f:
        return json.load(f)

def print_banner():
    print("\033[92m")
    print("#" * 80)
    print("#" + " " * 36 + "BRUTEFORCE PASSWORD CRACKER" + " " * 36 + "#")
    print("#" + " " * 37 + "CODE BY KAZELEGENDO" + " " * 37 + "#")
    print("#" * 80)
    print("          _______          ")
    print("         /       \         ")
    print("        /         \        ")
    print("   ___/           \___   ")
    print("  /   \             /   \  ")
    print(" /     \           /     \ ")
    print("/_______\         /_______\ ")
    print("  ^      ^         ^      ^ ")
    print("  |      |         |      | ")
    print("  |  o  |         |  o  | ")
    print("  |_____|         |_____| ")
    print("      ________________    ")                   
    print("    __      __      __    ")
    print("   /  \    /  \    /  \   ")
    print("  /    \  /    \  /    \  ")
    print(" /      \/      \/      \ ")
    print("/_______________________\ ")
    print("          _______          ")
    print("         /       \         ")
    print("        /         \        ")
    print("   ___/           \___   ")
    print("  /   \             /   \  ")
    print(" /     \           /     \ ")
    print("/_______\         /_______\ ")
    print("          ^          ")
    print("          |          ")
    print("          |          ")
    print("          |          ")
    print("          v          ")
    print("          _______          ")
    print("         /       \         ")
    print("        /         \        ")
    print("   ___/           \___   ")
    print("  /   \             /   \  ")
    print(" /     \           /     \ ")
    print("/_______\         /_______\ ")
    print("#" * 80)
    print("\033[0m")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Bruteforce Password Cracker')
    parser.add_argument('-p', '--password-hash', required=True, help='The hashed password to crack')
    parser.add_argument('-c', '--config', help='The configuration file')
    parser.add_argument('-s', '--start', action='store_true', help='Start the bruteforce cracker')
    parser.add_argument('-q', '--quiet', action='store_true', help='Run in quiet mode')
    parser.add_argument('-C', '--charset', help='The charset to use (alpha, alphanumeric, all, special, unicode)')
    parser.add_argument('-m', '--min-length', type=int, help='The minimum length of the password to try')
    parser.add_argument('-M', '--max-length', type=int, help='The maximum length of the password to try')
    parser.add_argument('-a', '--hash-algorithm', help=f'The hash algorithm used to hash the password ({", ".join(get_hash_algorithms())})')
    parser.add_argument('-S', '--salt', help='The salt value (optional)')
    args = parser.parse_args()

    if args.config:
        config = load_config(args.config)
        charset = get_charset(config.get('charset', 'alphanumeric'))
        min_length = config.get('min_length', 8)
        max_length = config.get('max_length', 12)
        hash_algorithm = config.get('hash_algorithm', 'md5')
    else:
        charset = get_charset(args.charset) if args.charset else get_charset('alphanumeric')
        min_length = args.min_length if args.min_length else 8
        max_length = args.max_length if args.max_length else 12
        hash_algorithm = args.hash_algorithm if args.hash_algorithm else 'md5'

    if charset is None:
        print(f"Unsupported charset: {args.charset}")
        return

    if hash_algorithm not in get_hash_algorithms():
        print(f"Unsupported hash algorithm: {args.hash_algorithm}")
        return

    if args.start:
        start_time = time.time()
        cracked_password = bruteforce_cracker(args.password_hash, charset, min_length, max_length, hash_algorithm, args.salt)
        end_time = time.time()

        if cracked_password:
            if not args.quiet:
                print(f"Cracked password: {cracked_password} (took {end_time - start_time:.2f} seconds)")
        else:
            if not args.quiet:
                print("Failed to crack the password.")
    else:
        if not args.quiet:
            print("Bruteforce cracker not started. Use -s or --start to start the cracker.")

if __name__ == '__main__':
    main()
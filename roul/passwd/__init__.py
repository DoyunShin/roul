import random, string

def generate(len: int):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(len))

def generate_hard(len: int):
    return ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(len))
import secrets
import string


def generate(len: int) -> str:
    """Generate a password containing letters and digits.

    Args:
        len: Number of characters to generate.

    Returns:
        Generated password.
    """
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(len))


def generate_hard(len: int) -> str:
    """Generate a password containing letters, digits, and punctuation.

    Args:
        len: Number of characters to generate.

    Returns:
        Generated password.
    """
    return ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(len))

import math

def shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string.
    Higher values indicate more randomness.
    """
    if not data:
        return 0.0
    
    entropy = 0.0
    length = len(data)
    
    for x in range(256):
        char = chr(x)
        p_x = data.count(char) / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    
    return entropy

def is_high_entropy_string(text: str, threshold: float = 4.5, min_len: int = 20) -> bool:
    """
    Determine if a string exhibits high entropy characteristics.
    
    Args:
        text: String to evaluate
        threshold: Entropy threshold for flagging (default 4.5)
        min_len: Minimum length to consider (default 20)
    
    Returns:
        True if string meets entropy criteria, False otherwise
    """
    return len(text) >= min_len and shannon_entropy(text) > threshold

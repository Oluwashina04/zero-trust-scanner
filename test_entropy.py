from scanner.core.entropy import shannon_entropy, is_high_entropy_string

def main():
    test_strings = [
        "sk-live-",
        "aBcDeFgHiJkLmNoPqRsTuVwXyZ",
        "1234567890",
        "gHtY67kLpQwErTzUiOpAsDfGhJk",
    ]
    
    print("Entropy Analysis Results:\n")
    
    for text in test_strings:
        score = shannon_entropy(text)
        is_secret = is_high_entropy_string(text)
        print(f"String: {text}")
        print(f"  Entropy Score: {score:.2f}")
        print(f"  Flagged: {is_secret}\n")

if __name__ == "__main__":
    main()

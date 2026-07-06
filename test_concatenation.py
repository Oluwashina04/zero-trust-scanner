from scanner.plugins.concatenators import detect_concatenated_secrets

def main():
    # Test content with concatenated secrets
    test_content = """
TOKEN_PART1 = "sk-live-"
TOKEN_PART2 = "aBcDeFgHiJkLmNoPqRsTuVwXyZ"
TOKEN_PART3 = "1234567890"

# Multi-line concatenation
api_key = (
    "xoxb-1234-"
    "5678-9012-"
    "3456-7890"
)
"""
    
    findings = detect_concatenated_secrets(test_content, "test_config.py")
    
    print("Concatenation Detection Results:\n")
    
    for finding in findings:
        print(f"File: {finding['file']}")
        print(f"Type: {finding['type']}")
        print(f"Match: {finding['match']}")
        print(f"Line: {finding['line']}")
        print(f"Method: {finding['detection_method']}\n")

if __name__ == "__main__":
    main()

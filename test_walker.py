from scanner.core.walker import walk_directory

# Walk through test_repo and print all files found
for file_path in walk_directory('./test_repo'):
    print(f"Found: {file_path}")

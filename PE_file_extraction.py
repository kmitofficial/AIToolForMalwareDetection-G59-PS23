from pathlib import Path

def extract_file_paths():
    directory_path = "C:\\Windows\\System32"
    extensions = {".exe", ".dll", ".sys", ".acm", ".ax", ".cpl", ".drv", ".efi", ".mui", ".ocx", ".scr", ".tsp", ".mun"} 
    directory = Path(directory_path)
    
    # Make sure the directory exists
    if not directory.exists() or not directory.is_dir():
        return []
    
    file_paths = []
    
    for file_path in directory.glob('*'):  # Remove the trailing slash from the pattern
        if file_path.is_file() and file_path.suffix.lower() in extensions:
            file_paths.append(file_path)
    
    return file_paths



# from pathlib import Path

# def extract_file_paths(directory_path, extensions):
#     directory = Path(directory_path)
    
#     # Make sure the directory exists
#     if not directory.exists() or not directory.is_dir():
#         print(f"The specified directory '{directory_path}' does not exist or is not a directory.")
#         return []

#     file_paths = []
#     for file_path in directory.glob(f'*/'):
#         if file_path.is_file() and file_path.suffix.lower() in extensions:
#             file_paths.append(file_path)

#     return file_paths

# # Specify the directory path and extensions
# directory_path = "/Users/anuragnarsingoju/Downloads/2-1 project/exe_files"
# extensions = {".exe", ".dll"}  # Add more extensions if needed

# # Extract file paths
# file_paths = extract_file_paths(directory_path, extensions)

# # Print the results
# if file_paths:
#     print("File paths:")
#     for file_path in file_paths:
#         print(file_path)
# else:
#     print("No files found.")
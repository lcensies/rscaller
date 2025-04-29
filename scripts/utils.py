import os 

def find_git_root(start_path="."):
    """
    Find the Git repository root directory by walking upwards from start_path.
    
    Args:
        start_path (str): Path to start searching from (default: current directory)
        
    Returns:
        str: Path to Git repository root, or None if no Git repo found
        
    Raises:
        ValueError: If start_path doesn't exist
    """
    if not os.path.exists(start_path):
        raise ValueError(f"Starting path '{start_path}' does not exist")
    
    current_path = os.path.abspath(start_path)
    previous_path = None
    
    while current_path != previous_path:
        # Check if .git exists in current directory
        git_dir = os.path.join(current_path, ".git")
        
        if os.path.exists(git_dir):
            return current_path
            
        previous_path = current_path
        current_path = os.path.dirname(current_path)
        
        # Safety check to prevent infinite loop
        if current_path == "/":
            break
            
    return None
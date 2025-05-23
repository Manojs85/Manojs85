import logging
import os
import shutil

logger = logging.getLogger("RansomwareAnalyzer.IncidentResponse")
DEFAULT_QUARANTINE_DIR = "quarantine_zone" # Relative to project root for simplicity

def isolate_file(filepath, quarantine_dir_base=None):
    """
    Moves the specified file to a quarantine directory.
    The quarantine directory will be under <project_root>/<DEFAULT_QUARANTINE_DIR>/<original_basename_of_file>
    so that files from different original paths don't immediately clash.
    A more robust solution might involve timestamping or UUIDs for quarantined file paths.
    """
    if not quarantine_dir_base:
        # Construct path relative to the ransomware_analyzer package's parent directory
        # Assuming this script (actions.py) is at ransomware_analyzer/incident_response/actions.py
        # Project root is two levels up from this file's directory.
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        quarantine_dir_base = os.path.join(project_root, DEFAULT_QUARANTINE_DIR)

    if not os.path.exists(filepath):
        logger.error(f"File isolation failed: Source file '{filepath}' not found.")
        return False

    try:
        # Create the base quarantine directory if it doesn't exist
        if not os.path.exists(quarantine_dir_base):
            os.makedirs(quarantine_dir_base)
            logger.info(f"Created base quarantine directory: {quarantine_dir_base}")

        # Create a subdirectory within quarantine_dir_base using the original file's name
        # to prevent direct name clashes if multiple files with the same name are quarantined.
        # For actual ransomware, the name itself might be part of the IOC.
        # A timestamp or UUID could be added for uniqueness.
        file_basename = os.path.basename(filepath)
        # Sanitize basename if it contains problematic characters (though os.path.join should handle most)
        safe_subdir_name = "".join(c if c.isalnum() or c in ('-', '_', '.') else '_' for c in file_basename)
        
        # Destination path for the file itself
        destination_filename = file_basename # Keep original filename within its unique subdir

        # Create unique subdirectory for this file to avoid overwriting
        # This simple version uses the filename again for the subdir, adding a count if needed.
        # A better approach for true uniqueness might be a UUID.
        unique_folder_name = safe_subdir_name
        counter = 0
        final_quarantine_path_dir = os.path.join(quarantine_dir_base, unique_folder_name)
        
        # Ensure the specific quarantine path for this file is unique to avoid overwriting the *folder*
        while os.path.exists(final_quarantine_path_dir):
            counter += 1
            unique_folder_name = f"{safe_subdir_name}_{counter}"
            final_quarantine_path_dir = os.path.join(quarantine_dir_base, unique_folder_name)
        
        os.makedirs(final_quarantine_path_dir)
        
        destination_path = os.path.join(final_quarantine_path_dir, destination_filename)

        shutil.move(filepath, destination_path)
        logger.warning(f"File '{filepath}' isolated to '{destination_path}'.")
        return True
    except Exception as e:
        logger.error(f"Error isolating file '{filepath}': {e}")
        return False

import logging
import time
import os # For checksum calculation in analyze_file_modification and os.walk
import sys # For sys.argv in direct execution block
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ransomware_analyzer.threat_detection.analyzer import (
    analyze_file, 
    analyze_file_modification, 
    get_file_hash,
    calculate_threat_score
)
from ransomware_analyzer.logger_config import setup_logging # Or get logger by name if already configured in main
from ransomware_analyzer.ml_model.predictor import RansomwarePredictor
from ransomware_analyzer.incident_response.actions import isolate_file

logger = logging.getLogger("RansomwareAnalyzer.Watcher")
ml_predictor = RansomwarePredictor() # Initialize with no specific model path for now

# Store previous checksums for modified files - simple in-memory cache
# For a more robust solution, a persistent store or more sophisticated cache would be needed.
file_checksums_cache = {}

class AnalysisEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        logger.info(f"File created: {event.src_path}")
        analysis_result = analyze_file(event.src_path)
        logger.info(f"Analysis for new file {event.src_path}: {analysis_result}")
        
        ml_analysis_result = ml_predictor.predict_ransomware_behavior(event.src_path)
        logger.info(f"ML analysis for {event.src_path}: {ml_analysis_result}")

        # For new files, behavioral analysis (checksum changes) isn't directly applicable in the same way.
        # However, analyze_file_modification can give info based on current_checksum and extension.
        # We'll call it to see if it flags uncommon extensions for new files.
        current_hash_for_new_file = get_file_hash(event.src_path)
        behavior_result_on_create = None
        if current_hash_for_new_file:
            behavior_result_on_create = analyze_file_modification(event.src_path, current_checksum=current_hash_for_new_file)
            logger.info(f"Initial behavioral check for new file {event.src_path}: {behavior_result_on_create}")

        final_score, score_reasons = calculate_threat_score(
            analysis_result_str=analysis_result,
            ml_result_dict=ml_analysis_result,
            behavioral_result_str=behavior_result_on_create
        )
        logger.info(f"Calculated Threat Score for new file {event.src_path}: {final_score} (Reasons: {'; '.join(score_reasons)})")

        # Decision Logic for Isolation
        should_isolate = False
        if "Known ransomware hash match" in analysis_result: # Prioritize hash match
            should_isolate = True
            logger.critical(f"High threat detected for {event.src_path} by hash match (Score: {final_score}). Attempting isolation.")
        elif final_score >= 80: # Example threshold, can be tuned. Hash match already covered.
            should_isolate = True
            logger.critical(f"High threat detected for {event.src_path} (Score: {final_score}). Attempting isolation based on score threshold.")
        
        # The original ML confidence check for isolation can be kept or replaced by score:
        # if isinstance(ml_analysis_result, dict) and ml_analysis_result.get('is_suspicious') and ml_analysis_result.get('confidence', 0) >= 0.7:
        # should_isolate = True ...

        if should_isolate:
            if isolate_file(event.src_path):
                logger.info(f"Successfully initiated isolation for {event.src_path}.")
                if event.src_path in file_checksums_cache:
                    del file_checksums_cache[event.src_path]
                return 
            else:
                logger.error(f"Failed to isolate {event.src_path}.")
        
        # Update checksum cache only if file was not isolated
        if current_hash_for_new_file: # current_hash_for_new_file was from get_file_hash
            file_checksums_cache[event.src_path] = current_hash_for_new_file

    def on_modified(self, event):
        if event.is_directory:
            return
        logger.info(f"File modified: {event.src_path}")
        
        original_checksum = file_checksums_cache.get(event.src_path)
        current_checksum = get_file_hash(event.src_path)

        # If current_checksum is None, file might be inaccessible (e.g., deleted quickly after mod)
        if not current_checksum:
            logger.warning(f"Could not hash {event.src_path} on modification, it may be inaccessible.")
            if event.src_path in file_checksums_cache:
                del file_checksums_cache[event.src_path]
            return

        # Basic analysis for any modification
        analysis_result = analyze_file(event.src_path)
        logger.info(f"Standard analysis for modified file {event.src_path}: {analysis_result}")

        ml_analysis_result = ml_predictor.predict_ransomware_behavior(event.src_path)
        logger.info(f"ML analysis for {event.src_path}: {ml_analysis_result}")

        # Decision Logic for Isolation
        should_isolate = False
        if "Known ransomware hash match" in analysis_result:
            should_isolate = True
            logger.critical(f"High threat detected for {event.src_path} by hash match. Attempting isolation.")

        if isinstance(ml_analysis_result, dict) and ml_analysis_result.get('is_suspicious') and ml_analysis_result.get('confidence', 0) >= 0.7:
            should_isolate = True
            logger.critical(f"High threat detected for {event.src_path} by ML model (Confidence: {ml_analysis_result.get('confidence',0)}). Attempting isolation.")
        
        if should_isolate:
            if isolate_file(event.src_path):
                logger.info(f"Successfully initiated isolation for {event.src_path}.")
                if event.src_path in file_checksums_cache:
                    del file_checksums_cache[event.src_path]
                return # Stop further processing for this event as file is moved
            else:
                logger.error(f"Failed to isolate {event.src_path}.")

        # Behavioral analysis if checksum changed and file not isolated
        if original_checksum != current_checksum: # current_checksum is guaranteed to be non-None here
            behavior_result = analyze_file_modification(event.src_path, original_checksum, current_checksum)
            logger.info(f"Behavioral analysis for {event.src_path}: {behavior_result}")
        elif not original_checksum: # File might have been created before watcher started, or cache cleared
            behavior_result = analyze_file_modification(event.src_path, current_checksum=current_checksum)
            logger.info(f"Behavioral analysis (no baseline) for {event.src_path}: {behavior_result}")

        # Update cache with the new checksum if file not isolated
        file_checksums_cache[event.src_path] = current_checksum

    # Optional: on_deleted
    def on_deleted(self, event):
        if event.is_directory:
            return
        logger.info(f"File deleted: {event.src_path}")
        if event.src_path in file_checksums_cache:
            del file_checksums_cache[event.src_path]

def start_monitoring(path_to_watch):
    # Ensure logger is configured if watcher is run standalone or before main.py configures it
    # For this subtask, assume main.py handles initial setup_logging()
    logger.info(f"Starting real-time monitoring on directory: {path_to_watch}")
    
    # Pre-populate checksum cache for existing files before starting monitoring
    logger.info(f"Pre-caching checksums for existing files in {path_to_watch}...")
    for root, _, files in os.walk(path_to_watch):
        for name in files:
            filepath = os.path.join(root, name)
            # Avoid analyzing files in .git or other service directories if desired
            # if ".git" in filepath or ".svn" in filepath:
            # continue
            file_hash = get_file_hash(filepath)
            if file_hash:
                file_checksums_cache[filepath] = file_hash
    logger.info(f"Pre-caching complete. Found {len(file_checksums_cache)} files.")

    event_handler = AnalysisEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path_to_watch, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("Real-time monitor stopped by user.")
    except Exception as e:
        logger.error(f"Real-time monitor encountered an error: {e}")
        observer.stop()
    observer.join()

if __name__ == "__main__":
    # Example of running watcher directly (for testing)
    # In practice, main.py should configure logging first.
    # For now, let's add a basic config here if run directly.
    if not logging.getLogger("RansomwareAnalyzer").hasHandlers():
         setup_logging(log_level=logging.DEBUG) # Basic setup if run directly
    
    watch_path = "." # Default to current directory for direct execution
    if len(sys.argv) > 1:
        watch_path = sys.argv[1]
    else:
        logger.info("No path specified, watching current directory by default.")
    
    # Pre-caching is now part of start_monitoring, called above.
    # No need to call it separately here.
    start_monitoring(watch_path)

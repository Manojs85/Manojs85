import logging
import time
import os 
import sys 
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from concurrent.futures import ThreadPoolExecutor
import threading
from ransomware_analyzer.threat_detection.analyzer import (
    analyze_file, 
    analyze_file_modification, 
    get_file_hash,
    calculate_threat_score
)
from ransomware_analyzer.logger_config import setup_logging # Or get logger by name if already configured in main
from ransomware_analyzer.ml_model.predictor import RansomwarePredictor
from ransomware_analyzer.incident_response.actions import isolate_file
# colorama is initialized in main.py, Fore/Style could be used if direct print from watcher is desired when not in JSON mode.
# For this subtask, we will focus on structured logging via 'extra'.

logger = logging.getLogger("RansomwareAnalyzer.Watcher")

# Global objects for thread pool and synchronization
executor = None 
cache_lock = threading.Lock()
file_checksums_cache = {} # In-memory cache for file checksums
ml_predictor = RansomwarePredictor() # Initialize ML predictor globally

# --- Worker function for processing file events ---
def process_file_event(event_path, event_type):
    logger.info(f"Processing {event_type} event for {event_path} in worker thread.",
                extra={'filepath': event_path, 'event_type': event_type, 'thread_id': threading.get_ident()})
    
    # --- Re-implement logic from on_created / on_modified here ---
    analysis_result = analyze_file(event_path) # This is I/O bound, good for threads

    # ML Prediction
    ml_analysis_result = ml_predictor.predict_ransomware_behavior(event_path) # Potentially CPU/I/O bound

    # Behavioral Analysis & Checksum Management
    current_checksum = get_file_hash(event_path) # I/O bound
    if not current_checksum and event_type != "deleted": # File might have been deleted/moved quickly
        logger.warning(f"Could not hash {event_path}, it may no longer exist or is inaccessible.", 
                       extra={'filepath': event_path})
        # No further behavioral analysis or isolation possible without current_checksum
        return

    behavior_result_for_score = None
    original_checksum_for_comparison = None

    if event_type == "created":
        with cache_lock:
            file_checksums_cache[event_path] = current_checksum
        # Initial behavioral check for new files
        behavior_result_for_score = analyze_file_modification(event_path, current_checksum=current_checksum)
        logger.info(f"Initial behavioral analysis for new file {event_path}: {behavior_result_for_score}", 
                    extra={'filepath': event_path, 'behavior_result': behavior_result_for_score})

    elif event_type == "modified":
        with cache_lock:
            original_checksum_for_comparison = file_checksums_cache.get(event_path)
        
        if current_checksum and original_checksum_for_comparison != current_checksum:
            behavior_result_for_score = analyze_file_modification(event_path, original_checksum_for_comparison, current_checksum)
            logger.info(f"Behavioral analysis for modified {event_path}: {behavior_result_for_score}", 
                        extra={'filepath': event_path, 'behavior_result': behavior_result_for_score, 'original_checksum': original_checksum_for_comparison, 'new_checksum': current_checksum})
        elif not original_checksum_for_comparison and current_checksum:
            behavior_result_for_score = analyze_file_modification(event_path, current_checksum=current_checksum) # No baseline
            logger.info(f"Behavioral analysis (no baseline) for {event_path}: {behavior_result_for_score}", 
                        extra={'filepath': event_path, 'behavior_result': behavior_result_for_score})
        
        if current_checksum: # Update cache if hash was successful
            with cache_lock:
                file_checksums_cache[event_path] = current_checksum
        elif event_path in file_checksums_cache: # If hashing failed but was in cache
            with cache_lock:
                 del file_checksums_cache[event_path]


    # Threat Scoring
    final_score, score_reasons = calculate_threat_score(
        analysis_result_str=analysis_result,
        ml_result_dict=ml_analysis_result,
        behavioral_result_str=behavior_result_for_score
    )
    logger.info(f"Calculated Threat Score for {event_path}: {final_score} (Reasons: {'; '.join(score_reasons)})", 
                extra={'filepath': event_path, 'score': final_score, 'reasons': score_reasons})

    # Incident Response (Isolation)
    should_isolate = False
    isolation_trigger_reason = ""
    if "Known ransomware hash match" in analysis_result:
        should_isolate = True
        isolation_trigger_reason = "hash_match"
    elif final_score >= 80: # Threshold for high threat
        should_isolate = True
        isolation_trigger_reason = f"score_threshold ({final_score})"

    if should_isolate:
        logger.critical(
            f"High threat detected for {event_path} ({isolation_trigger_reason}). Attempting isolation.", 
            extra={'filepath': event_path, 'trigger': isolation_trigger_reason, 'score': final_score}
        )
        quarantined_path = isolate_file(event_path) 
        if quarantined_path:
            logger.warning(
                f"Successfully ISOLATED {event_path} to {quarantined_path}.",
                extra={'filepath': event_path, 'quarantine_path': quarantined_path, 'status': 'success'}
            )
            with cache_lock: # Remove from cache as it's moved
                if event_path in file_checksums_cache:
                    del file_checksums_cache[event_path]
        else:
            logger.error(f"Failed to isolate {event_path}.", 
                         extra={'filepath': event_path, 'status': 'failure', 'trigger': isolation_trigger_reason, 'score': final_score})
    # --- End of re-implemented logic ---

# --- Event Handler ---
class AnalysisEventHandler(FileSystemEventHandler):
    # Using global executor, so no need to pass it in __init__
    
    def on_created(self, event):
        if event.is_directory:
            return
        if executor:
            logger.info(f"Queueing analysis for created file: {event.src_path}", 
                        extra={'filepath': event.src_path, 'event_type': 'created'})
            executor.submit(process_file_event, event.src_path, "created")
        else:
            logger.warning("Executor not available, cannot process created file event.", extra={'filepath': event.src_path})


    def on_modified(self, event):
        if event.is_directory:
            return
        if executor:
            logger.info(f"Queueing analysis for modified file: {event.src_path}", 
                        extra={'filepath': event.src_path, 'event_type': 'modified'})
            executor.submit(process_file_event, event.src_path, "modified")
        else:
            logger.warning("Executor not available, cannot process modified file event.", extra={'filepath': event.src_path})


    def on_deleted(self, event):
        if event.is_directory:
            return
        logger.info(f"File deleted: {event.src_path}", extra={'filepath': event.src_path, 'event_type': 'deleted'})
        with cache_lock:
            if event.src_path in file_checksums_cache:
                del file_checksums_cache[event.src_path]

# --- Monitoring Control ---
def start_monitoring(path_to_watch):
    global executor 
    # Max workers: twice the number of CPUs, or 4 if CPU count can't be determined.
    num_workers = (os.cpu_count() or 1) * 2 if os.cpu_count() else 4 
    executor = ThreadPoolExecutor(max_workers=num_workers)
    logger.info(f"Initialized ThreadPoolExecutor with {num_workers} workers.", extra={'num_workers': num_workers})

    logger.info(f"Starting real-time monitoring on directory: {path_to_watch}", 
                extra={'watch_path': path_to_watch})
    
    logger.info(f"Pre-caching checksums for existing files in {path_to_watch}...",
                extra={'watch_path': path_to_watch})
    for root, _, files in os.walk(path_to_watch):
        for name in files:
            filepath = os.path.join(root, name)
            file_hash = get_file_hash(filepath)
            if file_hash:
                with cache_lock: # Protect cache during pre-population
                    file_checksums_cache[filepath] = file_hash
    logger.info(f"Pre-caching complete. Found {len(file_checksums_cache)} files.",
                extra={'cached_files_count': len(file_checksums_cache)})

    event_handler = AnalysisEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path_to_watch, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Real-time monitor stopped by user (KeyboardInterrupt).")
    except Exception as e:
        logger.error(f"Real-time monitor encountered an error: {e}", exc_info=True)
    finally:
        if executor:
            logger.info("Shutting down thread pool executor...")
            executor.shutdown(wait=True)
            executor = None # Reset global executor
            logger.info("Thread pool executor shut down.")
        
        observer.stop()
        observer.join()
        logger.info("Watchdog observer stopped and joined.")


if __name__ == "__main__":
    if not logging.getLogger("RansomwareAnalyzer").hasHandlers():
         setup_logging(log_level=logging.DEBUG) 
    
    watch_path = "." 
    if len(sys.argv) > 1:
        watch_path = sys.argv[1]
    else:
        logger.info("No path specified, watching current directory by default for standalone execution.")
    
    start_monitoring(watch_path)

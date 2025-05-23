import argparse
import logging
from ransomware_analyzer.logger_config import setup_logging
from ransomware_analyzer.threat_detection.analyzer import analyze_file, analyze_file_modification
from ransomware_analyzer.realtime_monitor.watcher import start_monitoring

if __name__ == "__main__":
    setup_logging() # Default level INFO, logs to "analyzer.log"
    logger = logging.getLogger("RansomwareAnalyzer")

    parser = argparse.ArgumentParser(description="Analyze a file for ransomware, suspicious modifications, or start real-time monitoring.")
    parser.add_argument("--filepath", help="The path to the file to analyze for signatures.")
    parser.add_argument("--monitor-file", help="The path to the file to check for suspicious modifications.")
    parser.add_argument("--original-checksum", help="Original checksum of the monitored file.")
    parser.add_argument("--current-checksum", help="Current checksum of the monitored file.")
    parser.add_argument("--start-monitor", metavar="DIRECTORY", help="Path to the directory to monitor in real-time.")
    
    args = parser.parse_args()

    if args.start_monitor:
        logger.info(f"Real-time monitoring mode activated for directory: {args.start_monitor}")
        # setup_logging() is already called, so logger is configured.
        start_monitoring(args.start_monitor)
    elif args.monitor_file:
        logger.info(f"Initiating modification analysis for: {args.monitor_file}")
        modification_result = analyze_file_modification(
            args.monitor_file, 
            args.original_checksum, 
            args.current_checksum
        )
        logger.info(f"File modification analysis result for {args.monitor_file}: {modification_result}")
    
    elif args.filepath: # Changed to elif to ensure exclusivity with start_monitor
        logger.info(f"Initiating signature analysis for: {args.filepath}")
        signature_result = analyze_file(args.filepath)
        logger.info(f"Signature analysis result for {args.filepath}: {signature_result}")

    else: # No specific action was chosen
        logger.error("No action specified. Please provide --filepath, --monitor-file, or --start-monitor.")
        parser.print_help()

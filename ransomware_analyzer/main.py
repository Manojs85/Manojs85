import argparse
import logging
from ransomware_analyzer.logger_config import setup_logging
from ransomware_analyzer.threat_detection.analyzer import analyze_file, analyze_file_modification

if __name__ == "__main__":
    setup_logging() # Default level INFO, logs to "analyzer.log"
    logger = logging.getLogger("RansomwareAnalyzer")

    parser = argparse.ArgumentParser(description="Analyze a file for ransomware or suspicious modifications.")
    parser.add_argument("--filepath", help="The path to the file to analyze for signatures.")
    parser.add_argument("--monitor-file", help="The path to the file to check for suspicious modifications.")
    parser.add_argument("--original-checksum", help="Original checksum of the monitored file.")
    parser.add_argument("--current-checksum", help="Current checksum of the monitored file.")
    
    args = parser.parse_args()

    if args.monitor_file:
        logger.info(f"Initiating modification analysis for: {args.monitor_file}")
        modification_result = analyze_file_modification(
            args.monitor_file, 
            args.original_checksum, 
            args.current_checksum
        )
        # The analyze_file_modification function itself now logs the detailed result
        # So we just log that the analysis was performed.
        logger.info(f"File modification analysis result for {args.monitor_file}: {modification_result}")


    if args.filepath:
        logger.info(f"Initiating signature analysis for: {args.filepath}")
        signature_result = analyze_file(args.filepath)
        # The analyze_file function itself now logs the detailed result
        # So we just log that the analysis was performed.
        logger.info(f"Signature analysis result for {args.filepath}: {signature_result}")


    if not args.monitor_file and not args.filepath:
        logger.error("Please provide either --filepath for signature analysis or --monitor-file for modification analysis.")
        parser.print_help()

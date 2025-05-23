import argparse
import logging
from ransomware_analyzer.logger_config import setup_logging
from ransomware_analyzer.threat_detection.analyzer import analyze_file, analyze_file_modification
from ransomware_analyzer.realtime_monitor.watcher import start_monitoring
from colorama import init as colorama_init, Fore, Style

if __name__ == "__main__":
    colorama_init(autoreset=True)

    parser = argparse.ArgumentParser(description="Analyze a file for ransomware, suspicious modifications, or start real-time monitoring.")
    parser.add_argument("--filepath", help="The path to the file to analyze for signatures.")
    parser.add_argument("--monitor-file", help="The path to the file to check for suspicious modifications.")
    parser.add_argument("--original-checksum", help="Original checksum of the monitored file.")
    parser.add_argument("--current-checksum", help="Current checksum of the monitored file.")
    parser.add_argument("--start-monitor", metavar="DIRECTORY", help="Path to the directory to monitor in real-time.")
    parser.add_argument("--json-logs", action='store_true', help="Enable JSON formatted logs.")
    
    args = parser.parse_args()

    # Setup logging after parsing args to use --json-logs
    setup_logging(use_json=args.json_logs) 
    logger = logging.getLogger("RansomwareAnalyzer")


    if args.start_monitor:
        logger.info(f"Real-time monitoring mode activated for directory: {args.start_monitor}", 
                    extra={'directory': args.start_monitor, 'mode': 'realtime_monitor'})
        start_monitoring(args.start_monitor) # Logger is already configured
    
    elif args.monitor_file:
        logger.info(f"Initiating modification analysis for: {args.monitor_file}", 
                    extra={'filepath': args.monitor_file, 'mode': 'modification_analysis'})
        modification_result = analyze_file_modification(
            args.monitor_file, 
            args.original_checksum, 
            args.current_checksum
        )
        # For modification_result, similar colored output could be added if desired,
        # but the prompt specifically focuses on args.filepath for color.
        logger.info(f"File modification analysis result for {args.monitor_file}: {modification_result}",
                    extra={'filepath': args.monitor_file, 'result': modification_result})

    elif args.filepath:
        logger.info(f"Initiating signature analysis for: {args.filepath}",
                    extra={'filepath': args.filepath, 'mode': 'signature_analysis'})
        analysis_result = analyze_file(args.filepath)
        
        if args.json_logs:
            logger.info(f"Analysis result for {args.filepath}: {analysis_result}", 
                        extra={'filepath': args.filepath, 'result': analysis_result, 'scan_type': 'signature'})
        else:
            colored_result = analysis_result
            if "Known ransomware hash match" in analysis_result or "Suspicious:" in analysis_result:
                colored_result = Fore.RED + analysis_result + Style.RESET_ALL
            elif "File seems clean" in analysis_result:
                colored_result = Fore.GREEN + analysis_result + Style.RESET_ALL
            
            print(f"Analysis result for {Fore.CYAN}{args.filepath}{Style.RESET_ALL}: {colored_result}")
            # Log the plain result to file as well, even if printing colored to console
            logger.info(f"Analysis result for {args.filepath}: {analysis_result}", 
                        extra={'filepath': args.filepath, 'result': analysis_result, 'scan_type': 'signature'})


    else: # No specific action was chosen
        logger.error("No action specified. Please provide --filepath, --monitor-file, or --start-monitor.",
                     extra={'error_type': 'no_action_specified'})
        parser.print_help()

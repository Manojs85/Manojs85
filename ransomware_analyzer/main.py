import argparse
from ransomware_analyzer.threat_detection.analyzer import analyze_file

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze a file for ransomware signatures.")
    parser.add_argument("filepath", help="The path to the file to analyze.")
    args = parser.parse_args()

    result = analyze_file(args.filepath)
    print(result)

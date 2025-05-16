#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import yaml
import json
import sys
import argparse

def process_privateer_report(input_file, output_file):
    """
    Process a Privateer YAML report to create a CEL-friendly JSON format for Darnit.
    """
    try:
        with open(input_file, 'r') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        print(f"Error reading YAML input file: {e}")
        return False
    
    # Initialize the findings structure
    findings = {
        "failed_controls": [],
        "has_failed_control": {},
        "controls": {},
        "control_results": {},
        "control_messages": {}
    }
    
    # Process the evaluation suites
    for suite in data.get("evaluation_suites", []):
        findings["catalog_id"] = suite.get("catalog_id")
        findings["overall_result"] = suite.get("result")
        
        # Process each control evaluation
        for control in suite.get("control_evaluations", []):
            control_id = control.get("control_id", "")
            if not control_id:
                continue  # Skip if no control ID
                
            control_result = control.get("result", "")
            control_message = control.get("message", "")
            
            # Store in controls list
            findings["controls"][control_id] = control_id
            findings["control_results"][control_id] = control_result
            findings["control_messages"][control_id] = control_message
            
            # If control failed, add to failed controls list
            if control_result == "Failed":
                findings["failed_controls"].append(control_id)
                findings["has_failed_control"][control_id] = True
            
            # Process assessments
            for assessment in control.get("assessments", []):
                req_id = assessment.get("requirement_id", "")
                if not req_id:
                    continue  # Skip if no requirement ID
                    
                assess_result = assessment.get("result", "")
                assess_message = assessment.get("message", "")
                
                # Store in controls list
                findings["controls"][req_id] = req_id
                findings["control_results"][req_id] = assess_result
                findings["control_messages"][req_id] = assess_message
                
                # If assessment failed, add to failed controls list
                if assess_result == "Failed":
                    findings["failed_controls"].append(req_id)
                    findings["has_failed_control"][req_id] = True
    
    # Create the output structure expected by Darnit
    output = {
        "findings": findings
    }
    
    # Write the output file as JSON (Darnit expects JSON)
    try:
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"Successfully processed Privateer YAML report to {output_file}")
        return True
    except Exception as e:
        print(f"Error writing output file: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Process Privateer YAML report for Darnit')
    parser.add_argument('input', help='Input Privateer YAML report file')
    parser.add_argument('-o', '--output', default='findings.json', help='Output file for Darnit (default: findings.json)')
    
    args = parser.parse_args()
    
    if process_privateer_report(args.input, args.output):
        print("Processing complete. You can now use this file with Darnit:")
        print(f"darnit plan generate -m ~/.darn/library/mappings/openssf-baseline-remediation.yaml {args.output} --params params.json -o plan.json -v")
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
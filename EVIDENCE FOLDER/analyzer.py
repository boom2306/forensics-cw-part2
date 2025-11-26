import struct
import os
import sys
import json
from datetime import datetime, timedelta
import winreg
import pythoncom
from winreg import *

def analyze_installed_apps(software_hive_path):
    """
    Analyze installed applications from SOFTWARE registry hive
    """
    print("\n" + "="*60)
    print("INSTALLED APPLICATIONS ANALYSIS")
    print("="*60)
    
    apps_found = []
    
    try:
        # Load the SOFTWARE hive
        with open(software_hive_path, 'rb') as f:
            software_data = f.read()
        
        # This is a simplified analysis - in practice you'd use proper registry parsing
        # Look for common application patterns in the binary data
        app_indicators = [
            b'Microsoft', b'Google', b'Chrome', b'Firefox', b'Adobe',
            b'Office', b'Word', b'Excel', b'PowerPoint', b'Outlook',
            b'Zoom', b'Teams', b'Slack', b'VLC', b'WinRAR', b'7-Zip',
            b'Notepad++', b'Visual Studio', b'Python', b'Java'
        ]
        
        for indicator in app_indicators:
            if indicator in software_data:
                app_name = indicator.decode('utf-8', errors='ignore')
                if app_name not in apps_found:
                    apps_found.append(app_name)
        
        print(f"Found {len(apps_found)} application indicators:")
        for app in sorted(apps_found):
            print(f"  - {app}")
            
    except Exception:
        print("  - Could not analyze SOFTWARE hive (file may be in use or corrupted)")
    
    return apps_found

def analyze_user_accounts(sam_hive_path, system_hive_path):
    """
    Analyze user accounts from SAM and SYSTEM registry hives
    """
    print("\n" + "="*60)
    print("USER ACCOUNTS ANALYSIS")
    print("="*60)
    
    try:
        with open(sam_hive_path, 'rb') as f:
            sam_data = f.read()
        
        with open(system_hive_path, 'rb') as f:
            system_data = f.read()
        
        # Look for user account patterns
        user_indicators = [
            b'Administrator', b'Guest', b'DefaultAccount', 
            b'WDAGUtilityAccount', b'User', b'Admin'
        ]
        
        users_found = []
        for indicator in user_indicators:
            if indicator in sam_data:
                user = indicator.decode('utf-8', errors='ignore')
                if user not in users_found:
                    users_found.append(user)
        
        print("User accounts found:")
        for user in users_found:
            print(f"  - {user}")
            
        # Get computer name from SYSTEM hive
        if b'ComputerName' in system_data:
            print("\nComputer name indicators found in SYSTEM hive")
        
    except Exception:
        print("  - Could not analyze user accounts (files may be in use or corrupted)")
    
    return users_found

def analyze_usb_history(system_hive_path):
    """
    Analyze USB device history from SYSTEM registry hive
    """
    print("\n" + "="*60)
    print("USB HISTORY ANALYSIS")
    print("="*60)
    
    try:
        with open(system_hive_path, 'rb') as f:
            system_data = f.read()
        
        # Look for USB device indicators
        usb_indicators = [
            b'USBSTOR', b'Disk&Ven', b'ClassGUID', b'HardwareID',
            b'VID_', b'PID_', b'SerialNumber'
        ]
        
        usb_events = []
        for indicator in usb_indicators:
            if indicator in system_data:
                usb_events.append(indicator.decode('utf-8', errors='ignore'))
        
        print(f"Found {len(usb_events)} USB-related artifacts:")
        for event in set(usb_events):  # Remove duplicates
            print(f"  - {event}")
            
    except Exception:
        print("  - Could not analyze USB history")
    
    return usb_events

def analyze_command_history(ntuser_path):
    """
    Analyze command line history from NTUSER.DAT
    """
    print("\n" + "="*60)
    print("COMMAND HISTORY ANALYSIS")
    print("="*60)
    
    try:
        with open(ntuser_path, 'rb') as f:
            ntuser_data = f.read()
        
        # Look for command history patterns
        cmd_indicators = [
            b'cmd.exe', b'powershell', b'Command Prompt',
            b'ConsoleHost_history', b'PSReadLine'
        ]
        
        cmd_events = []
        for indicator in cmd_indicators:
            if indicator in ntuser_data:
                cmd_events.append(indicator.decode('utf-8', errors='ignore'))
        
        print("Command history artifacts found:")
        for cmd in set(cmd_events):
            print(f"  - {cmd}")
            
    except Exception:
        print("  - Could not analyze command history")
    
    return cmd_events

def analyze_browser_artifacts(ntuser_path):
    """
    Analyze browser artifacts from NTUSER.DAT
    """
    print("\n" + "="*60)
    print("BROWSER ARTIFACTS ANALYSIS")
    print("="*60)
    
    try:
        with open(ntuser_path, 'rb') as f:
            ntuser_data = f.read()
        
        browser_indicators = [
            b'Google\\Chrome', b'Mozilla\\Firefox', b'Microsoft\\Edge',
            b'Internet Explorer', b'Safari', b'Opera',
            b'History', b'Cookies', b'Bookmarks', b'Downloads',
            b'TypedURLs', b'VisitedLinks'
        ]
        
        browser_artifacts = []
        for indicator in browser_indicators:
            if indicator in ntuser_data:
                artifact = indicator.decode('utf-8', errors='ignore')
                if artifact not in browser_artifacts:
                    browser_artifacts.append(artifact)
        
        print("Browser artifacts found:")
        for artifact in browser_artifacts:
            print(f"  - {artifact}")
            
    except Exception:
        print("  - Could not analyze browser artifacts")
    
    return browser_artifacts

def generate_forensic_report(analysis_results, output_file="forensic_report.txt"):
    """
    Generate a comprehensive forensic report
    """
    print("\n" + "="*60)
    print("GENERATING FORENSIC REPORT")
    print("="*60)
    
    report = f"""
DIGITAL FORENSIC ANALYSIS REPORT
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{'='*50}

SUMMARY:
--------
- Installed Applications: {len(analysis_results['installed_apps'])}
- User Accounts: {len(analysis_results['user_accounts'])}
- USB Artifacts: {len(analysis_results['usb_history'])}
- Command History Items: {len(analysis_results['command_history'])}
- Browser Artifacts: {len(analysis_results['browser_artifacts'])}

DETAILED FINDINGS:
------------------

INSTALLED APPLICATIONS:
{chr(10).join(['  - ' + app for app in analysis_results['installed_apps']])}

USER ACCOUNTS:
{chr(10).join(['  - ' + user for user in analysis_results['user_accounts']])}

USB HISTORY:
{chr(10).join(['  - ' + usb for usb in analysis_results['usb_history']])}

COMMAND HISTORY:
{chr(10).join(['  - ' + cmd for cmd in analysis_results['command_history']])}

BROWSER ARTIFACTS:
{chr(10).join(['  - ' + browser for browser in analysis_results['browser_artifacts']])}
"""
    
    # Save report to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"Report saved to: {output_file}")
    print("\nReport preview:")
    print(report[:1000] + "...\n" if len(report) > 1000 else report)
    
    return report

def main():
    """
    Main forensic analysis function
    """
    print("FORENSIC ANALYSIS SCRIPT")
    print("=" * 50)
    
    # Get the directory where registry files are stored
    evidence_dir = input("Enter path to extracted registry files (or press Enter for current directory): ").strip()
    if not evidence_dir:
        evidence_dir = "."
    
    analysis_results = {
        'installed_apps': [],
        'user_accounts': [], 
        'usb_history': [],
        'command_history': [],
        'browser_artifacts': []
    }
    
    try:
        # Analyze each registry component
        software_path = os.path.join(evidence_dir, "SOFTWARE")
        sam_path = os.path.join(evidence_dir, "SAM")
        system_path = os.path.join(evidence_dir, "SYSTEM")
        ntuser_path = os.path.join(evidence_dir, "NTUSER.DAT")
        
        # Check which files exist
        available_files = []
        for path, name in [(software_path, "SOFTWARE"), (sam_path, "SAM"), 
                          (system_path, "SYSTEM"), (ntuser_path, "NTUSER.DAT")]:
            if os.path.exists(path):
                available_files.append(name)
                print(f"Found: {name}")
            else:
                print(f"Missing: {name}")
        
        print(f"\nAnalyzing {len(available_files)} available registry files...")
        
        # Perform analyses based on available files
        if os.path.exists(software_path):
            analysis_results['installed_apps'] = analyze_installed_apps(software_path)
        
        if os.path.exists(sam_path) and os.path.exists(system_path):
            analysis_results['user_accounts'] = analyze_user_accounts(sam_path, system_path)
        
        if os.path.exists(system_path):
            analysis_results['usb_history'] = analyze_usb_history(system_path)
        
        if os.path.exists(ntuser_path):
            analysis_results['command_history'] = analyze_command_history(ntuser_path)
            analysis_results['browser_artifacts'] = analyze_browser_artifacts(ntuser_path)
        
        # Generate report
        report = generate_forensic_report(analysis_results)
        
        
        print("\n" + "="*60)
        print("ANALYSIS COMPLETE")
        print("="*60)
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        print("Please ensure registry files are extracted and paths are correct.")

if __name__ == "__main__":
    main()
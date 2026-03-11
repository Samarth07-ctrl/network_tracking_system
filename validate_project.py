#!/usr/bin/env python3
"""
Project Validation Script
Checks if all required files exist and have content
"""

import os
import sys

def check_file(filepath, min_size=0):
    """Check if file exists and has minimum size"""
    if not os.path.exists(filepath):
        return False, "Missing"
    
    size = os.path.getsize(filepath)
    if size < min_size:
        return False, f"Too small ({size} bytes)"
    
    return True, f"OK ({size} bytes)"

def main():
    print("=" * 60)
    print("Campus Network Traffic Analyzer - Project Validation")
    print("=" * 60)
    print()
    
    files_to_check = {
        "Backend Core": [
            ("backend/main.py", 1000),
            ("backend/config.yaml", 100),
            ("backend/schema.sql", 1000),
            ("backend/requirements.txt", 50),
        ],
        "Backend Modules": [
            ("backend/modules/packet_capture.py", 1000),
            ("backend/modules/traffic_analyzer.py", 1000),
            ("backend/modules/intrusion_detection.py", 1000),
            ("backend/modules/database.py", 1000),
            ("backend/modules/config_loader.py", 100),
        ],
        "Backend API": [
            ("backend/api/routes.py", 1000),
        ],
        "Frontend Core": [
            ("frontend/package.json", 100),
            ("frontend/public/index.html", 50),
            ("frontend/src/index.js", 50),
            ("frontend/src/App.js", 100),
        ],
        "Frontend Components": [
            ("frontend/src/components/Dashboard.js", 500),
            ("frontend/src/components/NetworkDetail.js", 500),
            ("frontend/src/components/SecurityPanel.js", 500),
        ],
        "Frontend Services": [
            ("frontend/src/services/api.js", 100),
        ],
        "Documentation": [
            ("README.md", 500),
            ("QUICKSTART.md", 500),
            ("SETUP_GUIDE.md", 1000),
            ("ARCHITECTURE.md", 1000),
        ],
        "Scripts": [
            ("start_backend.sh", 50),
            ("start_backend.bat", 50),
            ("start_frontend.sh", 50),
            ("start_frontend.bat", 50),
        ],
    }
    
    all_passed = True
    total_files = 0
    passed_files = 0
    
    for category, files in files_to_check.items():
        print(f"\n{category}:")
        print("-" * 60)
        
        for filepath, min_size in files:
            total_files += 1
            passed, status = check_file(filepath, min_size)
            
            if passed:
                passed_files += 1
                print(f"  ✓ {filepath:<50} {status}")
            else:
                all_passed = False
                print(f"  ✗ {filepath:<50} {status}")
    
    print()
    print("=" * 60)
    print(f"Results: {passed_files}/{total_files} files passed")
    
    if all_passed:
        print("Status: ✅ ALL CHECKS PASSED - PROJECT COMPLETE!")
        print()
        print("Next steps:")
        print("1. Set up MySQL database (see QUICKSTART.md)")
        print("2. Install dependencies:")
        print("   - Backend: cd backend && pip install -r requirements.txt")
        print("   - Frontend: cd frontend && npm install")
        print("3. Run the system:")
        print("   - Backend: cd backend && python main.py")
        print("   - Frontend: cd frontend && npm start")
        return 0
    else:
        print("Status: ❌ SOME FILES ARE MISSING OR INCOMPLETE")
        print()
        print("Please check the files marked with ✗ above")
        return 1

if __name__ == "__main__":
    sys.exit(main())

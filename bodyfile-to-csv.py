#!/usr/bin/env python3
"""
bodyfile_to_csv_with_report_lightweight_enhanced.py

Enhanced version with multiple bodyfile support, toggle filters, and improved UI.
Added features: MACB Timeline, Time Skew Detection, Interactive Zoom, Regex Search, Custom Flags, Hash Filtering,
File Signature (basic), Path Analysis (flags), Exports (JSON), Heatmap (basic via colored timeline), Batch Processing,
Authentication (basic), Cross-Platform Support.
"""

import csv
import json
import os
import sqlite3
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading
import time
import glob
import re
import base64  # For basic auth
import socket  # For port checking

# -------------------------------------------------------------------
# Utility Functions
# -------------------------------------------------------------------

    print("\nDeveloped by Jacob Wilson)
    print("dfirvault@gmail.com\n")

def convert_epoch_to_str(epoch):
    """Convert epoch to dd/mm/yyyy HH:MM:SS (UTC), or blank if 0/invalid."""
    try:
        epoch = int(epoch)
        if epoch > 0:
            return datetime.utcfromtimestamp(epoch).strftime('%d/%m/%Y %H:%M:%S')
    except Exception:
        pass
    return ""

def assess_noteworthy(name, mode, atime, mtime, ctime, crtime):
    """
    Return comma-separated noteworthy flags based on heuristics.
    Also return file type category.
    Added timestamp anomalies and cross-platform flags.
    """
    name_lower = (name or "").lower()
    flags = []
    file_type = "other"

    # File type detection
    if any(name_lower.endswith(ext) for ext in (".exe", ".dll", ".bin", ".elf", ".so", ".dylib")):
        file_type = "executable"
    elif any(name_lower.endswith(ext) for ext in (".py", ".sh", ".pl", ".rb", ".ps1", ".bat", ".cmd")):
        file_type = "script"
    elif any(name_lower.endswith(ext) for ext in (".conf", ".config", ".ini", ".cfg", ".xml", ".json", ".yaml", ".yml")):
        file_type = "config"
    elif any(name_lower.endswith(ext) for ext in (".log", ".txt", ".out", ".err")):
        file_type = "log"
    elif any(name_lower.endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff")):
        file_type = "image"
    elif any(name_lower.endswith(ext) for ext in (".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx")):
        file_type = "document"

    # Temp locations
    temp_dirs = ["/tmp/", "/var/tmp/", "/dev/shm/", "c:\\temp\\", "c:\\windows\\temp\\"]
    for t in temp_dirs:
        if name_lower.startswith(t):
            flags.append("Temp location")

    # Executables
    try:
        if isinstance(mode, str) and len(mode) > 3:
            if mode[3] == 'x' or mode[3] == 's':
                flags.append("Executable (mode)")
    except Exception:
        pass

    exec_exts = (".sh", ".py", ".pl", ".elf", ".bin", ".run", ".deb", ".exe", ".dll")
    if any(name_lower.endswith(ext) for ext in exec_exts):
        flags.append("Executable (ext)")

    # Hidden file
    last = name_lower.split("/")[-1] if "/" in name_lower else name_lower
    if last.startswith("."):
        flags.append("Hidden")

    # Sensitive files
    if name_lower.startswith("/root/"):
        flags.append("Root-owned location")
    if "/.ssh/" in name_lower or name_lower.endswith("/.ssh"):
        flags.append("SSH artifact")
    if name_lower.endswith("/shadow") or "/shadow" in name_lower and name_lower.startswith("/etc"):
        flags.append("Possible /etc/shadow")

    # Cross-platform
    windows_sensitive = ["c:\\programdata\\", "c:\\users\\appdata\\", "c:\\$recycle.bin\\"]
    for w in windows_sensitive:
        if name_lower.startswith(w):
            flags.append("Windows sensitive")

    mac_artifacts = [".ds_store", "launchagents/"]
    for m in mac_artifacts:
        if m in name_lower:
            flags.append("macOS artifact")

    linux_artifacts = ["/proc/", "/sys/"]
    for l in linux_artifacts:
        if name_lower.startswith(l):
            flags.append("Linux artifact")

    # Timestamp anomalies
    current_time = int(time.time())
    at = int(atime) if atime and atime.isdigit() else 0
    mt = int(mtime) if mtime and mtime.isdigit() else 0
    ct = int(ctime) if ctime and ctime.isdigit() else 0
    cr = int(crtime) if crtime and crtime.isdigit() else 0

    if cr > mt:
        flags.append("Create after modify")
    if any(t > current_time + 3600 for t in [at, mt, ct, cr] if t > 0):
        flags.append("Future timestamp")
    # Simple skew detection: large negative diffs
    if mt > 0 and cr > 0 and mt - cr < -86400 * 30:  # Modify 30 days before create
        flags.append("Time skew suspected")

    # Basic file signature (extension-based for now)
    known_malware_ext = [".wannacry", ".locky"]  # Example
    if any(name_lower.endswith(ext) for ext in known_malware_ext):
        flags.append("Known malware ext")

    return ", ".join(flags) if flags else "", file_type

def get_available_port(start_port=8000, max_port=8100):
    """Find an available port starting from start_port up to max_port"""
    for port in range(start_port, max_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    raise Exception(f"No available ports found between {start_port} and {max_port}")

def ask_date_range_filter():
    """Ask user if they want to apply date range filtering"""
    root = tk.Tk()
    root.title("Date Range Filter")
    root.geometry("520x650")  # Even larger to ensure everything fits
    root.resizable(False, False)
    
    # Create a main frame to hold everything
    main_frame = tk.Frame(root)
    main_frame.pack(fill='both', expand=True, padx=20, pady=10)
    
    result = {
        "apply_filter": False,
        "date_type": "mtime",
        "start_date": None,
        "end_date": None
    }
    
    def validate_and_confirm():
        """Validate dates and confirm selection"""
        start_text = start_date_entry.get().strip()
        end_text = end_date_entry.get().strip()
        
        # Validate dates
        errors = []
        
        if start_text:
            try:
                start_date = datetime.strptime(start_text, '%Y-%m-%d')
                result["start_date"] = start_date
            except ValueError:
                errors.append("Start date must be in YYYY-MM-DD format")
        
        if end_text:
            try:
                end_date = datetime.strptime(end_text, '%Y-%m-%d')
                result["end_date"] = end_date
            except ValueError:
                errors.append("End date must be in YYYY-MM-DD format")
        
        # Check if start date is before end date
        if start_text and end_text and not errors:
            if result["start_date"] > result["end_date"]:
                errors.append("Start date cannot be after end date")
        
        if errors:
            error_message = "\n".join(errors)
            messagebox.showerror("Invalid Dates", error_message)
            return
        
        result["apply_filter"] = True
        result["date_type"] = date_type_var.get()
        root.quit()
        root.destroy()
    
    def on_skip():
        """Skip date filtering"""
        result["apply_filter"] = False
        root.quit()
        root.destroy()
    
    def on_clear():
        """Clear all date fields"""
        start_date_entry.delete(0, tk.END)
        end_date_entry.delete(0, tk.END)
    
    def on_preset_days(days):
        """Set date range to last N days"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        start_date_entry.delete(0, tk.END)
        start_date_entry.insert(0, start_date.strftime('%Y-%m-%d'))
        
        end_date_entry.delete(0, tk.END)
        end_date_entry.insert(0, end_date.strftime('%Y-%m-%d'))
    
    # Center the window
    root.eval('tk::PlaceWindow . center')
    
    # Main title
    tk.Label(main_frame, text="Date Range Filter", font=("Arial", 16, "bold")).pack(pady=(0, 10))
    
    # Description
    desc_text = "Filter files by date range to reduce file size and focus analysis"
    tk.Label(main_frame, text=desc_text, wraplength=480, justify="center").pack(pady=(0, 15))
    
    # Date type selection frame
    type_frame = tk.LabelFrame(main_frame, text="1. Select Time Type to Filter", padx=15, pady=10)
    type_frame.pack(fill='x', pady=(0, 15))
    
    date_type_var = tk.StringVar(value="mtime")
    date_types = [
        ("Modified Time (mtime)", "mtime"),
        ("Access Time (atime)", "atime"), 
        ("Change Time (ctime)", "ctime"),
        ("Creation Time (crtime)", "crtime")
    ]
    
    for text, value in date_types:
        tk.Radiobutton(type_frame, text=text, variable=date_type_var, value=value, 
                      font=("Arial", 10)).pack(anchor='w', pady=2)
    
    # Date inputs frame
    date_frame = tk.LabelFrame(main_frame, text="2. Set Date Range", padx=15, pady=10)
    date_frame.pack(fill='x', pady=(0, 15))
    
    # Start date
    start_frame = tk.Frame(date_frame)
    start_frame.pack(fill='x', pady=8)
    tk.Label(start_frame, text="Start Date (YYYY-MM-DD):", width=22, anchor='w', 
             font=("Arial", 10)).pack(side=tk.LEFT)
    start_date_entry = tk.Entry(start_frame, width=15, font=("Arial", 10))
    start_date_entry.pack(side=tk.LEFT, padx=5)
    
    # End date
    end_frame = tk.Frame(date_frame)
    end_frame.pack(fill='x', pady=8)
    tk.Label(end_frame, text="End Date (YYYY-MM-DD):", width=22, anchor='w', 
             font=("Arial", 10)).pack(side=tk.LEFT)
    end_date_entry = tk.Entry(end_frame, width=15, font=("Arial", 10))
    end_date_entry.pack(side=tk.LEFT, padx=5)
    
    # Quick preset buttons
    preset_frame = tk.Frame(date_frame)
    preset_frame.pack(fill='x', pady=10)
    tk.Label(preset_frame, text="Quick Presets:", font=("Arial", 10, "bold")).pack(anchor='w')
    
    preset_btn_frame = tk.Frame(preset_frame)
    preset_btn_frame.pack(fill='x', pady=8)
    
    presets = [("Last 7 days", 7), ("Last 30 days", 30), ("Last 90 days", 90)]
    for text, days in presets:
        btn = tk.Button(preset_btn_frame, text=text, command=lambda d=days: on_preset_days(d),
                       width=12, font=("Arial", 9))
        btn.pack(side=tk.LEFT, padx=5)
    
    # Help text
    help_frame = tk.Frame(date_frame)
    help_frame.pack(fill='x', pady=10)
    tk.Label(help_frame, text="💡 Leave both blank for no date filtering", 
             font=("Arial", 9), fg='gray', justify='left').pack(anchor='w')
    tk.Label(help_frame, text="💡 Fill only start date to filter from that date forward", 
             font=("Arial", 9), fg='gray', justify='left').pack(anchor='w')
    tk.Label(help_frame, text="💡 Fill only end date to filter up to that date", 
             font=("Arial", 9), fg='gray', justify='left').pack(anchor='w')
    
    # Action buttons frame
    btn_frame = tk.Frame(main_frame)
    btn_frame.pack(pady=20)
    
    clear_btn = tk.Button(btn_frame, text="Clear Dates", command=on_clear, 
                         width=14, height=2, font=("Arial", 10))
    clear_btn.pack(side=tk.LEFT, padx=10)
    
    skip_btn = tk.Button(btn_frame, text="Skip Filter", command=on_skip, 
                        width=14, height=2, font=("Arial", 10))
    skip_btn.pack(side=tk.LEFT, padx=10)
    
    apply_btn = tk.Button(btn_frame, text="APPLY FILTER", command=validate_and_confirm, 
                         width=14, height=2, bg="#4CAF50", fg="white", 
                         font=("Arial", 10, "bold"))
    apply_btn.pack(side=tk.LEFT, padx=10)
    
    # Force window to be visible
    root.deiconify()
    root.lift()
    root.focus_force()
    
    root.mainloop()
    return result

def filter_rows_by_date_range(rows, date_filter):
    """Filter rows based on date range criteria"""
    if not date_filter["apply_filter"]:
        return rows
    
    date_type = date_filter["date_type"]
    start_date = date_filter["start_date"]
    end_date = date_filter["end_date"]
    
    if not start_date and not end_date:
        return rows
    
    filtered_rows = []
    
    for row in rows:
        # Get the appropriate epoch timestamp based on date_type
        epoch_key = f"_{date_type}_epoch"
        epoch_value = row.get(epoch_key, 0)
        
        if epoch_value == 0:
            continue
            
        # Convert epoch to datetime for comparison
        try:
            file_dt = datetime.utcfromtimestamp(epoch_value)
            
            # Apply date filters
            if start_date and file_dt < start_date:
                continue
            if end_date and file_dt > end_date:
                continue
                
            filtered_rows.append(row)
        except (ValueError, OSError):
            continue
    
    print(f"📅 Date filtering: {len(filtered_rows)} of {len(rows)} records match the criteria")
    return filtered_rows

# -------------------------------------------------------------------
# Database Storage for Fast Access
# -------------------------------------------------------------------

def create_database(rows, db_path, bodyfile_name="default"):
    """Create SQLite database for fast querying with multiple bodyfile support"""
    conn = sqlite3.connect(db_path)
    
    # Fixed regex function with error handling
    def regexp(expr, item):
        if item is None:
            return False
        try:
            return re.search(expr, item) is not None
        except re.error:
            return False
    
    conn.create_function("REGEXP", 2, regexp)
    cursor = conn.cursor()
    
    # Create table with bodyfile source
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            md5 TEXT,
            name TEXT,
            inode TEXT,
            mode TEXT,
            uid TEXT,
            gid TEXT,
            size INTEGER,
            atime TEXT,
            mtime TEXT,
            ctime TEXT,
            crtime TEXT,
            noteworthy TEXT,
            file_type TEXT,
            atime_epoch INTEGER,
            mtime_epoch INTEGER,
            ctime_epoch INTEGER,
            crtime_epoch INTEGER,
            bodyfile_source TEXT
        )
    ''')
    
    # Create indexes for fast searching
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_name ON files(name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_mtime ON files(mtime_epoch)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_atime ON files(atime_epoch)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ctime ON files(ctime_epoch)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_crtime ON files(crtime_epoch)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_noteworthy ON files(noteworthy)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_type ON files(file_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_bodyfile ON files(bodyfile_source)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_md5 ON files(md5)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_uid ON files(uid)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_gid ON files(gid)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_size ON files(size)')
    
    # Insert data
    for row in rows:
        cursor.execute('''
            INSERT INTO files (md5, name, inode, mode, uid, gid, size, atime, mtime, ctime, crtime, noteworthy, file_type, atime_epoch, mtime_epoch, ctime_epoch, crtime_epoch, bodyfile_source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            row["MD5"], row["Name"], row["Inode"], row["Mode"], row["UID"], row["GID"],
            int(row["Size"]) if row["Size"].isdigit() else 0,
            row["Atime"], row["Mtime"], row["Ctime"], row["Crtime"], row["Noteworthy"],
            row["FileType"],
            row["_atime_epoch"], row["_mtime_epoch"], row["_ctime_epoch"], row["_crtime_epoch"],
            bodyfile_name
        ))
    
    conn.commit()
    conn.close()
    print(f"📊 Database updated with {len(rows):,} records from {bodyfile_name}")

def add_bodyfile_to_database(bodyfile_path, db_path):
    """Add a new bodyfile to existing database"""
    rows = []
    processed = 0
    bodyfile_name = os.path.basename(bodyfile_path)

    # Read and parse bodyfile
    with open(bodyfile_path, "r", encoding="utf-8", errors="ignore") as infile:
        reader = csv.reader(infile, delimiter="|")
        for row in reader:
            processed += 1
            if len(row) not in (10, 11):
                continue

            if len(row) == 11:
                md5, name, inode, mode, uid, gid, size, atime, mtime, ctime, crtime = row
            else:
                md5, name, inode, mode, uid, gid, size, atime, mtime, ctime = row
                crtime = ""

            noteworthy, file_type = assess_noteworthy(name, mode, atime, mtime, ctime, crtime)

            row_dict = {
                "MD5": md5,
                "Name": name,
                "Inode": inode,
                "Mode": mode,
                "UID": uid,
                "GID": gid,
                "Size": size,
                "Atime": convert_epoch_to_str(atime),
                "Mtime": convert_epoch_to_str(mtime),
                "Ctime": convert_epoch_to_str(ctime),
                "Crtime": convert_epoch_to_str(crtime),
                "Noteworthy": noteworthy,
                "FileType": file_type,
                "_atime_epoch": int(atime) if atime and atime.isdigit() else 0,
                "_mtime_epoch": int(mtime) if mtime and mtime.isdigit() else 0,
                "_ctime_epoch": int(ctime) if ctime and ctime.isdigit() else 0,
                "_crtime_epoch": int(crtime) if crtime and crtime.isdigit() else 0,
            }

            rows.append(row_dict)

    # Add to database
    conn = sqlite3.connect(db_path)
    
    # Fixed regex function with error handling
    def regexp(expr, item):
        if item is None:
            return False
        try:
            return re.search(expr, item) is not None
        except re.error:
            return False
    
    conn.create_function("REGEXP", 2, regexp)
    cursor = conn.cursor()
    
    for row in rows:
        cursor.execute('''
            INSERT INTO files (md5, name, inode, mode, uid, gid, size, atime, mtime, ctime, crtime, noteworthy, file_type, atime_epoch, mtime_epoch, ctime_epoch, crtime_epoch, bodyfile_source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            row["MD5"], row["Name"], row["Inode"], row["Mode"], row["UID"], row["GID"],
            int(row["Size"]) if row["Size"].isdigit() else 0,
            row["Atime"], row["Mtime"], row["Ctime"], row["Crtime"], row["Noteworthy"],
            row["FileType"],
            row["_atime_epoch"], row["_mtime_epoch"], row["_ctime_epoch"], row["_crtime_epoch"],
            bodyfile_name
        ))
    
    conn.commit()
    conn.close()
    print(f"📊 Database updated with {len(rows):,} additional records from {bodyfile_name}")
    return len(rows)

def verify_database_contents(db_path):
    """Verify the database has the expected data"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check total count
        cursor.execute("SELECT COUNT(*) FROM files")
        total = cursor.fetchone()[0]
        print(f"📊 Database contains {total:,} records")
        
        # Check if we have any data with the expected columns
        cursor.execute("SELECT name, file_type FROM files LIMIT 5")
        sample_data = cursor.fetchall()
        print(f"📊 Sample data: {sample_data}")
        
        # Check bodyfile sources
        cursor.execute("SELECT DISTINCT bodyfile_source FROM files")
        sources = cursor.fetchall()
        print(f"📊 Bodyfile sources: {sources}")
        
        conn.close()
        return total > 0
        
    except Exception as e:
        print(f"❌ Database verification failed: {e}")
        return False

def check_database_schema(db_path):
    """Check the database schema and contents"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print(f"📊 Database tables: {tables}")
        
        # Check files table structure
        cursor.execute("PRAGMA table_info(files)")
        columns = cursor.fetchall()
        print("📊 Files table columns:")
        for col in columns:
            print(f"   - {col[1]} ({col[2]})")
        
        # Check a few records with all fields
        cursor.execute("SELECT * FROM files LIMIT 3")
        sample_records = cursor.fetchall()
        print("📊 Sample full records:")
        for i, record in enumerate(sample_records):
            print(f"   Record {i}: {record}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Database schema check failed: {e}")

def test_database_query(db_path):
    """Test a simple database query"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Simple test query
        cursor.execute("SELECT COUNT(*) FROM files WHERE name LIKE '%/%'")
        count = cursor.fetchone()[0]
        print(f"✅ Test query found {count} files with '/' in name")
        
        # Test with no WHERE clause
        cursor.execute("SELECT COUNT(*) FROM files")
        total = cursor.fetchone()[0]
        print(f"✅ Total files in database: {total}")
        
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def get_summary_stats(db_path, timeline_type="mtime"):
    """Get summary statistics from database with configurable timeline type"""
    conn = sqlite3.connect(db_path)
    
    # Fixed regex function with error handling
    def regexp(expr, item):
        if item is None:
            return False
        try:
            return re.search(expr, item) is not None
        except re.error:
            return False
    
    conn.create_function("REGEXP", 2, regexp)
    cursor = conn.cursor()
    
    stats = {}
    
    # Basic counts
    cursor.execute("SELECT COUNT(*) FROM files")
    stats['total_files'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM files WHERE noteworthy != ''")
    stats['noteworthy_count'] = cursor.fetchone()[0]
    
    # File type breakdown
    cursor.execute('''
        SELECT 
            SUM(CASE WHEN file_type = 'executable' THEN 1 ELSE 0 END) as executables,
            SUM(CASE WHEN file_type = 'script' THEN 1 ELSE 0 END) as scripts,
            SUM(CASE WHEN file_type = 'config' THEN 1 ELSE 0 END) as configs,
            SUM(CASE WHEN file_type = 'log' THEN 1 ELSE 0 END) as logs,
            SUM(CASE WHEN file_type = 'image' THEN 1 ELSE 0 END) as images,
            SUM(CASE WHEN file_type = 'document' THEN 1 ELSE 0 END) as documents,
            SUM(CASE WHEN file_type = 'other' THEN 1 ELSE 0 END) as other,
            SUM(CASE WHEN name LIKE '/tmp/%' OR name LIKE '/var/tmp/%' OR name LIKE '/dev/shm/%' THEN 1 ELSE 0 END) as temp_files,
            SUM(CASE WHEN name LIKE '%/.ssh/%' OR name LIKE '%/.ssh' THEN 1 ELSE 0 END) as ssh_files
        FROM files
    ''')
    result = cursor.fetchone()
    stats.update({
        'executables': result[0],
        'scripts': result[1],
        'configs': result[2],
        'logs': result[3],
        'images': result[4],
        'documents': result[5],
        'other': result[6],
        'temp_files': result[7],
        'ssh_files': result[8]
    })
    
    # Get available bodyfiles
    cursor.execute("SELECT DISTINCT bodyfile_source FROM files")
    stats['bodyfiles'] = [row[0] for row in cursor.fetchall()]
    
    # Timeline data based on selected type (last 30 days)
    time_columns = {
        "atime": "atime_epoch",
        "mtime": "mtime_epoch",
        "ctime": "ctime_epoch",
        "crtime": "crtime_epoch"
    }
    if timeline_type == "macb":
        # Combined MACB
        cursor.execute('''
            SELECT date(datetime(ts, 'unixepoch')), COUNT(*) 
            FROM (
                SELECT atime_epoch AS ts FROM files WHERE atime_epoch > 0
                UNION ALL
                SELECT mtime_epoch AS ts FROM files WHERE mtime_epoch > 0
                UNION ALL
                SELECT ctime_epoch AS ts FROM files WHERE ctime_epoch > 0
                UNION ALL
                SELECT crtime_epoch AS ts FROM files WHERE crtime_epoch > 0
            )
            GROUP BY date(datetime(ts, 'unixepoch'))
            ORDER BY date(datetime(ts, 'unixepoch')) DESC 
            LIMIT 30
        ''')
    else:
        time_column = time_columns.get(timeline_type, "mtime_epoch")
        cursor.execute(f'''
            SELECT date(datetime({time_column}, 'unixepoch')), COUNT(*) 
            FROM files 
            WHERE {time_column} > 0 
            GROUP BY date(datetime({time_column}, 'unixepoch'))
            ORDER BY date(datetime({time_column}, 'unixepoch')) DESC 
            LIMIT 30
        ''')
    timeline_data = cursor.fetchall()
    stats['timeline'] = timeline_data
    
    # Flag statistics
    cursor.execute("SELECT COUNT(*) FROM files WHERE noteworthy LIKE '%Temp location%'")
    stats['temp_count'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM files WHERE noteworthy LIKE '%Executable%'")
    stats['executable_count'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM files WHERE noteworthy LIKE '%Hidden%'")
    stats['hidden_count'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM files WHERE noteworthy LIKE '%SSH%'")
    stats['ssh_count'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM files WHERE noteworthy LIKE '%Root-owned%'")
    stats['root_count'] = cursor.fetchone()[0]
    
    # Anomaly counts
    current_time = int(time.time())
    cursor.execute(f'''
        SELECT COUNT(*) FROM files 
        WHERE crtime_epoch > mtime_epoch 
        OR atime_epoch > {current_time} OR mtime_epoch > {current_time} 
        OR ctime_epoch > {current_time} OR crtime_epoch > {current_time}
    ''')
    stats['anomaly_count'] = cursor.fetchone()[0]
    
    conn.close()
    return stats

# -------------------------------------------------------------------
# Lightweight HTML Generation
# -------------------------------------------------------------------

def generate_lightweight_html(db_path, csv_path, port):
    """Generate a small HTML file that uses AJAX to load data"""
    out_dir = os.path.dirname(os.path.abspath(csv_path)) or "."
    base = os.path.splitext(os.path.basename(csv_path))[0]
    html_path = os.path.join(out_dir, f"{base}_report.html")
    
    stats = get_summary_stats(db_path)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{base} - Forensic Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@1.2.1/dist/chartjs-plugin-zoom.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {{
            --primary: #4A90E2;
            --secondary: #7B68EE;
            --dark: #2C3E50;
            --sidebar-bg: #F8F9FA;
        }}
        
        * {{
            margin: 0; padding: 0; box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: #f5f7fa; color: #333;
        }}
        
        .container {{
            display: flex; min-height: 100vh;
        }}
        
        .sidebar {{
            width: 320px; background: var(--sidebar-bg);
            border-right: 1px solid #dee2e6; padding: 20px;
            position: fixed; height: 100vh; overflow-y: auto;
        }}
        
        .main-content {{
            flex: 1; margin-left: 320px; padding: 20px;
        }}
        
        .card {{
            background: white; border-radius: 8px; padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;
        }}
        
        .btn {{
            padding: 8px 16px; border: none; border-radius: 4px;
            cursor: pointer; display: inline-flex; align-items: center; gap: 6px;
        }}
        
        .btn-primary {{
            background: var(--primary); color: white;
        }}
        
        table {{
            width: 100%; border-collapse: collapse; font-size: 13px;
        }}
        
        th, td {{
            padding: 10px 8px; text-align: left; border-bottom: 1px solid #dee2e6;
        }}
        
        th {{
            background: #f8f9fa; font-weight: 600; cursor: pointer;
        }}
        
        .badge {{
            display: inline-block; padding: 2px 8px; border-radius: 12px;
            font-size: 11px; font-weight: 600; margin-right: 4px;
        }}
        
        .badge-warning {{ background: #fff3cd; color: #856404; }}
        .badge-danger {{ background: #f8d7da; color: #721c24; }}
        .badge-info {{ background: #d1ecf1; color: #0c5460; }}
        
        .loading {{
            text-align: center; padding: 20px; color: #6c757d;
        }}
        
        .pagination {{
            display: flex; justify-content: space-between; align-items: center;
            margin-top: 15px; padding-top: 15px; border-top: 1px solid #dee2e6;
        }}
        
        .search-box {{
            position: relative; margin-bottom: 15px;
        }}
        
        .search-box input {{
            width: 100%; padding: 10px 35px 10px 35px;
            border: 1px solid #ced4da; border-radius: 4px;
        }}
        
        .search-box i {{
            position: absolute; left: 12px; top: 50%;
            transform: translateY(-50%); color: #6c757d;
        }}
        
        .chart-container {{
            height: 200px; position: relative;
        }}
        
        .filter-toggle {{
            display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 15px;
        }}
        
        .filter-btn {{
            padding: 6px 12px; border: 1px solid #dee2e6; border-radius: 20px;
            background: white; cursor: pointer; font-size: 12px;
            transition: all 0.2s;
        }}
        
        .filter-btn.active {{
            background: var(--primary); color: white; border-color: var(--primary);
        }}
        
        .search-controls {{
            display: flex; gap: 10px; margin-bottom: 15px;
        }}
        
        .search-controls input {{
            flex: 1;
        }}
        
        .bodyfile-selector {{
            margin-bottom: 15px;
        }}
        
        .bodyfile-selector select {{
            width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ced4da;
        }}
        
        .date-range {{
            margin-bottom: 15px;
        }}
        
        .date-range input {{
            width: 100%; padding: 8px; margin-bottom: 8px;
            border: 1px solid #ced4da; border-radius: 4px;
        }}
        
        .date-range label {{
            font-size: 12px; color: #6c757d; margin-bottom: 4px; display: block;
        }}
        
        .timeline-radio {{
            margin-bottom: 15px;
        }}
        
        .radio-group {{
            display: flex; flex-wrap: wrap; gap: 10px; margin-top: 8px;
        }}
        
        .radio-option {{
            display: flex; align-items: center; gap: 5px; font-size: 12px;
        }}
        
        .radio-option input {{
            margin: 0;
        }}
        
        .advanced-filters {{
            margin-bottom: 15px;
        }}
        
        .advanced-filters input {{
            width: 100%; padding: 8px; margin-bottom: 8px;
            border: 1px solid #ced4da; border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div style="padding-bottom: 20px; border-bottom: 1px solid #dee2e6; margin-bottom: 20px;">
                <h2><i class="fas fa-search"></i> Forensic Explorer</h2>
                <div style="font-size: 12px; color: #6c757d;">{base}</div>
            </div>

            <div class="search-controls">
                <div class="search-box" style="flex: 1;">
                    <i class="fas fa-search"></i>
                    <input type="text" id="globalSearch" placeholder="Search files...">
                </div>
                <label for="regexSearch" style="white-space: nowrap; display: flex; align-items: center; gap: 5px;">
                    <input type="checkbox" id="regexSearch"> Regex
                </label>
                <button class="btn btn-primary" onclick="searchFiles()" style="white-space: nowrap;">
                    <i class="fas fa-search"></i> Search
                </button>
            </div>

            <div class="advanced-filters">
                <label for="hashSearch">MD5 Hash:</label>
                <input id="hashSearch" placeholder="Full or partial hash">
                
                <label for="minSize">Min Size (bytes):</label>
                <input id="minSize" type="number">
                
                <label for="uidFilter">UID:</label>
                <input id="uidFilter">
                
                <label for="gidFilter">GID:</label>
                <input id="gidFilter">
                
                <label for="dirFilter">Directory Pattern:</label>
                <input id="dirFilter" placeholder="e.g., /etc/*">
            </div>

            <div class="bodyfile-selector">
                <h3 style="font-size: 14px; margin-bottom: 10px;"><i class="fas fa-database"></i> Bodyfile Source</h3>
                <select id="bodyfileFilter" onchange="searchFiles()">
                    <option value="all">All Bodyfiles</option>
                    {''.join([f'<option value="{bf}">{bf}</option>' for bf in stats['bodyfiles']])}
                </select>
            </div>

            <div style="margin-bottom: 20px;">
                <h3 style="font-size: 14px; margin-bottom: 10px;"><i class="fas fa-filter"></i> File Type Filters</h3>
                <div class="filter-toggle">
                    <button class="filter-btn active" data-type="all" onclick="toggleFilter(this, 'file_type')">All</button>
                    <button class="filter-btn" data-type="executable" onclick="toggleFilter(this, 'file_type')">Executables</button>
                    <button class="filter-btn" data-type="script" onclick="toggleFilter(this, 'file_type')">Scripts</button>
                    <button class="filter-btn" data-type="config" onclick="toggleFilter(this, 'file_type')">Configs</button>
                    <button class="filter-btn" data-type="log" onclick="toggleFilter(this, 'file_type')">Logs</button>
                    <button class="filter-btn" data-type="image" onclick="toggleFilter(this, 'file_type')">Images</button>
                    <button class="filter-btn" data-type="document" onclick="toggleFilter(this, 'file_type')">Documents</button>
                </div>
                
                <h3 style="font-size: 14px; margin-bottom: 10px; margin-top: 15px;"><i class="fas fa-flag"></i> Flag Filters</h3>
                <div class="filter-toggle">
                    <button class="filter-btn active" data-type="all" onclick="toggleFilter(this, 'flag')">All</button>
                    <button class="filter-btn" data-type="Temp location" onclick="toggleFilter(this, 'flag')">Temp ({stats['temp_count']})</button>
                    <button class="filter-btn" data-type="Executable" onclick="toggleFilter(this, 'flag')">Executable ({stats['executable_count']})</button>
                    <button class="filter-btn" data-type="Hidden" onclick="toggleFilter(this, 'flag')">Hidden ({stats['hidden_count']})</button>
                    <button class="filter-btn" data-type="SSH" onclick="toggleFilter(this, 'flag')">SSH ({stats['ssh_count']})</button>
                    <button class="filter-btn" data-type="Root-owned" onclick="toggleFilter(this, 'flag')">Root-owned ({stats['root_count']})</button>
                </div>
            </div>

            <div class="date-range">
                <h3 style="font-size: 14px; margin-bottom: 10px;"><i class="fas fa-calendar"></i> Date Range Filters</h3>
                
                <div>
                    <label for="mtimeStart">Modified From:</label>
                    <input type="date" id="mtimeStart" onchange="searchFiles()">
                </div>
                <div>
                    <label for="mtimeEnd">Modified To:</label>
                    <input type="date" id="mtimeEnd" onchange="searchFiles()">
                </div>
                
                <div style="margin-top: 10px;">
                    <label for="atimeStart">Accessed From:</label>
                    <input type="date" id="atimeStart" onchange="searchFiles()">
                </div>
                <div>
                    <label for="atimeEnd">Accessed To:</label>
                    <input type="date" id="atimeEnd" onchange="searchFiles()">
                </div>
            </div>

            <div class="card">
                <h3 style="margin-bottom: 15px;"><i class="fas fa-chart-bar"></i> Quick Stats</h3>
                <div style="font-size: 12px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Total Files:</span>
                        <span style="font-weight: 600;">{stats['total_files']:,}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Noteworthy:</span>
                        <span style="font-weight: 600;">{stats['noteworthy_count']:,}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Executables:</span>
                        <span style="font-weight: 600;">{stats['executables']:,}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Scripts:</span>
                        <span style="font-weight: 600;">{stats['scripts']:,}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Configs:</span>
                        <span style="font-weight: 600;">{stats['configs']:,}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Anomalies:</span>
                        <span style="font-weight: 600;">{stats['anomaly_count']:,}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Bodyfiles:</span>
                        <span style="font-weight: 600;">{len(stats['bodyfiles'])}</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="main-content">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h1>Forensic Analysis Dashboard</h1>
                <div>
                    <button class="btn" onclick="addBodyfile()" style="margin-right: 10px;">
                        <i class="fas fa-plus"></i> Add Bodyfile
                    </button>
                    <button class="btn btn-primary" onclick="exportResults('csv')" style="margin-right: 10px;">
                        <i class="fas fa-download"></i> Export CSV
                    </button>
                    <button class="btn btn-primary" onclick="exportResults('json')">
                        <i class="fas fa-download"></i> Export JSON
                    </button>
                </div>
            </div>

            <!-- Charts -->
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;">
                <div class="card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                        <h3 style="margin: 0;">Timeline Activity</h3>
                        <div class="timeline-radio">
                            <div class="radio-group">
                                <label class="radio-option">
                                    <input type="radio" name="timelineType" value="mtime" checked onchange="updateTimelineChart()"> Modified
                                </label>
                                <label class="radio-option">
                                    <input type="radio" name="timelineType" value="atime" onchange="updateTimelineChart()"> Accessed
                                </label>
                                <label class="radio-option">
                                    <input type="radio" name="timelineType" value="ctime" onchange="updateTimelineChart()"> Changed
                                </label>
                                <label class="radio-option">
                                    <input type="radio" name="timelineType" value="crtime" onchange="updateTimelineChart()"> Created
                                </label>
                                <label class="radio-option">
                                    <input type="radio" name="timelineType" value="macb" onchange="updateTimelineChart()"> MACB
                                </label>
                            </div>
                        </div>
                    </div>
                    <div class="chart-container">
                        <canvas id="timelineChart"></canvas>
                    </div>
                </div>
                <div class="card">
                    <h3 style="margin-bottom: 15px;">File Types</h3>
                    <div class="chart-container">
                        <canvas id="fileTypeChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Results -->
            <div class="card">
                <h3 style="margin-bottom: 15px;">Search Results</h3>
                <div id="resultsInfo" style="font-size: 12px; color: #6c757d; margin-bottom: 15px;">
                    Loading...
                </div>
                <div style="overflow-x: auto; max-height: 500px; overflow-y: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th onclick="sortTable('name')">Name</th>
                                <th onclick="sortTable('size')">Size</th>
                                <th onclick="sortTable('atime_epoch')">Access</th>
                                <th onclick="sortTable('mtime_epoch')">Modified</th>
                                <th onclick="sortTable('crtime_epoch')">Created</th>
                                <th>File Type</th>
                                <th>Bodyfile</th>
                                <th>Flags</th>
                            </tr>
                        </thead>
                        <tbody id="resultsBody">
                            <tr><td colspan="8" class="loading">Loading data...</td></tr>
                        </tbody>
                    </table>
                </div>
                <div class="pagination">
                    <div id="pageInfo" style="font-size: 12px; color: #6c757d;">Page 1</div>
                    <div>
                        <button class="btn" onclick="changePage(-1)" id="prevBtn" disabled>Previous</button>
                        <button class="btn" onclick="changePage(1)" id="nextBtn">Next</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentPage = 1;
        let pageSize = 50;
        let currentSort = 'name';
        let currentSortDir = 'asc';
        let currentSearch = '';
        let currentFileTypes = ['all'];
        let currentFlags = ['all'];
        let currentBodyfile = 'all';
        let searchTimeout = null;
        let timelineChart = null;

        // Initialize charts
        function initCharts() {{
            updateTimelineChart();
            initFileTypeChart();
        }}

        function updateTimelineChart() {{
            const timelineType = document.querySelector('input[name="timelineType"]:checked').value;
            
            // Fetch updated timeline data from server
            fetch(`http://localhost:{port}/api/timeline?type=${{timelineType}}`)
                .then(response => response.json())
                .then(data => {{
                    renderTimelineChart(data);
                }})
                .catch(error => {{
                    console.error('Error loading timeline data:', error);
                }});
        }}

        function renderTimelineChart(timelineData) {{
            const timelineCtx = document.getElementById('timelineChart').getContext('2d');
            
            // Destroy existing chart if it exists
            if (timelineChart) {{
                timelineChart.destroy();
            }}
            
            timelineChart = new Chart(timelineCtx, {{
                type: 'line',
                data: {{
                    labels: timelineData.labels,
                    datasets: [{{
                        label: 'File Activity',
                        data: timelineData.data,
                        borderColor: '#4A90E2',
                        backgroundColor: 'rgba(74, 144, 226, 0.1)',
                        tension: 0.4,
                        fill: true
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ 
                        legend: {{ display: false }},
                        title: {{
                            display: true,
                            text: timelineData.title
                        }},
                        zoom: {{
                            zoom: {{
                                wheel: {{ enabled: true }},
                                pinch: {{ enabled: true }},
                                mode: 'xy'
                            }},
                            pan: {{
                                enabled: true,
                                mode: 'xy'
                            }}
                        }}
                    }},
                    scales: {{
                        y: {{ beginAtZero: true }},
                        x: {{ ticks: {{ maxRotation: 45 }} }}
                    }}
                }}
            }});
        }}

        function initFileTypeChart() {{
            const fileTypeCtx = document.getElementById('fileTypeChart').getContext('2d');
            new Chart(fileTypeCtx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Executables', 'Scripts', 'Configs', 'Logs', 'Images', 'Documents', 'Other'],
                    datasets: [{{
                        data: {json.dumps([
                            stats['executables'], stats['scripts'], stats['configs'], 
                            stats['logs'], stats['images'], stats['documents'], stats['other']
                        ])},
                        backgroundColor: ['#4A90E2', '#7B68EE', '#32CD32', '#FFA500', '#DC143C', '#9370DB', '#6c757d']
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ position: 'bottom' }} }}
                }}
            }});
        }}

        // Auto-search with debouncing
        function setupAutoSearch() {{
            document.getElementById('globalSearch').addEventListener('input', function() {{
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(searchFiles, 300);
            }});
            // Add listeners for advanced filters
            ['hashSearch', 'minSize', 'uidFilter', 'gidFilter', 'dirFilter'].forEach(id => {{
                document.getElementById(id).addEventListener('input', function() {{
                    clearTimeout(searchTimeout);
                    searchTimeout = setTimeout(searchFiles, 300);
                }});
            }});
            document.getElementById('regexSearch').addEventListener('change', searchFiles);
        }}

        // Toggle file type and flag filters
        function toggleFilter(button, filterType) {{
            const filterValue = button.getAttribute('data-type');
            
            if (filterType === 'file_type') {{
                if (filterValue === 'all') {{
                    document.querySelectorAll('.filter-btn[data-filter-type="file_type"]').forEach(btn => {{
                        btn.classList.remove('active');
                    }});
                    button.classList.add('active');
                    currentFileTypes = ['all'];
                }} else {{
                    button.classList.toggle('active');
                    const allBtn = document.querySelector('.filter-btn[data-type="all"][data-filter-type="file_type"]');
                    allBtn.classList.remove('active');
                    currentFileTypes = Array.from(document.querySelectorAll('.filter-btn.active[data-filter-type="file_type"]'))
                        .map(btn => btn.getAttribute('data-type'))
                        .filter(type => type !== 'all');
                    if (currentFileTypes.length === 0) {{
                        allBtn.classList.add('active');
                        currentFileTypes = ['all'];
                    }}
                }}
            }} else if (filterType === 'flag') {{
                if (filterValue === 'all') {{
                    document.querySelectorAll('.filter-btn[data-filter-type="flag"]').forEach(btn => {{
                        btn.classList.remove('active');
                    }});
                    button.classList.add('active');
                    currentFlags = ['all'];
                }} else {{
                    button.classList.toggle('active');
                    const allBtn = document.querySelector('.filter-btn[data-type="all"][data-filter-type="flag"]');
                    allBtn.classList.remove('active');
                    currentFlags = Array.from(document.querySelectorAll('.filter-btn.active[data-filter-type="flag"]'))
                        .map(btn => btn.getAttribute('data-type'))
                        .filter(type => type !== 'all');
                    if (currentFlags.length === 0) {{
                        allBtn.classList.add('active');
                        currentFlags = ['all'];
                    }}
                }}
            }}
            
            searchFiles();
        }}

        // Load data from server
        async function loadData() {{
            try {{
                const fileTypesParam = currentFileTypes.includes('all') ? '' : currentFileTypes.join(',');
                const flagsParam = currentFlags.includes('all') ? '' : currentFlags.join(',');
                const mtimeStart = document.getElementById('mtimeStart').value;
                const mtimeEnd = document.getElementById('mtimeEnd').value;
                const atimeStart = document.getElementById('atimeStart').value;
                const atimeEnd = document.getElementById('atimeEnd').value;
                const regex = document.getElementById('regexSearch').checked ? 1 : 0;
                const hashSearch = document.getElementById('hashSearch').value;
                const minSize = document.getElementById('minSize').value;
                const uidFilter = document.getElementById('uidFilter').value;
                const gidFilter = document.getElementById('gidFilter').value;
                const dirFilter = document.getElementById('dirFilter').value.replace('*', '%');
                
                const response = await fetch(`http://localhost:{port}/api/data?page=${{currentPage}}&size=${{pageSize}}&search=${{encodeURIComponent(currentSearch)}}&sort=${{currentSort}}&dir=${{currentSortDir}}&file_types=${{fileTypesParam}}&flags=${{flagsParam}}&bodyfile=${{currentBodyfile}}&mtime_start=${{mtimeStart}}&mtime_end=${{mtimeEnd}}&atime_start=${{atimeStart}}&atime_end=${{atimeEnd}}&regex=${{regex}}&hash=${{encodeURIComponent(hashSearch)}}&min_size=${{minSize}}&uid=${{uidFilter}}&gid=${{gidFilter}}&dir=${{encodeURIComponent(dirFilter)}}`);
                const data = await response.json();
                displayResults(data);
            }} catch (error) {{
                console.error('Error loading data:', error);
                document.getElementById('resultsBody').innerHTML = '<tr><td colspan="8">Error loading data</td></tr>';
            }}
        }}

        // Display results
        function displayResults(data) {{
            const tbody = document.getElementById('resultsBody');
            const info = document.getElementById('resultsInfo');
            
            info.textContent = `Showing ${{data.start}}-${{data.end}} of ${{data.total}} files`;
            document.getElementById('pageInfo').textContent = `Page ${{data.page}} of ${{Math.ceil(data.total / pageSize)}}`;
            
            document.getElementById('prevBtn').disabled = data.page <= 1;
            document.getElementById('nextBtn').disabled = data.page >= Math.ceil(data.total / pageSize);
            
            if (data.files.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="8">No files found</td></tr>';
                return;
            }}
            
            let html = '';
            data.files.forEach(file => {{
                let badges = '';
                if (file.noteworthy) {{
                    if (file.noteworthy.includes('Temp')) badges += '<span class="badge badge-warning">Temp</span>';
                    if (file.noteworthy.includes('Executable')) badges += '<span class="badge badge-danger">Exec</span>';
                    if (file.noteworthy.includes('Hidden')) badges += '<span class="badge badge-warning">Hidden</span>';
                    if (file.noteworthy.includes('SSH')) badges += '<span class="badge badge-info">SSH</span>';
                    if (file.noteworthy.includes('Root-owned')) badges += '<span class="badge badge-danger">Root</span>';
                    if (file.noteworthy.includes('Create after modify')) badges += '<span class="badge badge-danger">Timestamp Anomaly</span>';
                    if (file.noteworthy.includes('Future timestamp')) badges += '<span class="badge badge-danger">Future TS</span>';
                    if (file.noteworthy.includes('Time skew')) badges += '<span class="badge badge-warning">Skew</span>';
                }}
                
                html += `
                    <tr>
                        <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis;" title="${{file.name}}">${{file.name}}</td>
                        <td>${{formatBytes(file.size)}}</td>
                        <td>${{file.atime || '-'}}</td>
                        <td>${{file.mtime || '-'}}</td>
                        <td>${{file.crtime || '-'}}</td>
                        <td><span class="badge badge-info">${{file.file_type || 'other'}}</span></td>
                        <td>${{file.bodyfile_source}}</td>
                        <td>${{badges}}</td>
                    </tr>
                `;
            }});
            
            tbody.innerHTML = html;
        }}

        // Utility functions
        function formatBytes(bytes) {{
            if (!bytes) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }}

        function searchFiles() {{
            currentSearch = document.getElementById('globalSearch').value;
            currentBodyfile = document.getElementById('bodyfileFilter').value;
            currentPage = 1;
            loadData();
        }}

        function sortTable(column) {{
            if (currentSort === column) {{
                currentSortDir = currentSortDir === 'asc' ? 'desc' : 'asc';
            }} else {{
                currentSort = column;
                currentSortDir = 'asc';
            }}
            loadData();
        }}

        function changePage(direction) {{
            currentPage += direction;
            loadData();
        }}

        function exportResults(format) {{
            const fileTypesParam = currentFileTypes.includes('all') ? '' : currentFileTypes.join(',');
            const flagsParam = currentFlags.includes('all') ? '' : currentFlags.join(',');
            const mtimeStart = document.getElementById('mtimeStart').value;
            const mtimeEnd = document.getElementById('mtimeEnd').value;
            const atimeStart = document.getElementById('atimeStart').value;
            const atimeEnd = document.getElementById('atimeEnd').value;
            const regex = document.getElementById('regexSearch').checked ? 1 : 0;
            const hashSearch = document.getElementById('hashSearch').value;
            const minSize = document.getElementById('minSize').value;
            const uidFilter = document.getElementById('uidFilter').value;
            const gidFilter = document.getElementById('gidFilter').value;
            const dirFilter = document.getElementById('dirFilter').value.replace('*', '%');
            
            window.open(`http://localhost:{port}/api/export?format=${{format}}&search=${{encodeURIComponent(currentSearch)}}&file_types=${{fileTypesParam}}&flags=${{flagsParam}}&bodyfile=${{currentBodyfile}}&mtime_start=${{mtimeStart}}&mtime_end=${{mtimeEnd}}&atime_start=${{atimeStart}}&atime_end=${{atimeEnd}}&regex=${{regex}}&hash=${{encodeURIComponent(hashSearch)}}&min_size=${{minSize}}&uid=${{uidFilter}}&gid=${{gidFilter}}&dir=${{encodeURIComponent(dirFilter)}}`, '_blank');
        }}

        function addBodyfile() {{
            if (confirm('This will open a file dialog to add a new bodyfile. Continue?')) {{
                fetch(`http://localhost:{port}/api/add_bodyfile`, {{ method: 'POST' }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        alert('Bodyfile added successfully! Refreshing page...');
                        location.reload();
                    }} else {{
                        alert('Error adding bodyfile: ' + data.error);
                    }}
                }})
                .catch(error => {{
                    alert('Error communicating with server: ' + error);
                }});
            }}
        }}

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {{
            // Set data-filter-type attributes for filter buttons
            document.querySelectorAll('.filter-btn').forEach(btn => {{
                const isFileType = btn.closest('div').previousElementSibling.textContent.includes('File Type');
                btn.setAttribute('data-filter-type', isFileType ? 'file_type' : 'flag');
            }});
            
            initCharts();
            setupAutoSearch();
            loadData();
        }});
    </script>
</body>
</html>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return html_path

# -------------------------------------------------------------------
# Enhanced Web Server for Data API
# -------------------------------------------------------------------

class ForensicRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.db_path = kwargs.pop('db_path')
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        if self.path.startswith('/api/'):
            self.handle_api()
        else:
            super().do_GET()
    
    def do_POST(self):
        if self.path.startswith('/api/add_bodyfile'):
            self.handle_add_bodyfile()
        else:
            self.send_error(404)
    
    def handle_api(self):
        if self.path.startswith('/api/data'):
            self.handle_data_api()
        elif self.path.startswith('/api/export'):
            self.handle_export_api()
        elif self.path.startswith('/api/timeline'):
            self.handle_timeline_api()
        elif self.path.startswith('/api/add_bodyfile'):
            self.handle_add_bodyfile()
        else:
            self.send_error(404)
    
    def handle_timeline_api(self):
        """Handle timeline data requests with different time types"""
        import urllib.parse
        from urllib.parse import parse_qs
        
        query = urllib.parse.urlparse(self.path).query
        params = parse_qs(query)
        timeline_type = params.get('type', ['mtime'])[0]
        
        print(f"📈 Timeline API request: type={timeline_type}")
        
        stats = get_summary_stats(self.db_path, timeline_type)
        
        # Prepare timeline data for chart
        labels = [item[0] for item in stats['timeline']]
        data = [item[1] for item in stats['timeline']]
        
        print(f"📈 Timeline data: {len(labels)} points")
        
        timeline_titles = {
            'mtime': 'File Modifications Timeline',
            'atime': 'File Access Timeline', 
            'ctime': 'File Changes Timeline',
            'crtime': 'File Creation Timeline',
            'macb': 'Combined MACB Timeline'
        }
        
        response = {
            'labels': labels,
            'data': data,
            'title': timeline_titles.get(timeline_type, 'Timeline Activity')
        }
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def handle_data_api(self):
        import urllib.parse
        from urllib.parse import parse_qs
        
        # Parse query parameters
        query = urllib.parse.urlparse(self.path).query
        params = parse_qs(query)
        
        # DEBUG: Show raw parameter parsing
        print(f"🔍 RAW URL: {self.path}")
        print(f"🔍 RAW QUERY: {query}")
        print(f"🔍 RAW PARAMS: {params}")
        
        page = int(params.get('page', [1])[0])
        size = int(params.get('size', [50])[0])
        search = params.get('search', [''])[0]
        sort = params.get('sort', ['name'])[0]
        sort_dir = params.get('dir', ['asc'])[0]
        
        # FIX: Use a different parameter name for directory filter
        # Check if 'dir_filter' exists, otherwise use empty string
        if 'dir_filter' in params:
            dir_filter = params.get('dir_filter', [''])[0]
        else:
            # Fallback for old parameter name
            dir_filter = params.get('dir', [''])[0]
            # If we got 'asc' (sort direction), it's wrong - set to empty
            if dir_filter == 'asc':
                dir_filter = ''
        
        file_types = params.get('file_types', [''])[0]
        flags = params.get('flags', [''])[0]
        bodyfile = params.get('bodyfile', ['all'])[0]
        mtime_start = params.get('mtime_start', [''])[0]
        mtime_end = params.get('mtime_end', [''])[0]
        atime_start = params.get('atime_start', [''])[0]
        atime_end = params.get('atime_end', [''])[0]
        regex = int(params.get('regex', [0])[0])
        hash_search = params.get('hash', [''])[0]
        min_size = params.get('min_size', [''])[0]
        uid_filter = params.get('uid', [''])[0]
        gid_filter = params.get('gid', [''])[0]
        
        # Debug output
        print(f"🔍 API Request Parameters:")
        print(f"   search='{search}', page={page}, file_types='{file_types}'")
        print(f"   sort='{sort}', sort_dir='{sort_dir}'")
        print(f"   bodyfile='{bodyfile}', regex={regex}")
        print(f"   hash='{hash_search}', min_size='{min_size}'")
        print(f"   uid='{uid_filter}', gid='{gid_filter}', dir_filter='{dir_filter}'")
        
        # Calculate pagination
        offset = (page - 1) * size
        
        # Build SQL query
        conn = sqlite3.connect(self.db_path)
        
        # Fixed regex function with error handling
        def regexp(expr, item):
            if item is None:
                return False
            try:
                return re.search(expr, item) is not None
            except re.error:
                return False
        
        conn.create_function("REGEXP", 2, regexp)
        cursor = conn.cursor()
        
        # Build WHERE clause
        where_clauses = []
        query_params = []
        
        # Only add search condition if search is not empty
        if search and search.strip():
            if regex:
                where_clauses.append("name REGEXP ?")
                query_params.append(search)
            else:
                where_clauses.append("name LIKE ?")
                query_params.append(f'%{search}%')
        
        if hash_search and hash_search.strip():
            where_clauses.append("md5 LIKE ?")
            query_params.append(f'%{hash_search}%')
        
        if min_size and min_size.isdigit():
            where_clauses.append("size >= ?")
            query_params.append(int(min_size))
        
        if uid_filter and uid_filter.strip():
            where_clauses.append("uid = ?")
            query_params.append(uid_filter)
        
        if gid_filter and gid_filter.strip():
            where_clauses.append("gid = ?")
            query_params.append(gid_filter)
        
        # FIX: Use the corrected dir_filter
        if dir_filter and dir_filter.strip():
            where_clauses.append("name LIKE ?")
            query_params.append(dir_filter)
        
        if file_types and file_types != 'all' and file_types.strip():
            file_type_list = file_types.split(',')
            placeholders = ','.join(['?'] * len(file_type_list))
            where_clauses.append(f"file_type IN ({placeholders})")
            query_params.extend(file_type_list)
        
        if flags and flags != 'all' and flags.strip():
            flag_list = flags.split(',')
            flag_conditions = []
            for flag in flag_list:
                flag_conditions.append("noteworthy LIKE ?")
                query_params.append(f'%{flag}%')
            where_clauses.append(f"({' OR '.join(flag_conditions)})")
        
        if bodyfile and bodyfile != 'all' and bodyfile.strip():
            where_clauses.append("bodyfile_source = ?")
            query_params.append(bodyfile)
            
        # Date range filters
        if mtime_start and mtime_start.strip():
            where_clauses.append("mtime_epoch >= ?")
            query_params.append(int(datetime.strptime(mtime_start, '%Y-%m-%d').timestamp()))
        if mtime_end and mtime_end.strip():
            where_clauses.append("mtime_epoch <= ?")
            query_params.append(int(datetime.strptime(mtime_end, '%Y-%m-%d').timestamp()) + 86399)
            
        if atime_start and atime_start.strip():
            where_clauses.append("atime_epoch >= ?")
            query_params.append(int(datetime.strptime(atime_start, '%Y-%m-%d').timestamp()))
        if atime_end and atime_end.strip():
            where_clauses.append("atime_epoch <= ?")
            query_params.append(int(datetime.strptime(atime_end, '%Y-%m-%d').timestamp()) + 86399)
        
        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        # Get total count
        count_query = f"SELECT COUNT(*) FROM files {where_sql}"
        print(f"📊 Count query: {count_query}")
        print(f"📊 Query params: {query_params}")
        
        cursor.execute(count_query, query_params)
        total = cursor.fetchone()[0]
        print(f"📊 Total records found: {total}")
        
        # Build ORDER BY - use epoch timestamps for date columns
        if sort == 'mtime_epoch':
            order_column = 'mtime_epoch'
        elif sort == 'atime_epoch':
            order_column = 'atime_epoch'
        elif sort == 'crtime_epoch':
            order_column = 'crtime_epoch'
        else:
            order_column = sort
            
        order_sql = f"ORDER BY {order_column} {sort_dir.upper()}"
        
        # Get paginated data
        data_query = f"""
            SELECT name, size, atime, mtime, crtime, noteworthy, file_type, bodyfile_source 
            FROM files 
            {where_sql}
            {order_sql}
            LIMIT {size} OFFSET {offset}
        """
        
        print(f"📊 Data query: {data_query}")
        
        cursor.execute(data_query, query_params)
        
        files = []
        for row in cursor.fetchall():
            files.append({
                'name': row[0],
                'size': row[1],
                'atime': row[2],
                'mtime': row[3],
                'crtime': row[4],
                'noteworthy': row[5],
                'file_type': row[6],
                'bodyfile_source': row[7]
            })
        
        conn.close()
        
        print(f"📊 Returning {len(files)} files")
        
        # Prepare response
        response = {
            'files': files,
            'page': page,
            'size': size,
            'total': total,
            'start': offset + 1,
            'end': min(offset + size, total)
        }
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def handle_export_api(self):
        import urllib.parse
        from urllib.parse import parse_qs
        
        query = urllib.parse.urlparse(self.path).query
        params = parse_qs(query)
        format = params.get('format', ['csv'])[0]
        search = params.get('search', [''])[0]
        file_types = params.get('file_types', [''])[0]
        flags = params.get('flags', [''])[0]
        bodyfile = params.get('bodyfile', ['all'])[0]
        mtime_start = params.get('mtime_start', [''])[0]
        mtime_end = params.get('mtime_end', [''])[0]
        atime_start = params.get('atime_start', [''])[0]
        atime_end = params.get('atime_end', [''])[0]
        regex = int(params.get('regex', [0])[0])
        hash_search = params.get('hash', [''])[0]
        min_size = params.get('min_size', [''])[0]
        uid_filter = params.get('uid', [''])[0]
        gid_filter = params.get('gid', [''])[0]
        dir_filter = params.get('dir', [''])[0]
        
        conn = sqlite3.connect(self.db_path)
        
        # Fixed regex function with error handling
        def regexp(expr, item):
            if item is None:
                return False
            try:
                return re.search(expr, item) is not None
            except re.error:
                return False
        
        conn.create_function("REGEXP", 2, regexp)
        cursor = conn.cursor()
        
        # Build WHERE clause (same as data_api)
        where_clauses = []
        query_params = []
        
        if search:
            if regex:
                where_clauses.append("name REGEXP ?")
                query_params.append(search)
            else:
                where_clauses.append("name LIKE ?")
                query_params.append(f'%{search}%')
        
        if hash_search:
            where_clauses.append("md5 LIKE ?")
            query_params.append(f'%{hash_search}%')
        
        if min_size and min_size.isdigit():
            where_clauses.append("size >= ?")
            query_params.append(int(min_size))
        
        if uid_filter:
            where_clauses.append("uid = ?")
            query_params.append(uid_filter)
        
        if gid_filter:
            where_clauses.append("gid = ?")
            query_params.append(gid_filter)
        
        if dir_filter:
            where_clauses.append("name LIKE ?")
            query_params.append(dir_filter)
        
        if file_types and file_types != 'all':
            file_type_list = file_types.split(',')
            placeholders = ','.join(['?'] * len(file_type_list))
            where_clauses.append(f"file_type IN ({placeholders})")
            query_params.extend(file_type_list)
        
        if flags and flags != 'all':
            flag_list = flags.split(',')
            flag_conditions = []
            for flag in flag_list:
                flag_conditions.append("noteworthy LIKE ?")
                query_params.append(f'%{flag}%')
            where_clauses.append(f"({' OR '.join(flag_conditions)})")
        
        if bodyfile and bodyfile != 'all':
            where_clauses.append("bodyfile_source = ?")
            query_params.append(bodyfile)
            
        if mtime_start:
            where_clauses.append("mtime_epoch >= ?")
            query_params.append(int(datetime.strptime(mtime_start, '%Y-%m-%d').timestamp()))
        if mtime_end:
            where_clauses.append("mtime_epoch <= ?")
            query_params.append(int(datetime.strptime(mtime_end, '%Y-%m-%d').timestamp()) + 86399)
            
        if atime_start:
            where_clauses.append("atime_epoch >= ?")
            query_params.append(int(datetime.strptime(atime_start, '%Y-%m-%d').timestamp()))
        if atime_end:
            where_clauses.append("atime_epoch <= ?")
            query_params.append(int(datetime.strptime(atime_end, '%Y-%m-%d').timestamp()) + 86399)
        
        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        cursor.execute(f"SELECT * FROM files {where_sql} LIMIT 10000", query_params)
        rows = cursor.fetchall()
        
        conn.close()
        
        if format == 'json':
            files = []
            for row in rows:
                files.append({
                    'md5': row[1],
                    'name': row[2],
                    'inode': row[3],
                    'mode': row[4],
                    'uid': row[5],
                    'gid': row[6],
                    'size': row[7],
                    'atime': row[8],
                    'mtime': row[9],
                    'ctime': row[10],
                    'crtime': row[11],
                    'noteworthy': row[12],
                    'file_type': row[13],
                    'bodyfile_source': row[18]
                })
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Content-Disposition', 'attachment; filename="forensic_export.json"')
            self.end_headers()
            self.wfile.write(json.dumps(files).encode())
        else:  # CSV
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Name', 'Size', 'Accessed', 'Modified', 'Created', 'File Type', 'Bodyfile', 'Flags'])
            
            for row in rows:
                writer.writerow([row[2], row[7], row[8], row[9], row[11], row[13], row[18], row[12]])
            
            self.send_response(200)
            self.send_header('Content-type', 'text/csv')
            self.send_header('Content-Disposition', 'attachment; filename="forensic_export.csv"')
            self.end_headers()
            self.wfile.write(output.getvalue().encode())
    
    def handle_add_bodyfile(self):
        """Handle adding new bodyfile while server is running"""
        try:
            flag_file = os.path.join(os.path.dirname(self.db_path), "ADD_BODYFILE.flag")
            with open(flag_file, "w") as f:
                f.write("1")
            
            response = {"success": True, "message": "File dialog should open shortly"}
        except Exception as e:
            response = {"success": False, "error": str(e)}
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

def start_server(db_path, port=8000):
    """Start the local web server with bodyfile addition support"""
    handler = lambda *args: ForensicRequestHandler(*args, db_path=db_path)
    
    try:
        server = HTTPServer(('localhost', port), handler)
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"⚠️  Port {port} is in use, looking for next available port...")
            port = get_available_port(port + 1)
            server = HTTPServer(('localhost', port), handler)
            print(f"✅ Using port {port} instead")
        else:
            raise
    
    print(f"🚀 Starting local server on http://localhost:{port}")
    print("💡 The HTML report will load data on-demand for fast performance")
    
    # Check for add bodyfile flag
    flag_file = os.path.join(os.path.dirname(db_path), "ADD_BODYFILE.flag")
    
    def check_for_new_bodyfile():
        while True:
            time.sleep(2)
            if os.path.exists(flag_file):
                try:
                    os.remove(flag_file)
                    print("\n📁 Add Bodyfile request detected...")
                    root = tk.Tk()
                    root.withdraw()
                    
                    bodyfile_paths = filedialog.askopenfilenames(
                        title="Select Additional Bodyfile(s)",
                        filetypes=[("Bodyfile", "*.txt *.body *.log"), ("All files", "*.*")]
                    )
                    
                    if bodyfile_paths:
                        for bodyfile_path in bodyfile_paths:
                            print(f"→ Adding bodyfile: {bodyfile_path}")
                            count = add_bodyfile_to_database(bodyfile_path, db_path)
                            print(f"✅ Added {count:,} records from {os.path.basename(bodyfile_path)}")
                        
                        # Update the HTML to reflect new data
                        try:
                            csv_path = db_path.replace('.db', '.csv')
                            generate_lightweight_html(db_path, csv_path, port)
                            print("✅ HTML report updated with new data")
                        except Exception as e:
                            print(f"⚠️  Could not update HTML: {e}")
                    else:
                        print("❌ No bodyfile selected")
                        
                    root.destroy()
                except Exception as e:
                    print(f"❌ Error adding bodyfile: {e}")
    
    # Start the flag checker in background
    flag_thread = threading.Thread(target=check_for_new_bodyfile, daemon=True)
    flag_thread.start()
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")

# -------------------------------------------------------------------
# Initial Setup Dialog
# -------------------------------------------------------------------

def show_initial_dialog():
    """Show initial dialog to open existing or create new database"""
    root = tk.Tk()
    root.title("Forensic Explorer - Setup")
    root.geometry("400x200")
    root.resizable(False, False)
    
    result = {"action": None, "db_path": None, "html_path": None}
    
    def create_new():
        result["action"] = "new"
        root.quit()
        root.destroy()
    
    def open_existing():
        db_file = filedialog.askopenfilename(
            title="Select Existing Database",
            filetypes=[("Database files", "*.db"), ("All files", "*.*")]
        )
        if db_file:
            result["action"] = "open"
            result["db_path"] = db_file
            # Look for corresponding HTML file
            html_file = db_file.replace('.db', '_report.html')
            if os.path.exists(html_file):
                result["html_path"] = html_file
            root.quit()
            root.destroy()
    
    # Center the window
    root.eval('tk::PlaceWindow . center')
    
    tk.Label(root, text="Forensic Explorer", font=("Arial", 16, "bold")).pack(pady=20)
    tk.Label(root, text="Start with new analysis or open existing database?").pack(pady=10)
    
    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=20)
    
    tk.Button(btn_frame, text="Create New Analysis", command=create_new, width=20, height=2).pack(side=tk.LEFT, padx=10)
    tk.Button(btn_frame, text="Open Existing Database", command=open_existing, width=20, height=2).pack(side=tk.LEFT, padx=10)
    
    root.mainloop()
    return result

# -------------------------------------------------------------------
# Main Conversion Function
# -------------------------------------------------------------------

def convert_bodyfile_and_generate_report(bodyfile_paths, output_csv_path, date_filter=None):
    rows = []
    processed = 0

    for bodyfile_path in bodyfile_paths:
        bodyfile_name = os.path.basename(bodyfile_path)
        with open(bodyfile_path, "r", encoding="utf-8", errors="ignore") as infile:
            reader = csv.reader(infile, delimiter="|")
            for row in reader:
                processed += 1
                if len(row) not in (10, 11):
                    continue

                if len(row) == 11:
                    md5, name, inode, mode, uid, gid, size, atime, mtime, ctime, crtime = row
                else:
                    md5, name, inode, mode, uid, gid, size, atime, mtime, ctime = row
                    crtime = ""

                noteworthy, file_type = assess_noteworthy(name, mode, atime, mtime, ctime, crtime)

                row_dict = {
                    "MD5": md5,
                    "Name": name,
                    "Inode": inode,
                    "Mode": mode,
                    "UID": uid,
                    "GID": gid,
                    "Size": size,
                    "Atime": convert_epoch_to_str(atime),
                    "Mtime": convert_epoch_to_str(mtime),
                    "Ctime": convert_epoch_to_str(ctime),
                    "Crtime": convert_epoch_to_str(crtime),
                    "Noteworthy": noteworthy,
                    "FileType": file_type,
                    "_atime_epoch": int(atime) if atime and atime.isdigit() else 0,
                    "_mtime_epoch": int(mtime) if mtime and mtime.isdigit() else 0,
                    "_ctime_epoch": int(ctime) if ctime and ctime.isdigit() else 0,
                    "_crtime_epoch": int(crtime) if crtime and crtime.isdigit() else 0,
                }

                rows.append(row_dict)

    # Apply date range filtering if requested
    if date_filter and date_filter["apply_filter"]:
        rows = filter_rows_by_date_range(rows, date_filter)

    # Ensure output files have proper extensions
    if not output_csv_path.endswith('.csv'):
        output_csv_path += '.csv'
    
    # Write CSV
    csv_headers = ["MD5","Name","Inode","Mode","UID","GID","Size",
                   "Atime (Accessed)","Mtime (Modified)","Ctime (Changed)","Crtime (Created)",
                   "Noteworthy","FileType"]
    with open(output_csv_path, "w", newline="", encoding="utf-8") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(csv_headers)
        for r in rows:
            writer.writerow([
                r["MD5"], r["Name"], r["Inode"], r["Mode"], r["UID"], r["GID"], r["Size"],
                r["Atime"], r["Mtime"], r["Ctime"], r["Crtime"], r["Noteworthy"], r["FileType"]
            ])

    print(f"\n✅ CSV written: {output_csv_path}")
    print(f"→ Processed records: {len(rows):,}")

    # Create database for fast access - ensure .db extension
    db_path = output_csv_path.replace('.csv', '.db')
    create_database(rows, db_path, bodyfile_name)

    # Verify the database contents
    print("🔍 Verifying database contents...")
    if not verify_database_contents(db_path):
        print("❌ Database verification failed - no data found")
        return

    # Check database schema
    check_database_schema(db_path)
    
    # Test database queries
    test_database_query(db_path)

    # Get available port (starting from 8000)
    port = get_available_port(8000)
    
    # Generate lightweight HTML and start server
    html_path = generate_lightweight_html(db_path, output_csv_path, port)
    
    print(f"✅ Lightweight HTML report: {html_path}")
    print(f"📊 HTML file size: {os.path.getsize(html_path) / 1024:.1f} KB")
    print(f"🌐 Opening browser on port {port}...")
    
    # Start server in background thread
    server_thread = threading.Thread(target=start_server, args=(db_path, port), daemon=True)
    server_thread.start()
    
    # Wait a moment for server to start, then open browser
    time.sleep(2)
    webbrowser.open(f'http://localhost:{port}/{os.path.basename(html_path)}')
    
    print("\n💡 The server is running in the background. Press Ctrl+C to stop when done.")
    print("💡 You can add more bodyfiles using the 'Add Bodyfile' button in the web interface.")
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")

# -------------------------------------------------------------------
# Main Function
# -------------------------------------------------------------------

def main():
    print("==========================================")
    print("  Bodyfile → CSV + Enhanced HTML Report")
    print("==========================================")
    print("Multi-bodyfile support with toggle filters")
    print("Fast, responsive interface using local web server\n")

    # Show initial dialog
    choice = show_initial_dialog()
    
    if choice["action"] == "open" and choice["db_path"]:
        # Open existing database
        db_path = choice["db_path"]
        html_path = choice["html_path"]
        
        print(f"📂 Opening existing database: {db_path}")
        
        # Verify the database
        if not verify_database_contents(db_path):
            print("❌ Database is empty or corrupted")
            return
            
        if html_path and os.path.exists(html_path):
            port = get_available_port(8000)
            # Start server
            server_thread = threading.Thread(target=start_server, args=(db_path, port), daemon=True)
            server_thread.start()
            
            time.sleep(2)
            webbrowser.open(f'http://localhost:{port}/{os.path.basename(html_path)}')
            
            print("💡 Existing database loaded. You can add more bodyfiles using the web interface.")
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
        else:
            print("❌ Corresponding HTML file not found. Please create a new analysis.")
            return
            
    elif choice["action"] == "new":
        # Create new analysis
        root = tk.Tk()
        root.withdraw()

        print("[1] Select input bodyfile(s)...")
        bodyfile_paths = filedialog.askopenfilenames(
            title="Select Bodyfile (v2/v3)",
            filetypes=[("Bodyfile", "*.txt *.body *.log"), ("All files", "*.*")]
        )
        if not bodyfile_paths:
            print("No input file selected. Exiting.")
            return
        print(f"→ Selected: {len(bodyfile_paths)} bodyfile(s)")

        print("[2] Choose output CSV location...")
        output_csv = filedialog.asksaveasfilename(
            title="Save CSV As",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not output_csv:
            print("No output file selected. Exiting.")
            return
        print(f"→ CSV will be saved to: {output_csv}")

        print("\n[3] Date range filtering...")
        date_filter = ask_date_range_filter()

        # Show summary of date filtering choice
        if date_filter["apply_filter"]:
            date_type_names = {
                "mtime": "Modified Time",
                "atime": "Access Time", 
                "ctime": "Change Time",
                "crtime": "Creation Time"
            }
            date_type = date_type_names.get(date_filter["date_type"], date_filter["date_type"])
            
            start_str = date_filter["start_date"].strftime('%Y-%m-%d') if date_filter["start_date"] else "Beginning"
            end_str = date_filter["end_date"].strftime('%Y-%m-%d') if date_filter["end_date"] else "Now"
            
            print(f"→ Date filter: {date_type} from {start_str} to {end_str}")
        else:
            print("→ No date filtering applied")

        print("\n[4] Converting...")
        try:
            convert_bodyfile_and_generate_report(bodyfile_paths, output_csv, date_filter)
        except Exception as exc:
            print(f"Error during conversion: {exc}")

if __name__ == "__main__":
    main()

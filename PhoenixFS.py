#!/usr/bin/env python3
"""
PhoenixFS - Advanced File Recovery System with GUI
A comprehensive Python program for recovering deleted files through file carving techniques.

This program can be run via the command line or through its graphical user interface.
It scans raw disk space looking for file signatures (magic numbers) to reconstruct
deleted files that are no longer indexed by the file system.

Author: LMLK-seal
License: MIT
Version: 1.3.1
"""

# --- Standard Library Imports ---
import os
import sys
import time
import struct
import hashlib
import argparse
import threading
import queue
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional, BinaryIO
import json
import logging

# --- Third-Party Imports ---
try:
    import customtkinter as ctk
    from tkinter import filedialog, messagebox
    import psutil # Essential for folder scanning logic
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    psutil = None

# --- Initial Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

#==============================================================================
# CORE FILE CARVING LOGIC
#==============================================================================

@dataclass
class FileSignature:
    name: str
    extension: str
    header: bytes
    footer: Optional[bytes] = None
    max_size: int = 100 * 1024 * 1024
    description: str = ""

@dataclass
class RecoveredFile:
    filename: str
    file_type: str
    start_offset: int
    end_offset: int
    size: int
    signature: FileSignature
    data_hash: str
    recovery_confidence: float

class FileSignatureDatabase:
    def __init__(self):
        self.signatures = self._initialize_signatures()

    def _initialize_signatures(self) -> List[FileSignature]:
        return [
            FileSignature("JPEG", "jpg", b'\xFF\xD8\xFF', b'\xFF\xD9', max_size=25*1024*1024, description="JPEG image file"),
            FileSignature("PNG", "png", b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', b'\x49\x45\x4E\x44\xAE\x42\x60\x82', max_size=25*1024*1024, description="PNG image file"),
            FileSignature("GIF", "gif", b'\x47\x49\x46\x38', b'\x00\x3B', max_size=15*1024*1024, description="GIF image file"),
            FileSignature("BMP", "bmp", b'\x42\x4D', max_size=50*1024*1024, description="Bitmap image file"),
            FileSignature("PDF", "pdf", b'\x25\x50\x44\x46', b'\x25\x25\x45\x4F\x46', max_size=200*1024*1024, description="PDF document"),
            FileSignature("DOCX", "docx", b'\x50\x4B\x03\x04', b'\x50\x4B\x05\x06', max_size=50*1024*1024, description="Office Open XML (DOCX, XLSX, PPTX)"),
            FileSignature("ZIP", "zip", b'\x50\x4B\x03\x04', b'\x50\x4B\x05\x06', max_size=4*1024*1024*1024, description="ZIP archive"),
            FileSignature("RAR", "rar", b'\x52\x61\x72\x21\x1A\x07\x00', max_size=4*1024*1024*1024, description="RAR archive"),
            FileSignature("MP3", "mp3", b'\x49\x44\x33', max_size=30*1024*1024, description="MP3 audio file (with ID3v2 tag)"),
            FileSignature("WAV", "wav", b'\x52\x49\x46\x46', max_size=1024*1024*1024, description="WAV audio file"),
            FileSignature("MP4", "mp4", b'\x00\x00\x00\x18\x66\x74\x79\x70\x6d\x70\x34\x32', max_size=4*1024*1024*1024, description="MP4 video file"),
            FileSignature("MOV", "mov", b'\x00\x00\x00\x14\x66\x74\x79\x70\x71\x74', max_size=4*1024*1024*1024, description="QuickTime MOV file"),
            FileSignature("AVI", "avi", b'\x52\x49\x46\x46', max_size=4*1024*1024*1024, description="AVI video file"),
            FileSignature("EXE", "exe", b'\x4D\x5A', max_size=200*1024*1024, description="Windows executable"),
            FileSignature("SQLite", "sqlite", b'\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00', max_size=1024*1024*1024, description="SQLite database"),
        ]

    def get_signature_by_header(self, header_bytes: bytes) -> Optional[FileSignature]:
        for signature in self.signatures:
            if header_bytes.startswith(signature.header):
                return signature
        return None

class DiskScanner:
    """Core scanning engine, can scan a single data stream (file or raw device)."""
    def __init__(self, chunk_size: int = 1 * 1024 * 1024,
                 progress_queue: Optional[queue.Queue] = None,
                 stop_event: Optional[threading.Event] = None):
        self.chunk_size = chunk_size
        self.signature_db = FileSignatureDatabase()
        self.progress_queue = progress_queue
        self.stop_event = stop_event
        self.scan_stats = { 'bytes_scanned': 0, 'files_found': 0, 'scan_start_time': None, 'scan_end_time': None, 'total_size': 0 }
        self.recovered_files = []

    def _log(self, level: str, message: str, source_file=""):
        if self.progress_queue:
            log_msg = f"[{source_file}] " if source_file else ""
            log_msg += message
            self.progress_queue.put({'type': 'log', 'level': level, 'message': log_msg})
        else:
            getattr(logger, level, logger.info)(message)

    def scan_device(self, device_path: str, output_dir: str, start_offset: int = 0,
                    max_scan_size: Optional[int] = None, source_filename_for_log="") -> List[RecoveredFile]:
        """Scans a single device or file."""
        self.recovered_files = []
        self._log('info', f"Starting scan...", source_file=source_filename_for_log or device_path)

        try:
            with open(device_path, 'rb') as device:
                return self._scan_stream(device, output_dir, start_offset, max_scan_size, source_filename_for_log or device_path)
        except PermissionError:
            self._log('error', f"Permission denied. Try running as Admin/root.", source_file=device_path)
            return []
        except FileNotFoundError:
            self._log('error', f"File not found.", source_file=device_path)
            return []
        except Exception as e:
            self._log('error', f"An error occurred: {e}", source_file=device_path)
            return []

    def _scan_stream(self, stream: BinaryIO, output_dir: str, start_offset: int, max_scan_size: Optional[int], source_log_name: str):
        stream.seek(start_offset)
        current_offset = start_offset
        os.makedirs(output_dir, exist_ok=True)
        
        while True:
            if self.stop_event and self.stop_event.is_set():
                self._log('warning', "Scan cancelled by user.")
                break
            
            if max_scan_size and (current_offset - start_offset) >= max_scan_size:
                self._log('info', "Reached maximum scan size limit.")
                break
                
            chunk = stream.read(self.chunk_size)
            if not chunk:
                break
                
            self.scan_stats['bytes_scanned'] += len(chunk)
            
            if self.progress_queue and not source_log_name: # Only show byte progress for single large files
                progress_data = {'type': 'progress', 'scanned': self.scan_stats['bytes_scanned'], 'total': self.scan_stats['total_size']}
                self.progress_queue.put(progress_data)
                
            found_signature_in_chunk = False
            for i in range(len(chunk)):
                if self.stop_event and self.stop_event.is_set(): break
                
                header_sample = chunk[i:i+16]
                signature = self.signature_db.get_signature_by_header(header_sample)
                
                if signature:
                    try:
                        file_start_offset = current_offset + i
                        self._log('info', f"Found potential {signature.name} signature at offset {file_start_offset:08x}", source_file=source_log_name)
                        recovered_file = self._carve_file(stream, file_start_offset, signature, output_dir)
                        if recovered_file:
                            self.recovered_files.append(recovered_file)
                            self.scan_stats['files_found'] += 1
                            self._log('success', f"Recovered {signature.name} file: {recovered_file.filename} ({recovered_file.size / 1024:.1f} KB)", source_file=source_log_name)
                            stream.seek(recovered_file.end_offset)
                            current_offset = recovered_file.end_offset
                            found_signature_in_chunk = True
                            break
                    except Exception as e:
                        self._log('warning', f"Failed to carve file at offset {file_start_offset}: {e}", source_file=source_log_name)
                        stream.seek(current_offset + len(chunk))
            
            if not found_signature_in_chunk:
                 current_offset += len(chunk)

        return self.recovered_files

    def _carve_file(self, stream: BinaryIO, start_offset: int, signature: FileSignature, output_dir: str) -> Optional[RecoveredFile]:
        current_pos = stream.tell()
        stream.seek(start_offset)
        
        try:
            end_offset = -1
            if signature.footer:
                max_read = signature.max_size
                search_data = stream.read(max_read)
                footer_pos = search_data.find(signature.footer)
                if footer_pos != -1:
                    end_offset = start_offset + footer_pos + len(signature.footer)
            
            if end_offset == -1:
                return None

            stream.seek(start_offset)
            file_size = end_offset - start_offset
            if file_size <= 0 or file_size > signature.max_size:
                return None
            
            file_data = stream.read(file_size)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            filename = f"recovered_{timestamp}_{start_offset:08x}.{signature.extension}"
            filepath = os.path.join(output_dir, filename)
            
            with open(filepath, 'wb') as output_file:
                output_file.write(file_data)
                
            confidence = 1.0 if signature.footer else 0.6
            
            return RecoveredFile(
                filename=filename, file_type=signature.name, start_offset=start_offset,
                end_offset=end_offset, size=file_size, signature=signature,
                data_hash=hashlib.sha256(file_data).hexdigest(), recovery_confidence=confidence
            )
        finally:
            stream.seek(current_pos)

#==============================================================================
# PHOENIXFS GUI
#==============================================================================

if GUI_AVAILABLE:
    class PhoenixFS_GUI(ctk.CTk):
        def __init__(self):
            super().__init__()
            self.title(f"PhoenixFS v1.3.1")
            self.geometry("900x700")
            ctk.set_appearance_mode("Dark")
            ctk.set_default_color_theme("blue")
            self.source_path = ctk.StringVar()
            self.output_path = ctk.StringVar()
            self.is_scanning = False
            self.stop_event = None
            self.scan_thread = None
            self.log_queue = queue.Queue()
            self.current_scanner = None # Bugfix: To hold scanner instance for progress updates

            if not self.is_admin():
                self.after(100, lambda: messagebox.showwarning(
                    "Admin Rights Recommended",
                    "For best results, please restart PhoenixFS with Administrator/root privileges. "
                    "Without them, you can only scan disk image files, not raw drives."
                ))
            self.create_widgets()
            self.process_log_queue()

        def is_admin(self):
            try:
                return os.getuid() == 0
            except AttributeError:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0

        def create_widgets(self):
            self.grid_columnconfigure(0, weight=1)
            self.grid_rowconfigure(2, weight=1)
            # IO Frame
            io_frame = ctk.CTkFrame(self)
            io_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
            io_frame.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(io_frame, text="Source (File, Drive, or Folder):").grid(row=0, column=0, padx=10, pady=5, sticky="w")
            ctk.CTkEntry(io_frame, textvariable=self.source_path).grid(row=0, column=1, padx=(0, 5), pady=5, sticky="ew")
            ctk.CTkButton(io_frame, text="Browse...", command=self.browse_source).grid(row=0, column=2, padx=5, pady=5)
            ctk.CTkLabel(io_frame, text="Output Folder:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
            ctk.CTkEntry(io_frame, textvariable=self.output_path).grid(row=1, column=1, padx=(0, 5), pady=5, sticky="ew")
            ctk.CTkButton(io_frame, text="Browse...", command=self.browse_output).grid(row=1, column=2, padx=5, pady=5)
            # Options Frame
            options_frame = ctk.CTkFrame(self)
            options_frame.grid(row=1, column=0, padx=10, pady=0, sticky="ew")
            options_frame.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(options_frame, text="File Types to Recover (leave all unchecked to scan for all)").pack(pady=(5,0))
            self.file_types_frame = ctk.CTkScrollableFrame(options_frame, height=120)
            self.file_types_frame.pack(fill="x", expand=True, padx=5, pady=5)
            self.file_type_vars = {}
            db = FileSignatureDatabase()
            sorted_sigs = sorted(db.signatures, key=lambda s: s.extension)
            for i, sig in enumerate(sorted_sigs):
                var = ctk.StringVar(value="")
                cb = ctk.CTkCheckBox(self.file_types_frame, text=f"{sig.extension.upper()} ({sig.description})", variable=var, onvalue=sig.extension, offvalue="")
                cb.grid(row=i // 3, column=i % 3, padx=10, pady=2, sticky="w")
                self.file_type_vars[sig.extension] = var
            # Log & Progress Frame
            log_frame = ctk.CTkFrame(self)
            log_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
            log_frame.grid_columnconfigure(0, weight=1)
            log_frame.grid_rowconfigure(0, weight=1)
            self.log_textbox = ctk.CTkTextbox(log_frame, state="disabled", wrap="word", font=("Courier New", 12))
            self.log_textbox.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
            self.log_textbox.tag_config("info", foreground="cyan")
            self.log_textbox.tag_config("error", foreground="red")
            self.log_textbox.tag_config("warning", foreground="orange")
            self.log_textbox.tag_config("success", foreground="lightgreen")
            self.progress_bar = ctk.CTkProgressBar(log_frame)
            self.progress_bar.set(0)
            self.progress_bar.grid(row=1, column=0, padx=5, pady=(0, 5), sticky="ew")
            self.status_label = ctk.CTkLabel(log_frame, text="Ready. Select source and output paths.", anchor="w")
            self.status_label.grid(row=2, column=0, padx=5, pady=(0, 5), sticky="ew")
            # Controls Frame
            control_frame = ctk.CTkFrame(self)
            control_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
            self.start_button = ctk.CTkButton(control_frame, text="Start Scan", command=self.start_scan)
            self.start_button.pack(side="left", padx=10, pady=5)
            self.stop_button = ctk.CTkButton(control_frame, text="Stop Scan", command=self.stop_scan, state="disabled", fg_color="red", hover_color="#C00000")
            self.stop_button.pack(side="left", padx=10, pady=5)

        def browse_source(self):
            if messagebox.askyesno("Select Source Type", "Are you selecting a single file (like a disk image)?\n\n"
                                   "Choose 'Yes' for a file, 'No' for a folder.", icon='question'):
                path = filedialog.askopenfilename(title="Select Disk Image File")
                if path:
                    self.source_path.set(path)
            else:
                path = filedialog.askdirectory(title="Select Folder")
                if path:
                    self.source_path.set(path)

        def browse_output(self):
            path = filedialog.askdirectory(title="Select Output Folder")
            if path:
                self.output_path.set(path)

        def get_drive_from_path(self, path):
            if sys.platform == "win32":
                drive = os.path.splitdrive(os.path.abspath(path))[0]
                return f"\\\\.\\{drive.strip(':')}:"
            else:
                path = os.path.abspath(path)
                best_match = ('', '')
                for part in psutil.disk_partitions():
                    if path.startswith(part.mountpoint) and len(part.mountpoint) > len(best_match[1]):
                        best_match = (part.device, part.mountpoint)
                return best_match[0] if best_match[0] else None

        def start_scan(self):
            source = self.source_path.get()
            output = self.output_path.get()

            if not source or not output:
                messagebox.showerror("Input Error", "Source and Output paths cannot be empty.")
                return

            if os.path.isdir(source):
                drive = self.get_drive_from_path(source)
                if not drive:
                     messagebox.showerror("Error", f"Could not determine the drive for folder:\n{source}")
                     return

                dialog = ctk.CTkToplevel(self)
                dialog.title("Folder Scan Option")
                dialog.geometry("550x220")
                dialog.transient(self)
                dialog.grab_set()

                label_text = (f"You have selected a folder.\n\n"
                              f"How would you like to scan?\n\n"
                              f"Option 1: Scan entire drive '{drive}'\n(This finds DELETED files that were once in the folder).\n\n"
                              f"Option 2: Scan existing files within '{os.path.basename(source)}'\n(This finds EMBEDDED data inside existing files).")
                ctk.CTkLabel(dialog, text=label_text, justify="left", wraplength=500).pack(pady=10, padx=20)
                
                result = None
                def set_result(choice):
                    nonlocal result
                    result = choice
                    dialog.destroy()

                button_frame = ctk.CTkFrame(dialog, fg_color="transparent")
                button_frame.pack(pady=10)
                ctk.CTkButton(button_frame, text="1. Scan Drive (for Deleted Files)", command=lambda: set_result("drive")).pack(side="left", padx=10)
                ctk.CTkButton(button_frame, text="2. Scan Folder (for Embedded Files)", command=lambda: set_result("folder")).pack(side="left", padx=10)
                
                self.wait_window(dialog)

                if result == "drive":
                    source = drive
                    self.source_path.set(source)
                    self.log_message("info", f"User chose to scan entire drive: {source}")
                    self.run_disk_scan_thread(source, output)
                elif result == "folder":
                    self.log_message("info", f"User chose to scan contents of folder: {source}")
                    self.run_folder_scan_thread(source, output)
                else:
                    return
            else:
                if not (sys.platform == "win32" and source.startswith("\\\\.\\")) and not os.path.exists(source):
                     messagebox.showerror("Input Error", f"Source file does not exist:\n{source}")
                     return
                self.run_disk_scan_thread(source, output)

        def prepare_for_scan(self):
            self.is_scanning = True
            self.toggle_controls()
            self.stop_event = threading.Event()
            self.log_textbox.configure(state="normal"); self.log_textbox.delete("1.0", "end"); self.log_textbox.configure(state="disabled")
            self.progress_bar.set(0)

        def run_disk_scan_thread(self, source, output):
            self.prepare_for_scan()
            selected_types = [var.get() for var in self.file_type_vars.values() if var.get()]
            self.current_scanner = DiskScanner(progress_queue=self.log_queue, stop_event=self.stop_event)
            self.scan_thread = threading.Thread(
                target=self.scan_worker,
                args=(self.current_scanner, source, output, selected_types),
                daemon=True)
            self.scan_thread.start()

        def scan_worker(self, scanner, source, output, types):
            if types:
                 scanner.signature_db.signatures = [s for s in scanner.signature_db.signatures if s.extension in types]
            try:
                total_size = os.path.getsize(source)
            except OSError:
                total_size = 0 
            scanner.scan_stats['total_size'] = total_size
            scanner.scan_device(source, output)
            self.log_queue.put({'type': 'finished'})

        def run_folder_scan_thread(self, source_folder, output):
            self.prepare_for_scan()
            selected_types = [var.get() for var in self.file_type_vars.values() if var.get()]
            self.current_scanner = DiskScanner(progress_queue=self.log_queue, stop_event=self.stop_event)
            self.scan_thread = threading.Thread(
                target=self.folder_scan_worker,
                args=(self.current_scanner, source_folder, output, selected_types),
                daemon=True)
            self.scan_thread.start()

        def folder_scan_worker(self, scanner, source_folder, output, types):
            if types:
                scanner.signature_db.signatures = [s for s in scanner.signature_db.signatures if s.extension in types]

            files_to_scan = [os.path.join(dp, f) for dp, dn, filenames in os.walk(source_folder) for f in filenames]
            total_files = len(files_to_scan)
            files_scanned = 0
            
            self.log_queue.put({'type':'log', 'level':'info', 'message':f"Found {total_files} files to scan in the folder."})

            for filepath in files_to_scan:
                if self.stop_event.is_set(): break
                
                files_scanned += 1
                filename = os.path.basename(filepath)
                
                self.log_queue.put({'type': 'progress', 'scanned': files_scanned, 'total': total_files, 'current_file': filename})
                scanner.scan_device(filepath, output, source_filename_for_log=filename)
            
            self.log_queue.put({'type': 'finished'})
        
        def stop_scan(self):
            if self.is_scanning and self.stop_event:
                self.log_message("info", "--- Stop signal sent. Finishing current operation... ---")
                self.stop_event.set()
                self.stop_button.configure(state="disabled", text="Stopping...")
        
        def toggle_controls(self):
            state = "disabled" if self.is_scanning else "normal"
            
            self.start_button.configure(state=state)
            self.stop_button.configure(state="normal" if self.is_scanning else "disabled")

            for frame in self.winfo_children():
                if isinstance(frame, ctk.CTkFrame):
                    for widget in frame.winfo_children():
                        if isinstance(widget, (ctk.CTkButton, ctk.CTkEntry, ctk.CTkOptionMenu, ctk.CTkCheckBox, ctk.CTkScrollableFrame)):
                            try:
                                widget.configure(state=state)
                            except Exception:
                                pass
            
            for checkbox in self.file_types_frame.winfo_children():
                if isinstance(checkbox, ctk.CTkCheckBox):
                    checkbox.configure(state=state)

            if self.is_scanning:
                self.stop_button.configure(state="normal")

        def process_log_queue(self):
            try:
                while True:
                    msg = self.log_queue.get_nowait()
                    if msg['type'] == 'log':
                        self.log_message(msg['level'], msg['message'])
                    elif msg['type'] == 'progress':
                        if msg.get('total', 0) > 0:
                            progress_val = msg['scanned'] / msg['total']
                            self.progress_bar.set(progress_val)
                        
                        if msg.get('current_file'):
                            self.status_label.configure(text=f"Scanning file {msg['scanned']}/{msg['total']}: {msg.get('current_file')}")
                        else:
                            if self.current_scanner:
                                scanned_mb = self.current_scanner.scan_stats['bytes_scanned'] / (1024*1024)
                                files_found = self.current_scanner.scan_stats['files_found']
                                self.status_label.configure(text=f"Scanned: {scanned_mb:.1f} MB | Files Found: {files_found}")
                    elif msg['type'] == 'finished':
                        self.is_scanning = False
                        self.toggle_controls()
                        self.stop_button.configure(text="Stop Scan")
                        self.status_label.configure(text="Scan finished. Check log for details.")
                        self.current_scanner = None
                        messagebox.showinfo("Scan Complete", "The file recovery process has finished.")
            except queue.Empty:
                pass
            finally:
                self.after(100, self.process_log_queue)

        def log_message(self, level, message):
            self.log_textbox.configure(state="normal")
            self.log_textbox.insert("end", f"[{level.upper()}] {message}\n", level)
            self.log_textbox.see("end")
            self.log_textbox.configure(state="disabled")

def main():
    # CLI entry point can be expanded here if needed
    if len(sys.argv) > 1:
        print("This script is primarily a GUI application.")
        print("To use the command line, please develop the argparse section.")
        print("Launching GUI...")

    if GUI_AVAILABLE:
        app = PhoenixFS_GUI()
        app.mainloop()
    else:
        print("ERROR: GUI libraries not found (customtkinter, psutil). Please install them.", file=sys.stderr)
        print("pip install customtkinter psutil", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nOperation interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected top-level error occurred: {e}", exc_info=True)
        sys.exit(1)
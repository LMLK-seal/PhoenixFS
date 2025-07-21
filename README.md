# PhoenixFS ✨ Advanced File Recovery System

![Language](https://img.shields.io/badge/language-Python-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![GUI](https://img.shields.io/badge/interface-GUI-brightgreen.svg)
![Version](https://img.shields.io/badge/version-1.3.1-orange.svg)

## Description

PhoenixFS is a powerful and user-friendly file recovery system designed to salvage deleted or lost files from raw disk space. Utilizing advanced file carving techniques, it scans for known file signatures (magic numbers) to reconstruct files that are no longer indexed by the operating system's file system. Whether you've accidentally deleted important documents, photos, or videos, PhoenixFS aims to bring them back from the digital abyss. It features a modern, intuitive Graphical User Interface (GUI) built with CustomTkinter, making complex recovery tasks accessible to everyone.

![PhoenixFS](https://raw.githubusercontent.com/LMLK-seal/PhoenixFS/refs/heads/main/PhoenixFS-Img.jpg)

## ✨ Features

*   **Comprehensive File Carving:** Recovers files by identifying their unique header and footer signatures directly from disk sectors, bypassing file system metadata.
*   **Broad File Type Support:** Includes signatures for common file types such as:
    *   **Images:** JPEG, PNG, GIF, BMP
    *   **Documents:** PDF, DOCX (Office Open XML)
    *   **Archives:** ZIP, RAR
    *   **Audio/Video:** MP3, WAV, MP4, MOV, AVI
    *   **Executables:** EXE
    *   **Databases:** SQLite
*   **Intuitive GUI:** A clean and easy-to-use graphical interface allows users to select source drives/files, specify output directories, and monitor scan progress.
*   **Flexible Scanning Options:**
    *   Scan entire physical drives (requires administrator/root privileges for full access).
    *   Scan disk image files (e.g., `.bin`, `.img`).
    *   Scan specific folders to find embedded files within existing files.
*   **Selective Recovery:** Users can choose which specific file types to scan for, optimizing the recovery process.
*   **Real-time Progress & Logging:** Provides live updates on scanned data, files found, and detailed operation logs within the GUI.
*   **Portable & Self-Contained:** Designed for straightforward deployment and execution.

## 📚 Tech Stack

*   **Language:** Python 3
*   **GUI Framework:** [CustomTkinter](https://customtkinter.tomschimansky.com/) (modern, customizable Tkinter fork)
*   **System Utilities:** [psutil](https://psutil.readthedocs.io/en/latest/) (for cross-platform process and system utilities, used here for disk partition detection)
*   **Standard Libraries:** `os`, `sys`, `threading`, `queue`, `pathlib`, `hashlib`, `struct`, `dataclasses`, `logging`, `tkinter`

## 🚀 Installation

To get PhoenixFS up and running on your local machine, follow these steps:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/LMLK-seal/PhoenixFS.git 
    cd PhoenixFS
    ```

2.  **Install dependencies:**
    PhoenixFS requires `customtkinter` and `psutil`. It's recommended to use a virtual environment.
    ```bash
    python -m venv venv
    # On Windows:
    venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate

    pip install customtkinter psutil
    ```

## ▶️ Usage

PhoenixFS is primarily a GUI application.

1.  **Run the application:**
    ```bash
    python PhoenixFS.py
    ```

2.  **Using the GUI:**
    *   **Admin/Root Privileges (Recommended):** For best results and the ability to scan raw physical drives, it is highly recommended to run PhoenixFS with administrator (Windows) or root (macOS/Linux) privileges. The GUI will warn you if you are not running with sufficient permissions.
    *   **Select Source:** Click "Browse..." next to "Source" to choose:
        *   A **single disk image file** (e.g., `.img`, `.bin`).
        *   A **folder** (you will be prompted to either scan the *entire drive* the folder resides on for deleted files, or scan *existing files within the folder* for embedded data).
        *   A **physical drive** (e.g., `D:` on Windows, `/dev/sdb` on Linux - requires admin/root).
    *   **Select Output Folder:** Click "Browse..." next to "Output Folder" to choose where recovered files will be saved.
    *   **Choose File Types (Optional):** In the "File Types to Recover" section, check the boxes for specific file types you wish to recover. If no types are selected, the scanner will attempt to recover all supported file types.
    *   **Start Scan:** Click the "Start Scan" button to begin the recovery process.
    *   **Monitor Progress:** The log textbox will display details of the scan, and the progress bar/status label will show overall progress.
    *   **Stop Scan:** Click the "Stop Scan" button at any time to halt the operation.
    *   **Recovered Files:** Once the scan is complete (or stopped), check the specified output folder for any recovered files.

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## 📝 License

Distributed under the MIT License. See the project's source code for full license text.

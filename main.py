import os
import base64
import logging
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
import threading
import hashlib
import secrets
import shutil

# Cryptography imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("file_encryptor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DragDropListbox(tk.Listbox):
    """A Listbox with drag-and-drop functionality for reordering items"""
    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        self.bind('<Button-1>', self.select_item)
        self.bind('<B1-Motion>', self.on_motion)
        self.curIndex = None
        
    def select_item(self, event):
        self.curIndex = self.nearest(event.y)
        
    def on_motion(self, event):
        if self.curIndex is not None:
            i = self.nearest(event.y)
            if i != self.curIndex:
                item = self.get(self.curIndex)
                self.delete(self.curIndex)
                self.insert(i, item)
                self.curIndex = i

class SecureFileEncryptor(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("Secure File Encryptor")
        self.geometry("800x600")
        self.minsize(800, 600)
        
        # App variables
        self.theme_var = tk.StringVar(value="light")
        self.files = []
        self.output_dir = os.path.join(os.path.expanduser("~"), "SecureEncryptor")
        self.secure_delete_var = tk.BooleanVar(value=False)
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        # Setup UI
        self.setup_ui()
        self.apply_theme()
        
    def setup_ui(self):
        """Set up the user interface"""
        # Create main frames
        self.menu_frame = tk.Frame(self)
        self.menu_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        self.content_frame = tk.Frame(self)
        self.content_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.status_frame = tk.Frame(self)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
        
        # Menu options
        theme_btn = tk.Button(self.menu_frame, text="Toggle Dark Mode", command=self.toggle_theme)
        theme_btn.pack(side=tk.LEFT, padx=5)
        
        help_btn = tk.Button(self.menu_frame, text="Help", command=self.show_help)
        help_btn.pack(side=tk.RIGHT, padx=5)
        
        # File selection area
        file_frame = tk.LabelFrame(self.content_frame, text="Files to Process")
        file_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.file_listbox = DragDropListbox(file_frame, selectmode=tk.EXTENDED, height=10)
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        scrollbar = tk.Scrollbar(file_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.file_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.file_listbox.yview)
        
        # File buttons
        file_btn_frame = tk.Frame(file_frame)
        file_btn_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)
        
        add_btn = tk.Button(file_btn_frame, text="Add Files", command=self.add_files)
        add_btn.pack(fill=tk.X, pady=2)
        
        remove_btn = tk.Button(file_btn_frame, text="Remove Selected", command=self.remove_files)
        remove_btn.pack(fill=tk.X, pady=2)
        
        clear_btn = tk.Button(file_btn_frame, text="Clear All", command=self.clear_files)
        clear_btn.pack(fill=tk.X, pady=2)
        
        # Password frame
        password_frame = tk.LabelFrame(self.content_frame, text="Password")
        password_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(password_frame, text="Enter Password:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.password_entry = tk.Entry(password_frame, show="*", width=30)
        self.password_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        tk.Label(password_frame, text="Confirm Password:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.confirm_password_entry = tk.Entry(password_frame, show="*", width=30)
        self.confirm_password_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Options frame
        options_frame = tk.LabelFrame(self.content_frame, text="Options")
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.secure_delete_check = tk.Checkbutton(
            options_frame, 
            text="Securely delete original files after encryption", 
            variable=self.secure_delete_var
        )
        self.secure_delete_check.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        
        output_dir_btn = tk.Button(options_frame, text="Set Output Directory", command=self.set_output_dir)
        output_dir_btn.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.output_dir_label = tk.Label(options_frame, text=f"Output Directory: {self.output_dir}")
        self.output_dir_label.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Action buttons
        action_frame = tk.Frame(self.content_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.encrypt_btn = tk.Button(
            action_frame, 
            text="Encrypt Files", 
            command=lambda: self.process_files(encrypt=True),
            bg="#4CAF50", 
            fg="white", 
            height=2
        )
        self.encrypt_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.decrypt_btn = tk.Button(
            action_frame, 
            text="Decrypt Files", 
            command=lambda: self.process_files(encrypt=False),
            bg="#2196F3", 
            fg="white", 
            height=2
        )
        self.decrypt_btn.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=5)
        
        # Progress bar and status
        self.progress = ttk.Progressbar(self.status_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_label = tk.Label(self.status_frame, text="Ready")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Log window
        log_frame = tk.LabelFrame(self.content_frame, text="Activity Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = ScrolledText(log_frame, height=5)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.config(state=tk.DISABLED)
        

    def handle_drop(self, event):
        """Handle file drop events with simple method"""
        try:
            # Parse the data - format can vary by OS
            data = event.data
            if data:
                # Clean the data - remove curly braces, quotes, etc.
                data = data.replace("{", "").replace("}", "")
                file_paths = data.split()
                
                for path in file_paths:
                    if os.path.isfile(path) and path not in self.files:
                        self.files.append(path)
                        self.file_listbox.insert(tk.END, os.path.basename(path))
                        self.log(f"Added: {os.path.basename(path)}")
        except Exception as e:
            self.log(f"Error handling drop: {str(e)}", is_error=True)
        
    def add_files(self):
        """Open file dialog to add files"""
        file_paths = filedialog.askopenfilenames(title="Select Files to Process")
        for file_path in file_paths:
            if file_path not in self.files:
                self.files.append(file_path)
                self.file_listbox.insert(tk.END, os.path.basename(file_path))
                self.log(f"Added: {os.path.basename(file_path)}")
        
    def remove_files(self):
        """Remove selected files from the list"""
        selected_indices = self.file_listbox.curselection()
        if not selected_indices:
            return
            
        # Remove from end to beginning to avoid index shifting
        for i in sorted(selected_indices, reverse=True):
            del self.files[i]
            self.file_listbox.delete(i)
            
    def clear_files(self):
        """Clear all files from the list"""
        self.files.clear()
        self.file_listbox.delete(0, tk.END)
        
    def set_output_dir(self):
        """Set the output directory"""
        dir_path = filedialog.askdirectory(title="Select Output Directory")
        if dir_path:
            self.output_dir = dir_path
            self.output_dir_label.config(text=f"Output Directory: {self.output_dir}")
            self.log(f"Output directory set to: {self.output_dir}")
        
    def validate_password(self, encrypt_mode=True):
        """Validate the password entries"""
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Password cannot be empty")
            return False
            
        if encrypt_mode and password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return False
            
        return True
        
    def process_files(self, encrypt=True):
        """Process the files (encrypt or decrypt)"""
        if not self.files:
            messagebox.showinfo("Info", "No files selected")
            return
            
        if not self.validate_password(encrypt_mode=encrypt):
            return
            
        # Disable buttons during processing
        self.encrypt_btn.config(state=tk.DISABLED)
        self.decrypt_btn.config(state=tk.DISABLED)
        
        # Start processing in a separate thread
        thread = threading.Thread(
            target=self.process_files_thread,
            args=(encrypt,)
        )
        thread.daemon = True
        thread.start()
        
    def process_files_thread(self, encrypt=True):
        """Thread for processing files"""
        try:
            password = self.password_entry.get()
            action = "Encryption" if encrypt else "Decryption"
            
            self.update_status(f"{action} in progress...")
            self.progress['value'] = 0
            
            total_files = len(self.files)
            processed_files = 0
            
            for file_path in self.files:
                file_name = os.path.basename(file_path)
                
                try:
                    if encrypt:
                        output_path = os.path.join(
                            self.output_dir, 
                            f"{file_name}.encrypted"
                        )
                        self.encrypt_file(file_path, output_path, password)
                        self.log(f"Encrypted: {file_name} -> {os.path.basename(output_path)}")
                        
                        # Securely delete original if option is selected
                        if self.secure_delete_var.get():
                            self.secure_delete_file(file_path)
                            self.log(f"Securely deleted original: {file_name}")
                            
                    else:
                        # For decryption, check if file has .encrypted extension
                        output_name = file_name
                        if output_name.endswith('.encrypted'):
                            output_name = output_name[:-10]  # Remove .encrypted extension
                        
                        output_path = os.path.join(self.output_dir, output_name)
                        self.decrypt_file(file_path, output_path, password)
                        self.log(f"Decrypted: {file_name} -> {os.path.basename(output_path)}")
                        
                except Exception as e:
                    error_msg = f"Error processing {file_name}: {str(e)}"
                    self.log(error_msg, is_error=True)
                    logger.error(error_msg)
                
                processed_files += 1
                progress_val = (processed_files / total_files) * 100
                self.progress['value'] = progress_val
                
            self.update_status(f"{action} completed")
            messagebox.showinfo("Success", f"{action} completed successfully")
            
        except Exception as e:
            error_msg = f"Error during {action.lower()}: {str(e)}"
            self.log(error_msg, is_error=True)
            logger.error(error_msg)
            messagebox.showerror("Error", error_msg)
            
        finally:
            # Re-enable buttons
            self.encrypt_btn.config(state=tk.NORMAL)
            self.decrypt_btn.config(state=tk.NORMAL)
    
    def derive_key(self, password, salt):
        """Derive a key from the password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bit key for AES-256
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())
    
    def encrypt_file(self, input_path, output_path, password):
        """Encrypt a file using AES-GCM"""
        # Generate a random salt
        salt = secrets.token_bytes(16)
        
        # Generate a random nonce (12 bytes is recommended for AES-GCM)
        nonce = secrets.token_bytes(12)
        
        # Derive encryption key from password and salt
        key = self.derive_key(password, salt)
        
        # Create an AES-GCM cipher with the derived key
        aesgcm = AESGCM(key)
        
        # Read the file content
        with open(input_path, 'rb') as f:
            data = f.read()
            
        # Encrypt the data (no need for padding with GCM mode)
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        
        # Write the salt, nonce, and encrypted data to the output file
        with open(output_path, 'wb') as f:
            # Write header to identify our encrypted files
            f.write(b'SECENC')  # 6-byte identifier
            
            # Write lengths as 2-byte integers
            f.write(len(salt).to_bytes(2, byteorder='big'))
            f.write(len(nonce).to_bytes(2, byteorder='big'))
            
            # Write the salt and nonce
            f.write(salt)
            f.write(nonce)
            
            # Write the encrypted data
            f.write(encrypted_data)
            
        logger.info(f"Encrypted file: {input_path} -> {output_path}")
    
    def decrypt_file(self, input_path, output_path, password):
        """Decrypt a file using AES-GCM"""
        try:
            with open(input_path, 'rb') as f:
                # Check the file identifier
                identifier = f.read(6)
                if identifier != b'SECENC':
                    raise ValueError("Not a valid encrypted file format")
                    
                # Read the lengths
                salt_len = int.from_bytes(f.read(2), byteorder='big')
                nonce_len = int.from_bytes(f.read(2), byteorder='big')
                
                # Read the salt and nonce
                salt = f.read(salt_len)
                nonce = f.read(nonce_len)
                
                # Read the encrypted data
                encrypted_data = f.read()
            
            # Derive the key from the password and salt
            key = self.derive_key(password, salt)
            
            # Create an AES-GCM cipher with the derived key
            aesgcm = AESGCM(key)
            
            # Decrypt the data
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
            
            # Write the decrypted data to the output file
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
                
            logger.info(f"Decrypted file: {input_path} -> {output_path}")
            
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise ValueError("Decryption failed. Incorrect password or corrupted file.")
    
    def secure_delete_file(self, file_path):
        """Securely delete a file by overwriting with random data before deletion"""
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Overwrite the file content with random data 3 times
        for i in range(3):
            with open(file_path, 'wb') as f:
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        # Delete the file
        os.unlink(file_path)
        logger.info(f"Securely deleted file: {file_path}")
    
    def log(self, message, is_error=False):
        """Add a message to the log window"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        level = "ERROR" if is_error else "INFO"
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        # Ensure UI updates happen in the main thread
        self.after(0, self._update_log, log_entry)
        
        # Also log to the logger
        if is_error:
            logger.error(message)
        else:
            logger.info(message)
    
    def _update_log(self, log_entry):
        """Update the log text widget (to be called from main thread)"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)  # Scroll to the end
        self.log_text.config(state=tk.DISABLED)
    
    def update_status(self, message):
        """Update the status label"""
        self.after(0, lambda: self.status_label.config(text=message))
    
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        current_theme = self.theme_var.get()
        new_theme = "dark" if current_theme == "light" else "light"
        self.theme_var.set(new_theme)
        self.apply_theme()
        
    def apply_theme(self):
        """Apply the current theme"""
        theme = self.theme_var.get()
        
        if theme == "dark":
            # Dark theme colors
            bg_color = "#2D2D2D"
            fg_color = "#FFFFFF"
            entry_bg = "#3D3D3D"
            entry_fg = "#FFFFFF"
            button_bg = "#505050"
            button_fg = "#FFFFFF"
            
            # Special buttons retain their colors
            encrypt_bg = "#4CAF50"
            decrypt_bg = "#2196F3"
            
        else:
            # Light theme colors
            bg_color = "#F0F0F0"
            fg_color = "#000000"
            entry_bg = "#FFFFFF"
            entry_fg = "#000000"
            button_bg = "#E0E0E0"
            button_fg = "#000000"
            
            # Special buttons retain their colors
            encrypt_bg = "#4CAF50"
            decrypt_bg = "#2196F3"
        
        # Configure main window and frames
        self.configure(bg=bg_color)
        self.menu_frame.configure(bg=bg_color)
        self.content_frame.configure(bg=bg_color)
        self.status_frame.configure(bg=bg_color)
        
        # Configure widgets
        for widget in self.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.configure(bg=bg_color)
                self._configure_child_widgets(widget, bg_color, fg_color, entry_bg, entry_fg, button_bg, button_fg)
        
        # Special buttons retain their colors
        self.encrypt_btn.configure(bg=encrypt_bg, fg="white")
        self.decrypt_btn.configure(bg=decrypt_bg, fg="white")
        
        # Configure log text
        self.log_text.configure(bg=entry_bg, fg=entry_fg)
        
    def _configure_child_widgets(self, parent, bg_color, fg_color, entry_bg, entry_fg, button_bg, button_fg):
        """Configure child widgets of a parent widget with the theme colors"""
        for widget in parent.winfo_children():
            try:
                widget_type = widget.winfo_class()
                
                if widget_type in ('Frame', 'Labelframe', 'TFrame'):
                    widget.configure(bg=bg_color)
                    self._configure_child_widgets(widget, bg_color, fg_color, entry_bg, entry_fg, button_bg, button_fg)
                    
                elif widget_type == 'Label':
                    widget.configure(bg=bg_color, fg=fg_color)
                    
                elif widget_type == 'Entry':
                    widget.configure(bg=entry_bg, fg=entry_fg, insertbackground=fg_color)
                    
                elif widget_type == 'Button':
                    # Skip special buttons (encrypt/decrypt)
                    if widget not in (self.encrypt_btn, self.decrypt_btn):
                        widget.configure(bg=button_bg, fg=button_fg)
                        
                elif widget_type == 'Listbox':
                    widget.configure(bg=entry_bg, fg=entry_fg)
                    
                elif widget_type == 'Checkbutton':
                    widget.configure(bg=bg_color, fg=fg_color, selectcolor=entry_bg)
                    
                elif widget_type == 'Text':
                    widget.configure(bg=entry_bg, fg=entry_fg, insertbackground=fg_color)
                    
                elif isinstance(widget, (tk.Frame, tk.LabelFrame)):
                    widget.configure(bg=bg_color)
                    self._configure_child_widgets(widget, bg_color, fg_color, entry_bg, entry_fg, button_bg, button_fg)
                    
            except tk.TclError:
                pass  # Ignore errors for widgets that don't support certain configurations
    
    def show_help(self):
        """Show help information"""
        help_text = """Secure File Encryptor Help

Encryption:
- Add files using the 'Add Files' button or drag and drop
- Enter and confirm your password
- Select options (e.g., secure delete)
- Click 'Encrypt Files'

Decryption:
- Add encrypted files
- Enter the password used for encryption
- Click 'Decrypt Files'

Security Notes:
- Files are encrypted with AES-256 bit encryption
- Passwords are never stored
- Original files can be securely deleted after encryption
- Always keep your password safe - lost passwords cannot be recovered

For more help, please refer to the documentation.
"""
        help_window = tk.Toplevel(self)
        help_window.title("Help")
        help_window.geometry("500x400")
        
        text = ScrolledText(help_window)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, help_text)
        text.config(state=tk.DISABLED)

if __name__ == "__main__":
    try:
        app = SecureFileEncryptor()
        app.mainloop()
    except Exception as e:
        logging.error(f"Application error: {str(e)}")
        messagebox.showerror("Error", f"Application error: {str(e)}")


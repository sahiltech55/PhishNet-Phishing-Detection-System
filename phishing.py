import re
import requests
import os
import socket
import ssl
import ctypes
import sys
import tkinter as tk  # Import Tkinter for GUI
from urllib.parse import urlparse
from datetime import datetime


if os.name == 'nt':
    HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"
else:
    HOSTS_FILE = "/etc/hosts"  # For Unix-based systems

def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def is_phishing_url(url):
    """Check if a URL is potentially phishing"""
    try:
        # Parse URL
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else url  # Ensure full URL is captured
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'https?://[^/]+@',  # Credentials in URL
            r'\.(tk|ml|ga|cf|gq)$',  # Free domains
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP address
            r'(login|signin|account|verify|secure|update|confirm)',  # Suspicious keywords
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        # Check SSL certificate
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # Check if certificate is valid
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if datetime.now() > not_after:
                    return True
        
        # Check domain age (if possible)
        try:
            whois = requests.get(f"https://whois.domaintools.com/{domain}", timeout=5)
            if "Created" in whois.text:
                created_date = whois.text.split("Created:")[1].split("\n")[0].strip()
                created = datetime.strptime(created_date, '%Y-%m-%d')
                if (datetime.now() - created).days < 30:
                    return True
        except:
            pass
            
        return False
        
    except Exception as e:
        print(f"Error checking URL: {e}")  # More specific error handling can be added here
        return False

def block_url(url):
    """Block URL by adding to hosts file"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else url  # Ensure full URL is captured
        
        # Add to hosts file
        with open(HOSTS_FILE, 'a') as f:
            f.write(f"\n127.0.0.1 {domain}")  # Block the domain
            f.write(f"\n127.0.0.1 www.{domain}")  # Block the www version
            f.write(f"\n127.0.0.1 {url}")  # Block the full URL

        
        print(f"Successfully blocked {domain}.")

        return True
    except PermissionError:
        print("Error: Need administrator privileges to modify hosts file")
        print("Please run this script as Administrator")
        return False
    except Exception as e:
        print(f"Error blocking URL: {e}")
        return False

def main():
    """Main function to launch the GUI"""
    def check_url():
        url = url_entry.get().strip()  # Get URL from entry field
        if is_phishing_url(url):
            result_label.config(text="WARNING: This URL appears to be phishing!")

            block_url(url)
            result_label.config(text="URL has been successfully blocked.")


        else:
            result_label.config(text="This URL appears to be safe.")


    # Create the main window
    window = tk.Tk()
    window.title("Phishing URL Detector")
    window.geometry("400x300")

    # Label for URL input
    url_label = tk.Label(window, text="Enter the URL:", font=("Arial", 12))
    url_label.pack(pady=5)

    # Input field with styling

    url_entry = tk.Entry(window, width=50, font=("Arial", 12), bg="lightyellow")

    url_entry = tk.Entry(window, width=50)
    url_entry.pack(pady=20)

    # Check button with styling
    check_button = tk.Button(window, text="Check URL", command=check_url, bg="lightgreen", font=("Arial", 12))

    check_button = tk.Button(window, text="Check URL", command=check_url)
    check_button.pack()

    # Result display with styling
    result_label = tk.Label(window, text="", font=("Arial", 12))

    result_label = tk.Label(window, text="")
    result_label.pack(pady=50)

    # Remove command-line URL checking logic
    # window.mainloop()  # Start the GUI event loop



    # Clear button to reset input and result
    clear_button = tk.Button(window, text="Clear", command=lambda: (url_entry.delete(0, tk.END), result_label.config(text="")), bg="lightcoral", font=("Arial", 12))
    clear_button.pack(pady=10)  # Increase space between buttons


    window.mainloop()  # Start the GUI event loop



if __name__ == "__main__":
    main()

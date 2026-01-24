"""
IMAP Common Utilities

Shared functionality for IMAP migration, counting, and comparison scripts.
"""

import imaplib
import os
import sys
import re
from email.header import decode_header
from email.parser import BytesParser

def verify_env_vars(vars_list):
    """
    Checks if all environment variables in the list are set.
    Returns True if all are present, False otherwise.
    Prints missing variables to stderr.
    """
    missing = [v for v in vars_list if not os.getenv(v)]
    if missing:
        print(f"Error: Missing environment variables: {', '.join(missing)}", file=sys.stderr)
        return False
    return True

def get_imap_connection(host, user, password):
    """
    Establishes an SSL connection to the IMAP server and logs in.
    Returns the connection object or None if failed.
    """
    if not all([host, user, password]):
        print(f"Error: Invalid credentials for {host}")
        return None

    try:
        conn = imaplib.IMAP4_SSL(host)
        conn.login(user, password)
        return conn
    except Exception as e:
        print(f"Connection error to {host}: {e}")
        return None

def normalize_folder_name(folder_info_str):
    """
    Parses the IMAP list response to extract the clean folder name.
    Handles quoted names and flags.
    """
    if isinstance(folder_info_str, bytes):
        folder_info_str = folder_info_str.decode('utf-8', errors='ignore')

    # Regex to extract folder name: (flags) "delimiter" name
    # Matches: (\HasNoChildren) "/" "INBOX"  OR  (\HasNoChildren) "/" Drafts
    list_pattern = re.compile(r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" "?(?P<name>.*)"?')
    match = list_pattern.search(folder_info_str)
    if match:
        name = match.group('name')
        # If the regex grabbed a trailing quote, strip it (though the regex tries to handle it)
        return name.rstrip('"').strip()
    
    # Fallback: take the last part
    return folder_info_str.split()[-1].strip('"')

def decode_mime_header(header_value):
    """
    Decodes MIME encoded headers (Subject, etc.) to a unicode (str) string.
    """
    if not header_value:
        return "(No Subject)"
    try:
        decoded_list = decode_header(header_value)
        default_charset = 'utf-8'
        text_parts = []
        for bytes_data, encoding in decoded_list:
            if isinstance(bytes_data, bytes):
                if encoding:
                    try:
                        text_parts.append(bytes_data.decode(encoding, errors='ignore'))
                    except LookupError:
                        text_parts.append(bytes_data.decode(default_charset, errors='ignore'))
                else:
                    text_parts.append(bytes_data.decode(default_charset, errors='ignore'))
            else:
                text_parts.append(str(bytes_data))
        return "".join(text_parts)
    except Exception:
        return str(header_value)

def get_msg_details(imap_conn, uid):
    """
    Fetches simplified message details (Message-ID, Size, Subject) for a given UID.
    Returns (msg_id, size, subject) tuple.
    """
    try:
        resp, data = imap_conn.uid('fetch', uid, '(RFC822.SIZE BODY.PEEK[HEADER.FIELDS (MESSAGE-ID SUBJECT)])')
    except Exception:
        return None, None, None
        
    if resp != 'OK':
        return None, None, None
        
    msg_id = None
    subject = "(No Subject)"
    size = 0
    
    for item in data:
        if isinstance(item, tuple):
            content = item[0].decode('utf-8', errors='ignore')
            
            # Parse Size
            size_match = re.search(r'RFC822\.SIZE\s+(\d+)', content)
            if size_match:
                size = int(size_match.group(1))
            
            # Parse Headers
            msg_bytes = item[1]
            parser = BytesParser()
            email_obj = parser.parsebytes(msg_bytes)
            msg_id = email_obj.get('Message-ID')
            raw_subject = email_obj.get('Subject')
            if raw_subject:
                subject = decode_mime_header(raw_subject)
            
    return msg_id, size, subject

def message_exists_in_folder(dest_conn, msg_id, src_size):
    """
    Checks if a message with the given Message-ID and RFC822.SIZE exists in the CURRENTLY SELECTED folder of dest_conn.
    Returns True if found, False otherwise.
    """
    if not msg_id:
        return False
    
    clean_id = msg_id.replace('"', '\\"')
    try:
        typ, data = dest_conn.search(None, f'(HEADER Message-ID "{clean_id}")')
        if typ != 'OK':
            return False
            
        dest_ids = data[0].split()
        if not dest_ids:
            return False
            
        for did in dest_ids:
            resp, items = dest_conn.fetch(did, '(RFC822.SIZE)')
            if resp == 'OK':
                for item in items:
                    if isinstance(item, bytes):
                        content = item.decode('utf-8', errors='ignore')
                    else: 
                        content = item[0].decode('utf-8', errors='ignore')
                    size_match = re.search(r'RFC822\.SIZE\s+(\d+)', content)
                    if size_match and int(size_match.group(1)) == src_size:
                        return True
    except Exception:
        return False
    return False

def detect_trash_folder(imap_conn):
    """
    Attempts to identify the Trash folder in the account.
    Returns the folder name (str) or None if not found.
    Checks for common names and SPECIAL-USE attributes.
    """
    try:
        status, folders = imap_conn.list()
        if status != 'OK':
            return None
    except Exception:
        return None
    
    trash_candidates = ['[Gmail]/Trash', 'Trash', 'Deleted Items', 'Bin', '[Gmail]/Bin']
    detected_by_flag = None
    all_folder_names = []

    for f in folders:
        if isinstance(f, bytes):
            f_str = f.decode('utf-8', errors='ignore')
        else:
            f_str = str(f)
            
        name = normalize_folder_name(f_str)
        all_folder_names.append(name)
        
        # Check for SPECIAL-USE flag \Trash
        # The flag is usually inside parentheses like (\HasNoChildren \Trash)
        if '\\Trash' in f_str or '\\Bin' in f_str: 
            detected_by_flag = name
            
    if detected_by_flag:
        return detected_by_flag

    # Check candidates
    for candidate in trash_candidates:
        if candidate in all_folder_names:
            return candidate
            
    return None

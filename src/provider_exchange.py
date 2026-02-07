"""
Exchange-Specific IMAP Utilities

Constants and functions specific to Microsoft Exchange/Outlook IMAP implementation.
"""

# Exchange/Outlook folders that typically can't be backed up via IMAP
# These often contain proprietary data that Exchange returns as error messages
EXCHANGE_SKIP_FOLDERS = {
    "Suggested Contacts",
    "Conversation History",
    "Calendar",
}


def is_special_folder(folder_name):
    """
    Check if a folder is an Exchange system folder that should be skipped.

    These folders often contain proprietary data that Exchange returns as error messages.

    Args:
        folder_name: The name of the folder to check

    Returns:
        True if the folder should be skipped, False otherwise
    """
    return folder_name in EXCHANGE_SKIP_FOLDERS

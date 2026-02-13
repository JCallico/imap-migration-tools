"""
Tests for provider_exchange.py

Tests cover:
- Exchange special folder detection
- EXCHANGE_SKIP_FOLDERS constant validation
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import provider_exchange


class TestIsSpecialFolder:
    """Tests for is_special_folder function."""

    def test_suggested_contacts_is_special(self):
        """Test that Suggested Contacts is detected as special folder."""
        assert provider_exchange.is_special_folder("Suggested Contacts") is True

    def test_conversation_history_is_special(self):
        """Test that Conversation History is detected as special folder."""
        assert provider_exchange.is_special_folder("Conversation History") is True

    def test_calendar_is_special(self):
        """Test that Calendar is detected as special folder."""
        assert provider_exchange.is_special_folder("Calendar") is True

    def test_contacts_is_special(self):
        """Test that Contacts is detected as special folder."""
        assert provider_exchange.is_special_folder("Contacts") is True

    def test_inbox_is_not_special(self):
        """Test that INBOX is not a special folder."""
        assert provider_exchange.is_special_folder("INBOX") is False

    def test_sent_items_is_not_special(self):
        """Test that Sent Items is not a special folder."""
        assert provider_exchange.is_special_folder("Sent Items") is False

    def test_drafts_is_not_special(self):
        """Test that Drafts is not a special folder."""
        assert provider_exchange.is_special_folder("Drafts") is False

    def test_user_folder_is_not_special(self):
        """Test that user-created folders are not special."""
        assert provider_exchange.is_special_folder("Work") is False
        assert provider_exchange.is_special_folder("Personal") is False

    def test_case_sensitive_matching(self):
        """Test that matching is case-sensitive."""
        assert provider_exchange.is_special_folder("suggested contacts") is False
        assert provider_exchange.is_special_folder("CALENDAR") is False

    def test_empty_string(self):
        """Test handling of empty string."""
        assert provider_exchange.is_special_folder("") is False

    def test_none_value(self):
        """Test handling of None value."""
        # This test documents current behavior - function expects string
        # In practice, callers should handle None before calling
        try:
            result = provider_exchange.is_special_folder(None)
            # If it doesn't raise, check the result
            assert result is False
        except (TypeError, AttributeError):
            # Expected if None is not handled
            pass


class TestExchangeConstants:
    """Tests for Exchange constants."""

    def test_exchange_skip_folders_constant(self):
        """Test that EXCHANGE_SKIP_FOLDERS contains expected folders."""
        assert "Suggested Contacts" in provider_exchange.EXCHANGE_SKIP_FOLDERS
        assert "Conversation History" in provider_exchange.EXCHANGE_SKIP_FOLDERS
        assert "Calendar" in provider_exchange.EXCHANGE_SKIP_FOLDERS
        assert "Contacts" in provider_exchange.EXCHANGE_SKIP_FOLDERS

    def test_exchange_skip_folders_count(self):
        """Test that EXCHANGE_SKIP_FOLDERS has expected number of entries."""
        # This test will catch if folders are accidentally added/removed
        assert len(provider_exchange.EXCHANGE_SKIP_FOLDERS) == 4

    def test_inbox_not_in_skip_folders(self):
        """Test that INBOX is not in EXCHANGE_SKIP_FOLDERS."""
        assert "INBOX" not in provider_exchange.EXCHANGE_SKIP_FOLDERS

    def test_sent_items_not_in_skip_folders(self):
        """Test that Sent Items is not in EXCHANGE_SKIP_FOLDERS."""
        assert "Sent Items" not in provider_exchange.EXCHANGE_SKIP_FOLDERS

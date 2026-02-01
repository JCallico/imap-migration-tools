"""Restore progress cache.

This module supports faster incremental restores by persisting, per destination+folder,
the set of Message-IDs already seen/processed by this tool.

The caller decides where the cache file lives by passing a cache directory/root.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections.abc import Callable

RESTORE_CACHE_VERSION = 1

# Throttle disk writes so we can update frequently without rewriting a large JSON file
# on every single message.
_MIN_SECONDS_BETWEEN_SAVES = 2.0
_MIN_PENDING_UPDATES_BEFORE_SAVE = 50


def _safe_cache_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value or "")


def _prepare_cache_for_json(cache_data: dict) -> dict:
    """Create a deep copy of cache_data suitable for JSON serialization.
    
    Removes in-memory helper fields like _ids_set that should not be persisted.
    """
    import copy

    snapshot = copy.deepcopy(cache_data)
    folders = snapshot.get("folders", {})
    if isinstance(folders, dict):
        for folder_entry in folders.values():
            if isinstance(folder_entry, dict):
                # Remove the in-memory set cache
                folder_entry.pop("_ids_set", None)
    return snapshot


def get_dest_index_cache_path(cache_root: str, dest_host: str, dest_user: str) -> str:
    safe_host = _safe_cache_component(dest_host)
    safe_user = _safe_cache_component(dest_user)
    return os.path.join(cache_root, f"restore_cache_{safe_host}_{safe_user}.json")


def load_dest_index_cache(cache_path: str) -> dict:
    try:
        with open(cache_path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"version": RESTORE_CACHE_VERSION, "folders": {}, "_meta": {}}
        if data.get("version") != RESTORE_CACHE_VERSION:
            return {"version": RESTORE_CACHE_VERSION, "folders": {}, "_meta": {}}
        if not isinstance(data.get("folders"), dict):
            data["folders"] = {}
        if not isinstance(data.get("_meta"), dict):
            data["_meta"] = {}
        return data
    except FileNotFoundError:
        return {"version": RESTORE_CACHE_VERSION, "folders": {}, "_meta": {}}
    except Exception:
        return {"version": RESTORE_CACHE_VERSION, "folders": {}, "_meta": {}}


def save_dest_index_cache(cache_path: str, cache_data: dict) -> None:
    try:
        tmp_path = f"{cache_path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, ensure_ascii=False)
        os.replace(tmp_path, cache_path)
        return True
    except Exception:
        # Cache is best-effort; do not fail restore.
        return False


def _ensure_dest(cache_data: dict, dest_host: str, dest_user: str) -> None:
    cache_dest = cache_data.get("dest")
    if not isinstance(cache_dest, dict) or cache_dest.get("host") != dest_host or cache_dest.get("user") != dest_user:
        cache_data.clear()
        cache_data.update(
            {
                "version": RESTORE_CACHE_VERSION,
                "dest": {"host": dest_host, "user": dest_user},
                "folders": {},
                "_meta": {},
            }
        )


def get_cached_message_ids(
    cache_data: dict,
    cache_lock: threading.Lock,
    dest_host: str,
    dest_user: str,
    folder_name: str,
) -> set[str]:
    """Return Message-IDs we've already seen/processed for this destination+folder."""
    with cache_lock:
        _ensure_dest(cache_data, dest_host, dest_user)
        folders = cache_data.setdefault("folders", {})
        entry = folders.get(folder_name)
        if not isinstance(entry, dict):
            return set()
        ids = entry.get("message_ids")
        if not isinstance(ids, list):
            return set()
        return {str(x) for x in ids if x}


def add_cached_message_id(
    cache_data: dict,
    cache_lock: threading.Lock,
    dest_host: str,
    dest_user: str,
    folder_name: str,
    message_id: str,
) -> bool:
    """Add a Message-ID to the cache. Returns True if it was newly added."""
    if not message_id:
        return False
    msg_id = str(message_id).strip()
    if not msg_id:
        return False

    with cache_lock:
        _ensure_dest(cache_data, dest_host, dest_user)
        folders = cache_data.setdefault("folders", {})
        entry = folders.setdefault(folder_name, {})
        if not isinstance(entry, dict):
            folders[folder_name] = {}
            entry = folders[folder_name]

        ids = entry.get("message_ids")
        if not isinstance(ids, list):
            ids = []
            entry["message_ids"] = ids

        # Maintain an in-memory set for O(1) lookups (not persisted to JSON)
        # The set is cached at the entry level to avoid O(n) set construction on each call
        ids_set = entry.get("_ids_set")
        if ids_set is None:
            ids_set = set(ids)
            entry["_ids_set"] = ids_set

        if msg_id in ids_set:
            return False

        ids.append(msg_id)
        ids_set.add(msg_id)

        meta = cache_data.setdefault("_meta", {})
        if not isinstance(meta, dict):
            meta = {}
            cache_data["_meta"] = meta
        meta["pending_updates"] = int(meta.get("pending_updates") or 0) + 1
        return True


def maybe_save_dest_index_cache(
    cache_path: str,
    cache_data: dict,
    cache_lock: threading.Lock,
    *,
    force: bool = False,
    log_fn: Callable[[str], None] | None = None,
) -> bool:
    """Persist cache to disk if enough updates/time has accumulated."""
    now = time.time()
    pending = 0
    with cache_lock:
        meta = cache_data.setdefault("_meta", {})
        if not isinstance(meta, dict):
            meta = {}
            cache_data["_meta"] = meta

        pending = int(meta.get("pending_updates") or 0)
        last_saved = float(meta.get("last_saved_ts") or 0.0)

        should_save = force or (
            pending > 0
            and (pending >= _MIN_PENDING_UPDATES_BEFORE_SAVE or (now - last_saved) >= _MIN_SECONDS_BETWEEN_SAVES)
        )
        if not should_save:
            return False

        # Update meta before writing so the on-disk file reflects the flush decision.
        meta["pending_updates"] = 0
        meta["last_saved_ts"] = now

        # Prepare a clean snapshot for JSON serialization (removes in-memory helper fields)
        snapshot = _prepare_cache_for_json(cache_data)

    did_write = save_dest_index_cache(cache_path, snapshot)
    if did_write and log_fn is not None:
        log_fn(f"Wrote restore cache ({pending} updates): {cache_path}")
    return did_write


def record_progress(
    *,
    message_id: str | None,
    folder_name: str,
    existing_dest_msg_ids: set[str] | None,
    existing_dest_msg_ids_lock: threading.Lock | None,
    progress_cache_path: str | None,
    progress_cache_data: dict | None,
    progress_cache_lock: threading.Lock | None,
    dest_host: str | None,
    dest_user: str | None,
    log_fn: Callable[[str], None] | None = None,
) -> None:
    """Record a processed Message-ID for fast skipping on future incremental runs.

    Updates both:
    - the in-memory set used by the current run, and
    - the persisted progress cache on disk (throttled writes).
    """
    if not message_id:
        return

    msg_id = str(message_id).strip()
    if not msg_id:
        return

    if existing_dest_msg_ids is not None and existing_dest_msg_ids_lock is not None:
        with existing_dest_msg_ids_lock:
            existing_dest_msg_ids.add(msg_id)

    if (
        progress_cache_path
        and progress_cache_data is not None
        and progress_cache_lock is not None
        and dest_host
        and dest_user
    ):
        add_cached_message_id(
            progress_cache_data,
            progress_cache_lock,
            dest_host,
            dest_user,
            folder_name,
            msg_id,
        )
        maybe_save_dest_index_cache(
            progress_cache_path,
            progress_cache_data,
            progress_cache_lock,
            log_fn=log_fn,
        )

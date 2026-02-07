import re
import socketserver
import threading

RESPONSE_SEARCH_COMPLETED = "OK SEARCH completed"
RESPONSE_SELECT_FIRST = "NO Select first"


class MockIMAPHandler(socketserver.StreamRequestHandler):
    """
    A minimal IMAP4rev1 mock server handler for testing purposes.
    Supports basic commands required for the migration scripts.
    """

    def handle(self):
        self.wfile.write(b"* OK [CAPABILITY IMAP4rev1] Mock IMAP Server Ready\r\n")
        self.selected_folder = None
        self.current_folders = self.server.folders

        while True:
            try:
                line = self.rfile.readline()
                if not line:
                    break
                line = line.decode("utf-8").strip()
                if not line:
                    continue

                parts = line.split(" ", 2)
                tag = parts[0]
                cmd = parts[1].upper()
                args = parts[2] if len(parts) > 2 else ""

                if cmd == "LOGIN":
                    self.send_response(tag, "OK LOGIN completed")

                elif cmd == "LOGOUT":
                    self.send_response(tag, "OK LOGOUT completed")
                    break

                elif cmd == "CAPABILITY":
                    self.wfile.write(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n")
                    self.send_response(tag, "OK CAPABILITY completed")

                elif cmd == "LIST":
                    for folder in self.current_folders:
                        self.wfile.write(f'* LIST (\\HasNoChildren) "/" "{folder}"\r\n'.encode())
                    self.send_response(tag, "OK LIST completed")

                elif cmd == "SELECT":
                    folder = args.strip().strip('"')
                    if folder in self.current_folders:
                        self.selected_folder = folder
                        count = len(self.current_folders[folder])
                        self.wfile.write(f"* {count} EXISTS\r\n".encode())
                        self.wfile.write(f"* {count} RECENT\r\n".encode())
                        self.wfile.write(b"* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n")
                        self.wfile.write(b"* OK [UIDVALIDITY 1] UIDs valid\r\n")
                        self.send_response(tag, "OK [READ-WRITE] SELECT completed")
                    else:
                        self.send_response(tag, "NO [NONEXISTENT] Folder not found")

                elif cmd == "EXAMINE":
                    # EXAMINE is like SELECT but read-only
                    folder = args.strip().strip('"')
                    if folder in self.current_folders:
                        self.selected_folder = folder
                        count = len(self.current_folders[folder])
                        self.wfile.write(f"* {count} EXISTS\r\n".encode())
                        self.wfile.write(f"* {count} RECENT\r\n".encode())
                        self.wfile.write(b"* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n")
                        self.wfile.write(b"* OK [UIDVALIDITY 1] UIDs valid\r\n")
                        self.send_response(tag, "OK [READ-ONLY] EXAMINE completed")
                    else:
                        self.send_response(tag, "NO [NONEXISTENT] Folder not found")

                elif cmd == "CREATE":
                    folder = args.strip().strip('"')
                    if folder not in self.current_folders:
                        self.current_folders[folder] = []
                    self.send_response(tag, "OK CREATE completed")

                elif cmd == "SEARCH":
                    if not self.selected_folder:
                        self.send_response(tag, RESPONSE_SELECT_FIRST)
                        continue

                    msgs = self.current_folders[self.selected_folder]
                    sub_args = args

                    header_msg_id = None
                    try:
                        m = re.search(r'HEADER\s+Message-ID\s+"([^"]+)"', sub_args, re.IGNORECASE)
                        if m:
                            header_msg_id = m.group(1)
                    except Exception:
                        header_msg_id = None

                    seq_nums = []
                    for idx, m in enumerate(msgs, start=1):
                        if "UNDELETED" in sub_args and "\\Deleted" in m["flags"]:
                            continue
                        if header_msg_id:
                            msg_text = m["content"].decode("utf-8", errors="ignore")
                            if header_msg_id not in msg_text:
                                continue
                        seq_nums.append(str(idx))

                    if "ALL" in sub_args.upper() and not header_msg_id:
                        seq_nums = [str(idx) for idx in range(1, len(msgs) + 1)]

                    seq_str = " ".join(seq_nums)
                    if seq_str:
                        self.wfile.write(f"* SEARCH {seq_str}\r\n".encode())
                    else:
                        self.wfile.write(b"* SEARCH\r\n")
                    self.send_response(tag, RESPONSE_SEARCH_COMPLETED)

                elif cmd == "EXPUNGE":
                    if self.selected_folder:
                        msgs = self.current_folders[self.selected_folder]
                        # In-place remove marked deleted
                        # We use a dictionary-like structure implicitly via dicts in list now
                        # Check "flags" set in msg object
                        new_msgs = [m for m in msgs if "\\Deleted" not in m["flags"]]
                        self.current_folders[self.selected_folder] = new_msgs
                        # According to IMAP, we should send Expunge indices but we'll skip for mock
                        self.send_response(tag, "OK EXPUNGE completed")
                    else:
                        self.send_response(tag, RESPONSE_SELECT_FIRST)

                elif cmd == "UID":
                    sub_parts = args.split(" ", 1)
                    sub_cmd = sub_parts[0].upper()
                    sub_rest = sub_parts[1] if len(sub_parts) > 1 else ""

                    if sub_cmd == "SEARCH":
                        sub_args = sub_rest
                        if not self.selected_folder:
                            self.send_response(tag, RESPONSE_SELECT_FIRST)
                            continue
                        msgs = self.current_folders[self.selected_folder]

                        # Support UID range searches like: UID SEARCH UID 101:*
                        uid_min = None
                        try:
                            m = re.search(r"UID\s+(\d+)", sub_args, re.IGNORECASE)
                            if m:
                                uid_min = int(m.group(1))
                        except Exception:
                            uid_min = None

                        # Handle UNDELETED
                        # If args has UNDELETED, filter flags
                        valid_uids = []
                        for m in msgs:
                            if uid_min is not None and m["uid"] < uid_min:
                                continue
                            if "UNDELETED" in sub_args and "\\Deleted" in m["flags"]:
                                continue
                            valid_uids.append(str(m["uid"]))

                        uids_str = " ".join(valid_uids)
                        if uids_str:
                            self.wfile.write(f"* SEARCH {uids_str}\r\n".encode())
                        else:
                            self.wfile.write(b"* SEARCH\r\n")
                        self.send_response(tag, RESPONSE_SEARCH_COMPLETED)

                    elif sub_cmd == "STORE":
                        # UID STORE <uid> +FLAGS (\Deleted)
                        store_parts = sub_rest.split(" ", 2)

                        uid = int(store_parts[0])
                        action = store_parts[1].upper()  # +FLAGS or -FLAGS

                        # Flags can be "(\Deleted)" or "\Deleted"
                        flags_str = store_parts[2].strip("()")
                        flags_list = {f.strip() for f in flags_str.split()}

                        if self.selected_folder:
                            msgs = self.current_folders[self.selected_folder]
                            found = False
                            for m in msgs:
                                if m["uid"] == uid:
                                    if action == "+FLAGS":
                                        m["flags"].update(flags_list)
                                    elif action == "-FLAGS":
                                        m["flags"].difference_update(flags_list)
                                    found = True

                                    # Send update
                                    flag_output = " ".join(m["flags"])
                                    self.wfile.write(
                                        f"* {msgs.index(m) + 1} FETCH (FLAGS ({flag_output}))\r\n".encode()
                                    )
                                    break
                            if found:
                                self.send_response(tag, "OK STORE completed")
                            else:
                                self.send_response(tag, "NO UID not found")
                        else:
                            self.send_response(tag, RESPONSE_SELECT_FIRST)

                    elif sub_cmd == "FETCH":
                        # sub_rest is e.g. "1 (RFC822.SIZE BODY.PEEK[...])"
                        parts = sub_rest.split(" ", 1)
                        uid_set = parts[0]
                        opts = parts[1].upper() if len(parts) > 1 else ""

                        if not self.selected_folder:
                            self.send_response(tag, RESPONSE_SELECT_FIRST)
                            continue

                        msgs = self.current_folders[self.selected_folder]
                        # Find msg by UID - handle single UID, comma-separated, or ranges
                        target_msgs = []
                        if ":" in uid_set:
                            # Range logic omitted for brevity, taking all for '*' or simplified assumption
                            # But since we use UIDs, we should filter.
                            target_msgs = msgs  # Return all for range
                        elif "," in uid_set:
                            # Handle comma-separated UIDs like "1,2,3"
                            try:
                                uid_list = [int(u) for u in uid_set.split(",")]
                                target_msgs = [m for m in msgs if m["uid"] in uid_list]
                            except Exception:
                                pass
                        else:
                            try:
                                t_uid = int(uid_set)
                                target_msgs = [m for m in msgs if m["uid"] == t_uid]
                            except Exception:
                                pass

                        for m in target_msgs:
                            # Mock always returns info if iterating all, or specific
                            # Construction
                            msg_content = m["content"]
                            msg_len = len(msg_content)
                            flags_str = " ".join(m["flags"])

                            # Check if requesting header fields only
                            if "HEADER.FIELDS" in opts:
                                rfc822_size_part = f" RFC822.SIZE {msg_len}" if "RFC822.SIZE" in opts else ""
                                # Extract just the headers from content
                                content_str = msg_content.decode("utf-8", errors="ignore")
                                header_part = content_str.split("\r\n\r\n")[0] + "\r\n"
                                header_bytes = header_part.encode("utf-8")
                                header_len = len(header_bytes)

                                resp = (
                                    f"* {msgs.index(m) + 1} FETCH (UID {m['uid']}{rfc822_size_part} FLAGS ({flags_str}) "
                                    f"BODY[HEADER.FIELDS (MESSAGE-ID SUBJECT)] {{{header_len}}}\r\n"
                                )
                                self.wfile.write(resp.encode("utf-8"))
                                self.wfile.write(header_bytes)
                                self.wfile.write(b")\r\n")
                            elif "RFC822" in opts or "BODY" in opts:
                                resp = f"* {msgs.index(m) + 1} FETCH (UID {m['uid']} RFC822.SIZE {msg_len} FLAGS ({flags_str})"
                                resp += f" BODY[] {{{msg_len}}}\r\n"
                                self.wfile.write(resp.encode("utf-8"))
                                self.wfile.write(msg_content)
                                self.wfile.write(b")\r\n")
                            else:
                                resp = f"* {msgs.index(m) + 1} FETCH (UID {m['uid']} RFC822.SIZE {msg_len} FLAGS ({flags_str})"
                                resp += ")\r\n"
                                self.wfile.write(resp.encode("utf-8"))

                            self.wfile.flush()

                        self.send_response(tag, "OK FETCH completed")

                    elif sub_cmd == "COPY":
                        # UID COPY <uid> <target>
                        c_parts = sub_rest.split(" ", 1)
                        c_uid = int(c_parts[0])
                        c_dest = c_parts[1].strip().strip('"')

                        if c_dest in self.current_folders and self.selected_folder:
                            msgs = self.current_folders[self.selected_folder]
                            found_msg = next((m for m in msgs if m["uid"] == c_uid), None)
                            if found_msg:
                                # COPY: create new msg object (new UID usually)
                                # We need a new UID generator.
                                # For simplicity, use max_uid + 1
                                dest_msgs = self.current_folders[c_dest]
                                max_uid = max([m["uid"] for m in dest_msgs], default=0)
                                new_msg = found_msg.copy()
                                new_msg["uid"] = max_uid + 1
                                new_msg["flags"] = found_msg["flags"].copy()
                                dest_msgs.append(new_msg)
                                self.send_response(tag, "OK COPY completed")
                            else:
                                self.send_response(tag, "NO UID not found")
                        else:
                            self.send_response(tag, "NO Dest not found")

                elif cmd == "APPEND":
                    try:
                        match = re.search(r"\{(\d+)\}$", args)
                        if match:
                            size = int(match.group(1))
                            self.wfile.write(b"+ Ready\r\n")
                            data = self.rfile.read(size)

                            # Args format (typical): <folder> (<flags>) "<internaldate>" {<size>}
                            # We only care about folder + flags for tests.
                            folder_arg = args.split(" ")[0].strip().strip('"')
                            flags_match = re.search(r"\(([^)]*)\)", args)
                            flags_set = set()
                            if flags_match:
                                flags_str = flags_match.group(1).strip()
                                if flags_str:
                                    flags_set = {f.strip() for f in flags_str.split() if f.strip()}

                            if folder_arg in self.current_folders:
                                dest_msgs = self.current_folders[folder_arg]
                                max_uid = max([m["uid"] for m in dest_msgs], default=0)

                                # IMPORTANT: Reset pointer or copy
                                new_msg = {"uid": max_uid + 1, "flags": flags_set, "content": data}
                                dest_msgs.append(new_msg)
                                print(f"MOCK APPEND SUCCESS: {folder_arg} now has {len(dest_msgs)}")
                                self.send_response(tag, "OK APPEND completed")
                            else:
                                self.send_response(tag, "NO Folder not found")
                        else:
                            self.send_response(tag, "BAD APPEND")
                    except Exception as e:
                        print(f"MOCK APPEND ERROR: {e}")
                        self.send_response(tag, "BAD APPEND")

                elif cmd == "STORE":
                    # STORE <msg_set> +FLAGS (\Seen)  (non-UID; uses message sequence numbers)
                    if not self.selected_folder:
                        self.send_response(tag, RESPONSE_SELECT_FIRST)
                        continue

                    try:
                        store_parts = args.split(" ", 2)
                        msg_set = store_parts[0]
                        action = store_parts[1].upper()  # +FLAGS or -FLAGS
                        flags_str = store_parts[2].strip().strip("()")
                        flags_list = {f.strip() for f in flags_str.split() if f.strip()}

                        msgs = self.current_folders[self.selected_folder]

                        # Only implement single message number for now (sufficient for tests)
                        try:
                            msg_num = int(msg_set)
                        except Exception:
                            self.send_response(tag, "BAD STORE")
                            continue

                        if msg_num < 1 or msg_num > len(msgs):
                            self.send_response(tag, "NO Message not found")
                            continue

                        m = msgs[msg_num - 1]
                        if action == "+FLAGS":
                            m["flags"].update(flags_list)
                        elif action == "-FLAGS":
                            m["flags"].difference_update(flags_list)

                        flag_output = " ".join(m["flags"])
                        self.wfile.write(f"* {msg_num} FETCH (FLAGS ({flag_output}))\r\n".encode())
                        self.send_response(tag, "OK STORE completed")
                    except Exception:
                        self.send_response(tag, "BAD STORE")

                elif cmd == "FETCH":
                    # Non-UID FETCH - args is e.g. "1 (RFC822.SIZE)"
                    if not self.selected_folder:
                        self.send_response(tag, RESPONSE_SELECT_FIRST)
                        continue

                    parts = args.split(" ", 1)
                    msg_num = int(parts[0])
                    opts = parts[1].upper() if len(parts) > 1 else ""

                    msgs = self.current_folders[self.selected_folder]
                    if 1 <= msg_num <= len(msgs):
                        m = msgs[msg_num - 1]  # Convert to 0-indexed
                        msg_content = m["content"]
                        msg_len = len(msg_content)
                        flags_str = " ".join(m["flags"])

                        resp = f"* {msg_num} FETCH (UID {m['uid']} RFC822.SIZE {msg_len} FLAGS ({flags_str})"

                        if "RFC822" in opts or "BODY" in opts:
                            resp += f" BODY[] {{{msg_len}}}\r\n"
                            self.wfile.write(resp.encode("utf-8"))
                            self.wfile.write(msg_content)
                            self.wfile.write(b")\r\n")
                        else:
                            resp += ")\r\n"
                            self.wfile.write(resp.encode("utf-8"))
                        self.wfile.flush()

                    self.send_response(tag, "OK FETCH completed")

                elif cmd == "NOOP":
                    self.send_response(tag, "OK NOOP")

                else:
                    self.send_response(tag, "BAD Command not recognized")

            except Exception:
                break

    def send_response(self, tag, message):
        self.wfile.write(f"{tag} {message}\r\n".encode())


class MockIMAPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, request_handler_class, initial_folders=None):
        super().__init__(server_address, request_handler_class)
        self.folders = {}
        if initial_folders:
            for fname, contents in initial_folders.items():
                self.folders[fname] = []
                for i, c in enumerate(contents):
                    if isinstance(c, bytes):
                        self.folders[fname].append({"uid": i + 1, "flags": set(), "content": c})
                    else:
                        self.folders[fname].append(c)
        else:
            self.folders = {"INBOX": []}


def start_server_thread(port=10143, initial_folders=None):
    server = MockIMAPServer(("localhost", port), MockIMAPHandler, initial_folders)
    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.start()
    return t, server

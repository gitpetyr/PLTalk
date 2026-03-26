import os
import json
import logging
import threading
import time
import webview

from npcp.api import API
from npcp.config import Config

logger = logging.getLogger(__name__)


class ApiBridge:
    def __init__(self):
        self._window: webview.Window = None
        self._profile = os.environ.get("PLTALK_PROFILE", "default")
        self._config = Config.load(self._profile)
        self._api: API = None

    def set_window(self, win: webview.Window):
        self._window = win

    def _emit(self, event_name: str, data: dict):
        if not self._window:
            return
        # Escape JSON for safely putting it into JS script format
        try:
            json_str = json.dumps(data, ensure_ascii=False)
            json_str = json_str.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
            script = f'window.on_event("{event_name}", JSON.parse("{json_str}"));'
            self._window.evaluate_js(script)
        except Exception as e:
            logger.error("Failed to emit event %s to JS: %s", event_name, e)

    # ── JS Callable ──────────────────────────────────────────────────────────

    def get_config(self) -> dict:
        return {
            "node_alias": self._config.node_alias,
            "network_id": self._config.network_id,
            "udp_discovery_port": self._config.udp_discovery_port,
            "tcp_listen_port": self._config.tcp_listen_port,
            "broadcast_interval": self._config.broadcast_interval,
            "enable_store_and_forward": self._config.enable_store_and_forward
        }

    def save_config(self, kwargs: dict):
        self._config.update(**kwargs)
        return True

    def login(self, alias: str, netid: str, udp: int, tcp: int) -> dict:
        self._config.update(
            node_alias = alias,
            network_id = netid,
            udp_discovery_port = int(udp),
            tcp_listen_port = int(tcp)
        )
        try:
            if not self._api:
                self._api = API(self._config)
                self._api.on("peer_discovered", self._on_peer_discovered)
                self._api.on("session_established", self._on_session_established)
                self._api.on("message_received", self._on_message_received)
                self._api.on("file_chunk_received", self._on_file_chunk)
                threading.Thread(target=self._api.start, daemon=True).start()
            
            return {
                "status": "ok", 
                "node_id": self._api.node_id, 
                "alias": self._api.alias
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def get_fingerprint(self) -> str:
        if self._api:
            return self._api.fingerprint
        return ""

    def send_message(self, peer_id: str, content: str):
        if self._api:
            self._api.send_message(peer_id, content)
            self._emit("message_sent", {
                "sender_id": peer_id,  # Render on peer's log
                "is_me": True,
                "content": content,
                "timestamp": int(time.time()),
                "alias": self._api.alias,
                "is_file": False
            })

    def choose_file(self) -> str:
        if not self._window: return ""
        file_types = ('All files (*.*)',)
        paths = self._window.create_file_dialog(webview.OPEN_DIALOG, allow_multiple=False, file_types=file_types)
        if paths and len(paths) > 0:
            return paths[0]
        return ""

    def send_file(self, peer_id: str, path: str):
        if self._api and os.path.exists(path):
            # We don't emit sending here immediately, let JS handle temporary view for better latency perception
            self._api.send_file(peer_id, path)

    def broadcast_message(self, content: str):
        if not self._api: return
        nodes = self._api.get_all_known_nodes()
        bcast_content = "BCAST:" + content
        for node in nodes:
            try:
                self._api.send_message(node["node_id"], bcast_content)
            except Exception:
                pass
        
        self._emit("message_sent", {
            "sender_id": "#BROADCAST", 
            "is_me": True,
            "content": content,
            "timestamp": int(time.time()),
            "alias": self._api.alias,
            "is_file": False,
            "is_broadcast": True
        })

    def broadcast_file(self, path: str):
        if not self._api or not os.path.exists(path): return
        nodes = self._api.get_all_known_nodes()
        for node in nodes:
            try:
                self._api.send_file(node["node_id"], path)
            except Exception:
                pass

    def open_file(self, path: str):
        if os.path.exists(path):
            if os.name == 'mac' or sys.platform == 'darwin':
                os.system(f'open "{path}"')
            elif os.name == 'nt':
                os.system(f'start "" "{path}"')
            elif os.name == 'posix':
                os.system(f'xdg-open "{path}"')

    # ── NPCP Event Handlers ──────────────────────────────────────────────────

    def _on_peer_discovered(self, peer_info: dict):
        self._emit("peer_discovered", peer_info)

    def _on_session_established(self, peer_id: str, session_id: str):
        self._emit("session_established", {"peer_id": peer_id, "session_id": session_id})

    def _on_message_received(self, msg: dict):
        # We need to attach the sender's alias if available
        nodes = self._api.get_all_known_nodes() if self._api else []
        node_map = {n["node_id"]: n for n in nodes}
        pid = msg.get("sender_id", "")
        alias = node_map.get(pid, {}).get("alias", pid[:12])
        
        content = msg.get("content", "")
        is_bcast = False
        if content.startswith("BCAST:"):
            is_bcast = True
            content = content[6:]

        self._emit("message_received", {
            "sender_id": pid,
            "is_me": False,
            "content": content,
            "timestamp": msg.get("timestamp", int(time.time())),
            "alias": alias,
            "is_file": False,
            "is_broadcast": is_bcast
        })

    def _on_file_chunk(self, sender_id: str, meta: dict, data: bytes):
        # Temporary logic to build the file
        fid = meta["file_id"]
        fname = meta["filename"]
        total = meta["total_chunks"]
        idx = meta["chunk_idx"]
        
        if not hasattr(self, "_file_bufs"):
            self._file_bufs = {}
        
        if fid not in self._file_bufs:
            self._file_bufs[fid] = {"chunks": {}, "meta": meta}
        
        self._file_bufs[fid]["chunks"][idx] = data
        
        if len(self._file_bufs[fid]["chunks"]) == total:
            # File finished
            buf = self._file_bufs.pop(fid)
            raw = b"".join(buf["chunks"][i] for i in range(total))
            
            tmp_dir = os.path.join(os.getcwd(), "PLTalk_Downloads")
            os.makedirs(tmp_dir, exist_ok=True)
            tmp_path = os.path.join(tmp_dir, fname)
            
            with open(tmp_path, "wb") as f:
                f.write(raw)
                
            self._emit("file_received", {
                "sender_id": sender_id,
                "file_path": tmp_path,
                "file_name": fname
            })

    def shutdown(self):
        if self._api:
            threading.Thread(target=self._api.stop, daemon=True).start()
        from npcp.config import _cleanup_base
        _cleanup_base()

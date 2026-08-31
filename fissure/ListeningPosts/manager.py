import json
import os
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone

import yaml

import fissure.comms
import fissure.utils
from fissure.utils.common import YAML_DIR

from .common import endpoint_summary, normalize_listening_post_definition
from .factory import create_listening_post_runtime


LISTENING_POSTS_FILENAME = "listening_posts.yaml"
MAX_ACTIVITY_ENTRIES = 100


class ListeningPostManager:
    """Authoritative persisted/runtime state for HIPRFISR-hosted Listening Posts."""

    def __init__(self, component):
        self.component = component
        self.definitions = {}
        self.runtime = {}
        self.last_error = {}
        self.activity = defaultdict(lambda: deque(maxlen=MAX_ACTIVITY_ENTRIES))
        self._load_definitions()

    @property
    def yaml_path(self):
        return os.path.join(YAML_DIR, LISTENING_POSTS_FILENAME)

    def _load_definitions(self):
        os.makedirs(YAML_DIR, exist_ok=True)

        if not os.path.isfile(self.yaml_path):
            self._save_definitions()
            return

        try:
            with open(self.yaml_path, "r", encoding="utf-8") as stream:
                loaded = yaml.safe_load(stream) or {}
        except Exception as exc:
            self.component.logger.error(
                f"Could not load YAML/{LISTENING_POSTS_FILENAME}: {exc}"
            )
            return

        if isinstance(loaded, dict):
            raw_posts = loaded.get("listening_posts", []) or []
        elif isinstance(loaded, list):
            raw_posts = loaded
        else:
            raw_posts = []

        if not isinstance(raw_posts, list):
            self.component.logger.error(
                f"YAML/{LISTENING_POSTS_FILENAME} must contain a listening_posts list."
            )
            return

        changed = False
        seen_names = set()

        for raw_definition in raw_posts:
            try:
                definition = normalize_listening_post_definition(raw_definition)
            except Exception as exc:
                self.component.logger.error(
                    f"Skipping invalid Listening Post definition: {exc}"
                )
                continue

            if not definition["id"]:
                definition["id"] = str(uuid.uuid4())
                changed = True

            name_key = definition["name"].casefold()
            if name_key in seen_names:
                self.component.logger.error(
                    f"Skipping duplicate Listening Post name: {definition['name']}"
                )
                continue

            seen_names.add(name_key)
            self.definitions[definition["id"]] = definition

        if changed:
            self._save_definitions()

    def _save_definitions(self):
        payload = {
            "listening_posts": [
                self.definitions[post_id]
                for post_id in sorted(
                    self.definitions,
                    key=lambda value: self.definitions[value]["name"].casefold(),
                )
            ]
        }

        os.makedirs(YAML_DIR, exist_ok=True)
        temporary_path = self.yaml_path + ".tmp"

        with open(temporary_path, "w", encoding="utf-8") as stream:
            yaml.safe_dump(
                payload,
                stream,
                sort_keys=False,
                default_flow_style=False,
            )

        os.replace(temporary_path, self.yaml_path)

    def _status(self, post_id):
        runtime = self.runtime.get(post_id)
        if runtime is not None and runtime.is_running():
            return "Running"
        if str(self.last_error.get(post_id, "") or "").strip():
            return "Error"
        return "Stopped"

    def _snapshot_post(self, post_id):
        definition = self.definitions.get(post_id)
        if not isinstance(definition, dict):
            return None

        return {
            "id": post_id,
            "name": definition.get("name", ""),
            "type": definition.get("type", ""),
            "host": definition.get("host", "hiprfisr"),
            "autostart": bool(definition.get("autostart", False)),
            "parameters": dict(definition.get("parameters", {}) or {}),
            "endpoint": endpoint_summary(definition),
            "status": self._status(post_id),
            "last_error": str(self.last_error.get(post_id, "") or ""),
            "activity": list(self.activity.get(post_id, [])),
        }

    def snapshot(self):
        posts = []
        for post_id in sorted(
            self.definitions,
            key=lambda value: self.definitions[value]["name"].casefold(),
        ):
            post = self._snapshot_post(post_id)
            if post is not None:
                posts.append(post)
        return posts

    async def notify_dashboard(self, post_id):
        if not getattr(self.component, "dashboard_connected", False):
            return

        post = self._snapshot_post(post_id)
        if post is None:
            return

        msg = {
            fissure.comms.MessageFields.IDENTIFIER:
                self.component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME:
                "listeningPostUpdate",
            fissure.comms.MessageFields.PARAMETERS: {
                "post": post,
            },
        }

        await self.component.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )

    async def record_activity(self, post_id, level, message, notify=True):
        definition = self.definitions.get(post_id, {}) or {}
        post_name = str(definition.get("name", post_id) or post_id)
        level = str(level or "INFO").upper()
        message = str(message or "").strip()

        entry = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "level": level,
            "message": message,
        }
        self.activity[post_id].append(entry)

        runtime = self.runtime.get(post_id)
        if level == "ERROR":
            if runtime is None or not runtime.is_running():
                self.last_error[post_id] = message
        elif runtime is not None and runtime.is_running():
            self.last_error.pop(post_id, None)

        log_message = f"[Listening Post: {post_name}] {message}"
        if level == "ERROR":
            self.component.logger.error(log_message)
        elif level == "WARNING":
            self.component.logger.warning(log_message)
        else:
            self.component.logger.info(log_message)

        if notify:
            await self.notify_dashboard(post_id)

    async def create_or_update(self, definition):
        normalized = normalize_listening_post_definition(definition)
        post_id = normalized.get("id", "")

        if post_id and post_id in self.runtime and self.runtime[post_id].is_running():
            raise RuntimeError("Stop the Listening Post before editing it.")

        if not post_id:
            post_id = str(uuid.uuid4())
            normalized["id"] = post_id
            event_message = "Listening Post created."
        elif post_id not in self.definitions:
            raise RuntimeError("Listening Post no longer exists.")
        else:
            event_message = "Configuration updated."

        name_key = normalized["name"].casefold()
        for existing_id, existing in self.definitions.items():
            if existing_id == post_id:
                continue
            if str(existing.get("name", "") or "").casefold() == name_key:
                raise RuntimeError(
                    f"A Listening Post named '{normalized['name']}' already exists."
                )

        self.definitions[post_id] = normalized
        self.last_error.pop(post_id, None)
        self._save_definitions()
        await self.record_activity(post_id, "INFO", event_message, notify=False)
        return post_id

    async def start(self, post_id, autostart=False):
        definition = self.definitions.get(post_id)
        if not isinstance(definition, dict):
            raise RuntimeError("Listening Post not found.")

        existing = self.runtime.get(post_id)
        if existing is not None and existing.is_running():
            return
        if existing is not None:
            try:
                await existing.stop()
            except Exception:
                pass
            self.runtime.pop(post_id, None)

        self.last_error.pop(post_id, None)
        loop = __import__("asyncio").get_running_loop()

        runtime = create_listening_post_runtime(
            definition["type"],
            component=self.component,
            post_id=post_id,
            name=definition["name"],
            parameters=definition.get("parameters", {}),
            loop=loop,
            message_callback=lambda message, metadata: self.handle_message(
                post_id,
                message,
                metadata,
            ),
            activity_callback=lambda level, message: self.record_activity(
                post_id,
                level,
                message,
            ),
        )

        self.runtime[post_id] = runtime

        try:
            await runtime.start()
        except Exception as exc:
            self.runtime.pop(post_id, None)
            self.last_error[post_id] = str(exc)
            await self.record_activity(
                post_id,
                "ERROR",
                f"Could not start Listening Post: {exc}",
                notify=not autostart,
            )
            raise

        await self.record_activity(
            post_id,
            "INFO",
            "Listening Post started automatically."
            if autostart
            else "Listening Post started.",
            notify=not autostart,
        )

    async def stop(self, post_id, notify=True):
        if post_id not in self.definitions:
            raise RuntimeError("Listening Post not found.")

        runtime = self.runtime.pop(post_id, None)
        if runtime is not None:
            try:
                await runtime.stop()
            except Exception as exc:
                self.last_error[post_id] = str(exc)
                await self.record_activity(
                    post_id,
                    "ERROR",
                    f"Listening Post stop failed: {exc}",
                    notify=notify,
                )
                raise

        self.last_error.pop(post_id, None)
        await self.record_activity(
            post_id,
            "INFO",
            "Listening Post stopped.",
            notify=notify,
        )

    async def delete(self, post_id):
        definition = self.definitions.get(post_id)
        if not isinstance(definition, dict):
            raise RuntimeError("Listening Post not found.")

        runtime = self.runtime.get(post_id)
        if runtime is not None and runtime.is_running():
            raise RuntimeError("Stop the Listening Post before removing it.")

        self.definitions.pop(post_id, None)
        self.runtime.pop(post_id, None)
        self.last_error.pop(post_id, None)
        self.activity.pop(post_id, None)
        self._save_definitions()

    async def clear_activity(self, post_id):
        """Clear the bounded Recent Activity buffer without touching HIPRFISR logs."""
        if post_id not in self.definitions:
            raise RuntimeError("Listening Post not found.")

        self.activity[post_id].clear()

    async def start_autostart(self):
        for post_id, definition in list(self.definitions.items()):
            if not bool(definition.get("autostart", False)):
                continue
            try:
                await self.start(post_id, autostart=True)
            except Exception:
                # start() already records and logs the actual reason.
                pass

    async def shutdown(self):
        for post_id in list(self.runtime.keys()):
            try:
                await self.stop(post_id, notify=False)
            except Exception:
                pass

    async def handle_message(self, post_id, raw_message, metadata=None):
        definition = self.definitions.get(post_id)
        if not isinstance(definition, dict):
            return

        raw_text = str(raw_message or "").strip()
        if not raw_text:
            return

        metadata = dict(metadata or {})
        normalized_text = raw_text.replace("“", '"').replace("”", '"')
        payload = None

        try:
            loaded = json.loads(normalized_text)
            if isinstance(loaded, dict):
                payload = loaded
        except Exception:
            payload = None

        target_id = ""

        if payload is not None:
            target_id = str(payload.get("target_id", "") or "").strip()
            summary = str(
                payload.get("alert_text")
                or payload.get("message")
                or payload.get("status")
                or ""
            ).strip()

            if not summary:
                summary = json.dumps(payload, separators=(",", ":"), default=str)
        else:
            summary = raw_text

        if len(summary) > 500:
            summary = summary[:497] + "..."

        source = str(metadata.get("source", "") or "").strip()
        activity_message = "Message received"
        if source:
            activity_message += f" from {source}"
        if target_id:
            activity_message += f" for target {target_id}"
        activity_message += f": {summary}"

        await self.record_activity(
            post_id,
            "RECV",
            activity_message,
            notify=False,
        )

        await fissure.utils.tak_messages.send(
            self.component,
            {
                "msg_type": "event",
                "uid": f"listening-post-{post_id}-{uuid.uuid4()}",
                "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "tak_icon": "b-t-f-r",
                "alert_kind": "listening_post",
                "alert_summary": f"{definition['name']}: {summary}",
                "suppress_point": True,
            },
        )

        if target_id:
            targets = getattr(self.component, "targets", {}) or {}
            if target_id in targets:
                try:
                    from fissure.callbacks.HiprFisrCallbacks import targetPatch

                    history_entry = {
                        "event": "listening_post",
                        "requester": "HIPRFISR",
                        "listening_post": definition["name"],
                        "summary": summary,
                    }
                    if source:
                        history_entry["source"] = source

                    await targetPatch(
                        self.component,
                        target_id=target_id,
                        patch={},
                        history_entry=history_entry,
                    )
                except Exception as exc:
                    await self.record_activity(
                        post_id,
                        "ERROR",
                        f"Could not update Target history for {target_id}: {exc}",
                        notify=False,
                    )
            else:
                await self.record_activity(
                    post_id,
                    "WARNING",
                    f"Message referenced unknown target_id {target_id}; alert left unassociated.",
                    notify=False,
                )

        await self.notify_dashboard(post_id)

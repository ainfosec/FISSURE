import asyncio

from .base import BaseListeningPost


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, post):
        self.post = post

    def datagram_received(self, data, addr):
        try:
            message = data.decode("utf-8").strip()
        except UnicodeDecodeError:
            message = data.decode("utf-8", errors="replace").strip()

        self.post.emit_message_threadsafe(
            message,
            source=f"{addr[0]}:{addr[1]}",
            transport="UDP",
        )

    def error_received(self, exc):
        if exc:
            self.post.report_activity_threadsafe(
                "ERROR",
                f"UDP transport error: {exc}",
            )


class TCPUDPListeningPost(BaseListeningPost):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.protocol = str(self.parameters.get("protocol", "TCP") or "TCP").upper()
        self.ip_address = str(self.parameters.get("ip_address", "0.0.0.0") or "0.0.0.0")
        self.port = int(self.parameters.get("port", 55555))
        self.server = None
        self.udp_transport = None
        self.client_writers = set()

    async def start(self):
        if self.running:
            return

        if self.protocol == "TCP":
            self.server = await asyncio.start_server(
                self._handle_tcp_connection,
                self.ip_address,
                self.port,
            )
        elif self.protocol == "UDP":
            self.udp_transport, _protocol = await self.loop.create_datagram_endpoint(
                lambda: _UDPProtocol(self),
                local_addr=(self.ip_address, self.port),
            )
        else:
            raise RuntimeError(f"Unsupported TCP/UDP protocol: {self.protocol}")

        self.running = True

    async def stop(self):
        if not self.running and self.server is None and self.udp_transport is None:
            return

        self.running = False

        for writer in list(self.client_writers):
            try:
                writer.close()
                if hasattr(writer, "wait_closed"):
                    await writer.wait_closed()
            except Exception:
                pass
        self.client_writers.clear()

        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

        if self.udp_transport is not None:
            self.udp_transport.close()
            self.udp_transport = None

    async def _handle_tcp_connection(self, reader, writer):
        peer = writer.get_extra_info("peername")
        peer_text = ""
        if isinstance(peer, tuple) and len(peer) >= 2:
            peer_text = f"{peer[0]}:{peer[1]}"

        self.client_writers.add(writer)

        try:
            while self.running:
                data = await reader.readline()
                if not data:
                    break

                try:
                    message = data.decode("utf-8").strip()
                except UnicodeDecodeError:
                    message = data.decode("utf-8", errors="replace").strip()

                if message:
                    await self.emit_message(
                        message,
                        source=peer_text,
                        transport="TCP",
                    )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self.report_activity(
                "ERROR",
                f"TCP client error from {peer_text or 'unknown peer'}: {exc}",
            )
        finally:
            self.client_writers.discard(writer)
            try:
                writer.close()
                if hasattr(writer, "wait_closed"):
                    await writer.wait_closed()
            except Exception:
                pass

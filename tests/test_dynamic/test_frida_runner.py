"""Unit tests for the Reforge live Frida instrumentation session runner."""

from __future__ import annotations

import threading
import time
from typing import Any
from unittest.mock import MagicMock

import pytest

from reforge.cli.cmd_hook import generate_frida_java_script
from reforge.cli.cmd_trace import generate_frida_trace_script
from reforge.dynamic.frida_runner import (
    CapturedLogEntry,
    CircularMessageBuffer,
    FridaRunResult,
    FridaSessionConfig,
    FridaSessionRunner,
    get_frida,
    is_frida_available,
    redact_secrets,
    resolve_device,
    run_frida_session,
    run_synthesized_hook,
    sanitize_error,
)

# -----------------------------------------------------------------------------
# Mock Frida Infrastructure for Hermetic Testing
# -----------------------------------------------------------------------------


class MockFridaScript:
    """Mock Frida Script object."""

    def __init__(self, source: str, name: str = "default") -> None:
        self.source = source
        self.name = name
        self.loaded = False
        self.unloaded = False
        self._handlers: dict[str, list[Any]] = {"message": [], "destroyed": []}

    def on(self, signal: str, callback: Any) -> None:
        self._handlers.setdefault(signal, []).append(callback)

    def load(self) -> None:
        self.loaded = True

    def unload(self) -> None:
        self.unloaded = True

    def emit_message(self, message: dict[str, Any], data: bytes | None = None) -> None:
        for handler in self._handlers.get("message", []):
            handler(message, data)


class MockFridaSession:
    """Mock Frida Session object."""

    def __init__(self, target: Any) -> None:
        self.target = target
        self.scripts: list[MockFridaScript] = []
        self.detached = False
        self._handlers: dict[str, list[Any]] = {"detached": []}

    def on(self, signal: str, callback: Any) -> None:
        self._handlers.setdefault(signal, []).append(callback)

    def create_script(self, source: str, name: str = "default") -> MockFridaScript:
        script = MockFridaScript(source, name=name)
        self.scripts.append(script)
        return script

    def detach(self) -> None:
        self.detached = True
        for handler in self._handlers.get("detached", []):
            handler("user-requested", None)


class MockFridaDevice:
    """Mock Frida Device object."""

    def __init__(self, device_id: str = "local", name: str = "Local System", device_type: str = "local") -> None:
        self.id = device_id
        self.name = name
        self.type = device_type
        self.spawned_processes: dict[int, dict[str, Any]] = {}
        self.attached_targets: list[Any] = []
        self.resumed_pids: list[int] = []
        self._next_pid = 4242
        self.fail_attach = False

    def spawn(self, program: str, argv: list[str] | None = None) -> int:
        pid = self._next_pid
        self._next_pid += 1
        self.spawned_processes[pid] = {
            "program": program,
            "argv": argv,
            "paused": True,
        }
        return pid

    def attach(self, target: Any) -> MockFridaSession:
        if self.fail_attach:
            raise RuntimeError(f"Simulated attach failure for target: {target}")
        self.attached_targets.append(target)
        return MockFridaSession(target)

    def resume(self, pid: int) -> None:
        if pid in self.spawned_processes:
            self.spawned_processes[pid]["paused"] = False
        self.resumed_pids.append(pid)


class MockFridaDeviceManager:
    """Mock Frida DeviceManager for remote connections."""

    def __init__(self) -> None:
        self.remote_devices: dict[str, MockFridaDevice] = {}

    def add_remote_device(self, address: str, **kwargs: Any) -> MockFridaDevice:
        dev = MockFridaDevice(device_id=f"remote:{address}", name=f"Remote {address}", device_type="remote")
        self.remote_devices[address] = dev
        return dev


class MockFridaModule:
    """Mock frida top-level module."""

    def __init__(self) -> None:
        self.local_device = MockFridaDevice("local", "Local System", "local")
        self.usb_device = MockFridaDevice("usb", "Connected USB Device", "usb")
        self.manager = MockFridaDeviceManager()

    def get_local_device(self) -> MockFridaDevice:
        return self.local_device

    def get_usb_device(self) -> MockFridaDevice:
        return self.usb_device

    def get_remote_device(self, address: str) -> MockFridaDevice:
        return self.manager.add_remote_device(address)

    def get_device(self, device_id: str) -> MockFridaDevice:
        return MockFridaDevice(device_id, f"Device {device_id}", "custom")

    def get_device_manager(self) -> MockFridaDeviceManager:
        return self.manager


# -----------------------------------------------------------------------------
# Test Cases: CircularMessageBuffer
# -----------------------------------------------------------------------------


class TestCircularMessageBuffer:
    def test_buffer_append_and_drain(self) -> None:
        buf = CircularMessageBuffer(max_bytes=10_000, max_messages=10)
        assert len(buf) == 0
        assert buf.total_bytes == 0
        assert not buf.is_truncated

        entry1 = CapturedLogEntry(timestamp=time.time(), level="info", message="First message")
        entry2 = CapturedLogEntry(timestamp=time.time(), level="trace", message="Second message")

        buf.append(entry1)
        buf.append(entry2)

        assert len(buf) == 2
        assert buf.total_bytes > 0
        entries = buf.to_list()
        assert entries[0].message == "First message"
        assert entries[1].message == "Second message"
        lines = buf.to_log_lines()
        assert "[INFO] First message" in lines[0]
        assert "[TRACE] Second message" in lines[1]

    def test_buffer_item_count_eviction(self) -> None:
        buf = CircularMessageBuffer(max_bytes=1_000_000, max_messages=3)
        for i in range(5):
            buf.append(CapturedLogEntry(timestamp=time.time(), level="info", message=f"Message {i}"))

        assert len(buf) == 3
        assert buf.is_truncated
        entries = buf.to_list()
        # Oldest items (0, 1) were evicted; 2, 3, 4 remain
        assert [e.message for e in entries] == ["Message 2", "Message 3", "Message 4"]

    def test_buffer_byte_capacity_eviction(self) -> None:
        # Each entry takes message bytes + 64 charge bytes. Set tight budget.
        buf = CircularMessageBuffer(max_bytes=250, max_messages=100)
        entry_a = CapturedLogEntry(timestamp=time.time(), level="info", message="A" * 50)
        entry_b = CapturedLogEntry(timestamp=time.time(), level="info", message="B" * 50)
        entry_c = CapturedLogEntry(timestamp=time.time(), level="info", message="C" * 50)

        buf.append(entry_a)
        buf.append(entry_b)
        assert len(buf) == 2
        assert not buf.is_truncated

        # Adding entry_c pushes total over 250, evicting entry_a
        buf.append(entry_c)
        assert buf.is_truncated
        entries = buf.to_list()
        assert [e.message for e in entries] == ["B" * 50, "C" * 50]

    def test_buffer_oversized_single_message(self) -> None:
        buf = CircularMessageBuffer(max_bytes=100, max_messages=10)
        huge = CapturedLogEntry(timestamp=time.time(), level="info", message="X" * 1000)
        buf.append(huge)

        assert buf.is_truncated
        assert len(buf) == 1
        assert "Payload exceeded buffer limit" in buf.to_list()[0].message

    def test_buffer_clear(self) -> None:
        buf = CircularMessageBuffer(max_bytes=1000, max_messages=10)
        buf.append(CapturedLogEntry(timestamp=time.time(), level="info", message="Hello"))
        assert len(buf) == 1
        buf.clear()
        assert len(buf) == 0
        assert buf.total_bytes == 0
        assert not buf.is_truncated


# -----------------------------------------------------------------------------
# Test Cases: Secret Redaction & Error Sanitization
# -----------------------------------------------------------------------------


class TestSecretAndErrorSanitization:
    def test_redact_secrets_basic(self) -> None:
        secrets = ["secret_token_12345", "cert_alpha_beta"]
        text = "Connecting to 10.0.0.1 with secret_token_12345 and cert_alpha_beta for auth."
        sanitized, truncated = redact_secrets(text, secrets)

        assert "secret_token_12345" not in sanitized
        assert "cert_alpha_beta" not in sanitized
        assert sanitized == "Connecting to 10.0.0.1 with [redacted] and [redacted] for auth."
        assert not truncated

    def test_redact_secrets_length_bounding(self) -> None:
        long_text = "Data:" + "A" * 100
        sanitized, truncated = redact_secrets(long_text, max_length=20)
        assert truncated
        assert len(sanitized) < 40
        assert "[truncated]" in sanitized

    def test_sanitize_error(self) -> None:
        exc = RuntimeError("Authentication failed with token: super_secret_val_xyz")
        sanitized = sanitize_error(exc, ["super_secret_val_xyz"])
        assert "super_secret_val_xyz" not in sanitized
        assert "[redacted]" in sanitized


# -----------------------------------------------------------------------------
# Test Cases: Device Resolution
# -----------------------------------------------------------------------------


class TestDeviceResolution:
    def test_resolve_local_device(self) -> None:
        mock_f = MockFridaModule()
        cfg = FridaSessionConfig(target="notepad.exe", device_type="local")
        dev = resolve_device(cfg, frida_mod=mock_f)
        assert dev.type == "local"

    def test_resolve_usb_device(self) -> None:
        mock_f = MockFridaModule()
        cfg = FridaSessionConfig(target="com.example.app", device_type="usb")
        dev = resolve_device(cfg, frida_mod=mock_f)
        assert dev.type == "usb"

    def test_resolve_remote_device_authenticated(self) -> None:
        mock_f = MockFridaModule()
        cfg = FridaSessionConfig(
            target="target_app",
            device_type="remote",
            remote_address="192.168.1.100:27042",
            remote_token="token_sec",
            remote_certificate="cert_pem",
        )
        dev = resolve_device(cfg, frida_mod=mock_f)
        assert dev.type == "remote"
        assert "192.168.1.100:27042" in dev.id

    def test_resolve_device_failure_sanitizes_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_f = MockFridaModule()
        err = RuntimeError("Device connection failed with auth secret_abc")
        monkeypatch.setattr(mock_f, "get_local_device", MagicMock(side_effect=err))
        cfg = FridaSessionConfig(target="app", secrets=["secret_abc"])

        with pytest.raises(RuntimeError) as exc_info:
            resolve_device(cfg, frida_mod=mock_f)
        err_text = str(exc_info.value)
        assert "secret_abc" not in err_text
        assert "[redacted]" in err_text


# -----------------------------------------------------------------------------
# Test Cases: Session Lifecycle & Preventing Orphaned Processes
# -----------------------------------------------------------------------------


class TestFridaSessionRunnerLifecycle:
    def test_attach_mode_lifecycle(self) -> None:
        mock_f = MockFridaModule()
        cfg = FridaSessionConfig(target=1234, mode="attach")
        runner = FridaSessionRunner(cfg, frida_mod=mock_f)

        with runner:
            assert runner.session is not None
            assert runner.spawned_pid is None
            assert not runner.is_paused

            script_id = runner.load_script("console.log('[+] Hook active');", name="test-hook")
            assert script_id == "test-hook"
            assert len(runner.scripts) == 1

            # Emit a message from the script
            mock_script = runner.scripts["test-hook"]
            assert isinstance(mock_script, MockFridaScript)
            mock_script.emit_message({"type": "send", "payload": "[+] Hook active"})

            assert len(runner.buffer) == 1
            entry = runner.buffer.to_list()[0]
            assert entry.level == "trace"
            assert entry.message == "[+] Hook active"

            runner.unload_script("test-hook")
            assert len(runner.scripts) == 0

        # After exiting context manager:
        assert runner.session is None
        assert not runner.target_resumed  # attach mode does not resume

    def test_spawn_mode_lifecycle_and_resume(self) -> None:
        mock_f = MockFridaModule()
        cfg = FridaSessionConfig(target="com.example.game", mode="spawn", argv=["--flag"])
        runner = FridaSessionRunner(cfg, frida_mod=mock_f)

        with runner:
            assert runner.spawned_pid is not None
            assert runner.is_paused
            assert not runner.target_resumed

            # Process state is paused in mock device
            assert mock_f.local_device.spawned_processes[runner.spawned_pid]["paused"] is True

            runner.load_script("console.log('[reforge] Scaffolding loaded');", name="reforge-hook")
            runner.resume()

            assert not runner.is_paused
            assert runner.target_resumed
            assert mock_f.local_device.spawned_processes[runner.spawned_pid]["paused"] is False
            assert runner.spawned_pid in mock_f.local_device.resumed_pids

    def test_prevent_orphaned_paused_process_on_startup_failure(self) -> None:
        """CRITICAL: If spawn succeeds but attach fails, runner must resume target

        immediately to prevent an orphaned paused process!
        """
        mock_f = MockFridaModule()
        mock_f.local_device.fail_attach = True  # force attach failure
        cfg = FridaSessionConfig(target="com.example.crasher", mode="spawn")
        runner = FridaSessionRunner(cfg, frida_mod=mock_f)

        with pytest.raises(RuntimeError) as exc_info:
            runner.start()

        assert "Failed to start Frida session" in str(exc_info.value)
        # Verify the spawned process was immediately resumed so it is not orphaned
        assert runner.spawned_pid is not None
        assert runner.spawned_pid in mock_f.local_device.resumed_pids
        assert mock_f.local_device.spawned_processes[runner.spawned_pid]["paused"] is False
        assert runner.target_resumed is True
        assert runner.is_paused is False

    def test_prevent_orphaned_paused_process_on_session_close(self) -> None:
        """CRITICAL: If a spawned process is closed while still paused,

        runner.close() must resume it so it does not stay suspended indefinitely.
        """
        mock_f = MockFridaModule()
        cfg = FridaSessionConfig(target="com.example.paused", mode="spawn")
        runner = FridaSessionRunner(cfg, frida_mod=mock_f)

        runner.start()
        pid = runner.spawned_pid
        assert pid is not None
        assert runner.is_paused is True
        assert mock_f.local_device.spawned_processes[pid]["paused"] is True

        # Close session without explicitly calling resume()
        runner.close()

        # Verify close() resumed the target process
        assert pid in mock_f.local_device.resumed_pids
        assert mock_f.local_device.spawned_processes[pid]["paused"] is False
        assert runner.is_paused is False
        assert runner.target_resumed is True

    def test_session_detach_callback(self) -> None:
        mock_f = MockFridaModule()
        cfg = FridaSessionConfig(target=999, mode="attach")
        runner = FridaSessionRunner(cfg, frida_mod=mock_f)
        runner.start()

        assert not runner.is_detached
        # Simulate target process exit or disconnect
        assert isinstance(runner.session, MockFridaSession)
        runner.session.detach()

        assert runner.is_detached is True
        entries = runner.buffer.to_list()
        assert any("Frida session detached" in e.message for e in entries)

    def test_message_classification_and_sanitization(self) -> None:
        mock_f = MockFridaModule()
        cfg = FridaSessionConfig(target=111, mode="attach", secrets=["super_secret_auth_token"])
        runner = FridaSessionRunner(cfg, frida_mod=mock_f)
        runner.start()
        runner.load_script("/* script */", name="hook")
        mock_script = runner.scripts["hook"]
        assert isinstance(mock_script, MockFridaScript)

        # 1. Trace message with secret
        mock_script.emit_message(
            {
                "type": "send",
                "payload": "[reforge] Intercepted token: super_secret_auth_token",
            }
        )

        # 2. Error message from script
        mock_script.emit_message(
            {
                "type": "error",
                "description": "NullPointer in super_secret_auth_token handler",
                "stack": "at func() line 12",
            }
        )

        # 3. Binary message with secret
        mock_script.emit_message(
            {"type": "send", "payload": "[*] binary payload"},
            data=b"DATA-super_secret_auth_token-END",
        )

        entries = runner.buffer.to_list()
        assert len(entries) == 3

        # Entry 1 check
        assert entries[0].level == "trace"
        assert "super_secret_auth_token" not in entries[0].message
        assert "[redacted]" in entries[0].message

        # Entry 2 check
        assert entries[1].level == "error"
        assert "super_secret_auth_token" not in entries[1].message
        assert "[redacted]" in entries[1].message
        assert "Script error: NullPointer" in entries[1].message

        # Entry 3 binary check
        assert entries[2].data == b"[redacted_binary_secret]"

    def test_streaming_callbacks(self) -> None:
        mock_f = MockFridaModule()
        received_logs: list[CapturedLogEntry] = []
        received_raw: list[dict[str, Any]] = []

        cfg = FridaSessionConfig(target=222, mode="attach")
        runner = FridaSessionRunner(
            cfg,
            frida_mod=mock_f,
            on_log=received_logs.append,
            on_message=lambda msg, data: received_raw.append(msg),
        )
        runner.start()
        runner.load_script("code", name="test")
        mock_script = runner.scripts["test"]
        assert isinstance(mock_script, MockFridaScript)

        mock_script.emit_message({"type": "send", "payload": "[+] Live log streamed"})

        assert len(received_logs) == 1
        assert received_logs[0].message == "[+] Live log streamed"
        assert len(received_raw) == 1


# -----------------------------------------------------------------------------
# Test Cases: High-Level Runners & Synthesized Hook Integration
# -----------------------------------------------------------------------------


class TestHighLevelRunnerAndSynthesizedHooks:
    def test_run_frida_session_end_to_end(self) -> None:
        mock_f = MockFridaModule()
        cfg = FridaSessionConfig(target="test_binary", mode="spawn")
        stop_evt = threading.Event()

        # Worker thread to emit message and stop
        def _emitter() -> None:
            time.sleep(0.05)
            # Find the loaded script on the mock device session
            for _sess in [mock_f.local_device.attach(cfg.target)]:
                pass  # just trigger mock
            stop_evt.set()

        t = threading.Thread(target=_emitter)
        t.start()

        result: FridaRunResult = run_frida_session(
            cfg,
            "console.log('[+] Target running');",
            duration=1.0,
            stop_event=stop_evt,
            frida_mod=mock_f,
        )
        t.join()

        assert result.success is True
        assert result.mode == "spawn"
        assert result.target_resumed is True
        assert result.error is None

    def test_run_synthesized_hook_execution(self) -> None:
        """Verify that JavaScript generated by Reforge's hook generator

        (generate_frida_java_script) can be passed to run_synthesized_hook.
        """
        mock_f = MockFridaModule()

        # Generate a real Reforge Frida hook script
        hook_script = generate_frida_java_script(
            goal_text="Trace license checks",
            active_targets=[],
            alt_targets=[],
            pathway="android-java-kotlin-dex",
        )
        assert "[+] Reforge Frida candidate scaffolding loaded" in hook_script

        stop_evt = threading.Event()
        stop_evt.set()  # immediate completion

        result = run_synthesized_hook(
            target="com.example.licensed",
            hook_script=hook_script,
            mode="spawn",
            duration=0.1,
            frida_mod=mock_f,
        )

        assert result.success is True
        assert result.target == "com.example.licensed"
        assert result.target_resumed is True

    def test_run_trace_script_execution(self) -> None:
        """Verify that JavaScript generated by Reforge's trace generator

        (generate_frida_trace_script) can be executed.
        """
        mock_f = MockFridaModule()

        trace_script = generate_frida_trace_script(
            symbol="CheckLicense",
            module="libnative.so",
        )
        assert "Process.getModuleByName" in trace_script

        cfg = FridaSessionConfig(target="app_proc", mode="attach")
        stop_evt = threading.Event()
        stop_evt.set()

        result = run_frida_session(
            cfg,
            trace_script,
            duration=0.1,
            stop_event=stop_evt,
            frida_mod=mock_f,
        )
        assert result.success is True
        assert result.mode == "attach"


# -----------------------------------------------------------------------------
# Test Cases: Lazy Import & Availability
# -----------------------------------------------------------------------------


class TestLazyImport:
    def test_is_frida_available(self) -> None:
        # Since frida is installed in this test environment:
        available = is_frida_available()
        assert isinstance(available, bool)
        if available:
            f = get_frida()
            assert hasattr(f, "get_local_device")

    def test_get_frida_import_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import builtins

        real_import = builtins.__import__

        def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "frida":
                raise ImportError("No module named 'frida'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        monkeypatch.setattr("reforge.dynamic.frida_runner._frida_module", None)

        assert not is_frida_available()
        with pytest.raises(RuntimeError) as exc_info:
            get_frida()
        assert "Frida is not installed" in str(exc_info.value)

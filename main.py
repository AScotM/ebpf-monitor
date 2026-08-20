#!/usr/bin/env python3
"""
eBPF Process Monitor for Fedora 44
Requires: bcc, bcc-tools, python3-bcc, kernel-devel, kernel-headers
"""

import os
import sys
import time
import ctypes
import signal
import logging
import platform
from collections import Counter, deque
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

try:
    from bcc import BPF
except ImportError as exc:
    print(f"ERROR: BCC not installed: {exc}")
    print("Install with: sudo dnf install bcc bcc-tools python3-bcc")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Event:
    pid: int
    uid: int
    comm: str
    filename: str
    ppid: Optional[int] = None
    timestamp: float = field(default_factory=time.time)


@dataclass(slots=True)
class OpenEvent:
    pid: int
    comm: str
    filename: str
    flags: int
    timestamp: float = field(default_factory=time.time)


@dataclass(slots=True)
class Alert:
    pid: int
    comm: str
    filename: str
    reason: str
    timestamp: float = field(default_factory=time.time)


class SystemChecker:
    @staticmethod
    def check_root() -> bool:
        if os.geteuid() != 0:
            logger.error("eBPF requires root privileges")
            logger.info("Run with: sudo python3 %s", sys.argv[0])
            return False
        return True

    @staticmethod
    def check_bcc() -> bool:
        try:
            import bcc

            version = getattr(bcc, "__version__", "unknown")
            logger.info("BCC version: %s", version)
            return True
        except ImportError:
            logger.error("BCC not installed")
            logger.info(
                "Install: sudo dnf install bcc bcc-tools python3-bcc"
            )
            return False

    @staticmethod
    def check_kernel_headers() -> bool:
        kernel = platform.release()

        header_paths = (
            f"/usr/src/kernels/{kernel}",
            f"/lib/modules/{kernel}/build",
        )

        for path in header_paths:
            include_path = os.path.join(path, "include")

            if os.path.exists(path) and os.path.exists(include_path):
                logger.info("Kernel headers found at: %s", path)
                return True

        logger.error("Kernel headers not found")
        logger.info(
            "Install: sudo dnf install kernel-devel kernel-headers"
        )
        logger.info(
            "For exact version: sudo dnf install kernel-devel-%s",
            kernel,
        )

        return False

    @staticmethod
    def check_tracing_filesystem() -> bool:
        for path in (
            "/sys/kernel/tracing",
            "/sys/kernel/debug/tracing",
        ):
            if os.path.isdir(path):
                logger.info(
                    "Tracing filesystem available at: %s",
                    path,
                )
                return True

        logger.error("Tracing filesystem not available")
        logger.info(
            "Mount with: "
            "sudo mount -t tracefs tracefs /sys/kernel/tracing"
        )

        return False

    @staticmethod
    def check_security_settings() -> None:
        checks = {
            "kernel.kptr_restrict": (
                "/proc/sys/kernel/kptr_restrict",
                "Kernel pointer visibility is restricted",
            ),
            "net.core.bpf_jit_harden": (
                "/proc/sys/net/core/bpf_jit_harden",
                "BPF JIT hardening is enabled",
            ),
            "kernel.yama.ptrace_scope": (
                "/proc/sys/kernel/yama/ptrace_scope",
                "Process tracing restrictions are enabled",
            ),
        }

        for name, (path, warning) in checks.items():
            try:
                with open(
                    path,
                    "r",
                    encoding="utf-8",
                ) as handle:
                    value = int(handle.read().strip())

                if value > 0:
                    logger.info(
                        "%s=%d - %s",
                        name,
                        value,
                        warning,
                    )

            except FileNotFoundError:
                continue

            except (
                OSError,
                ValueError,
            ) as exc:
                logger.debug(
                    "Could not read %s: %s",
                    name,
                    exc,
                )

    @classmethod
    def check_all(cls) -> bool:
        logger.info(
            "=== System Environment Check ==="
        )

        checks = (
            (
                cls.check_root,
                "Root privileges",
            ),
            (
                cls.check_bcc,
                "BCC installation",
            ),
            (
                cls.check_kernel_headers,
                "Kernel headers",
            ),
            (
                cls.check_tracing_filesystem,
                "Tracing filesystem",
            ),
        )

        all_passed = True

        for check_func, name in checks:
            if check_func():
                logger.info(
                    "PASSED: %s",
                    name,
                )
            else:
                logger.error(
                    "FAILED: %s",
                    name,
                )
                all_passed = False

        if all_passed:
            cls.check_security_settings()

        return all_passed


class BPFPrograms:
    MINIMAL = r"""
    int hello(void *ctx)
    {
        bpf_trace_printk("Hello from eBPF\n");
        return 0;
    }
    """

    EXECVE_MONITOR = r"""
    #include <uapi/linux/ptrace.h>
    #include <linux/sched.h>

    struct event_t {
        u32 pid;
        u32 uid;
        char comm[TASK_COMM_LEN];
        char filename[256];
    };

    BPF_PERF_OUTPUT(events);

    TRACEPOINT_PROBE(syscalls, sys_enter_execve)
    {
        struct event_t event = {};

        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.uid = bpf_get_current_uid_gid();

        bpf_get_current_comm(
            &event.comm,
            sizeof(event.comm)
        );

        bpf_probe_read_user_str(
            &event.filename,
            sizeof(event.filename),
            (void *)args->filename
        );

        events.perf_submit(
            args,
            &event,
            sizeof(event)
        );

        return 0;
    }
    """

    OPENAT_MONITOR = r"""
    #include <uapi/linux/ptrace.h>
    #include <linux/sched.h>

    struct open_event_t {
        u32 pid;
        char comm[TASK_COMM_LEN];
        char filename[256];
        int flags;
    };

    BPF_PERF_OUTPUT(open_events);

    TRACEPOINT_PROBE(syscalls, sys_enter_openat)
    {
        struct open_event_t event = {};

        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.flags = args->flags;

        bpf_get_current_comm(
            &event.comm,
            sizeof(event.comm)
        );

        bpf_probe_read_user_str(
            &event.filename,
            sizeof(event.filename),
            (void *)args->filename
        );

        open_events.perf_submit(
            args,
            &event,
            sizeof(event)
        );

        return 0;
    }
    """

    @staticmethod
    def execve_with_pid_filter(
        pid: int,
    ) -> str:
        return rf"""
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>

        struct event_t {{
            u32 pid;
            u32 uid;
            char comm[TASK_COMM_LEN];
            char filename[256];
        }};

        BPF_PERF_OUTPUT(events);

        TRACEPOINT_PROBE(
            syscalls,
            sys_enter_execve
        )
        {{
            u32 pid =
                bpf_get_current_pid_tgid() >> 32;

            if (pid != {pid}) {{
                return 0;
            }}

            struct event_t event = {{}};

            event.pid = pid;
            event.uid =
                bpf_get_current_uid_gid();

            bpf_get_current_comm(
                &event.comm,
                sizeof(event.comm)
            );

            bpf_probe_read_user_str(
                &event.filename,
                sizeof(event.filename),
                (void *)args->filename
            );

            events.perf_submit(
                args,
                &event,
                sizeof(event)
            );

            return 0;
        }}
        """


class ProcessMonitor:
    MAX_EVENTS = 10_000
    MAX_OPEN_EVENTS = 10_000
    MAX_ALERTS = 2_000

    def __init__(self) -> None:
        self.bpf: Optional[BPF] = None
        self.running = False

        self.events: deque[Event] = deque(
            maxlen=self.MAX_EVENTS
        )

        self.open_events: deque[OpenEvent] = deque(
            maxlen=self.MAX_OPEN_EVENTS
        )

        self.alerts: deque[Alert] = deque(
            maxlen=self.MAX_ALERTS
        )

        self.event_callbacks: list[
            Callable[[Event], None]
        ] = []

        self.open_callbacks: list[
            Callable[[OpenEvent], None]
        ] = []

        self.alert_callbacks: list[
            Callable[[Alert], None]
        ] = []

        self.total_events = 0
        self.total_open_events = 0
        self.total_alerts = 0

        self.lost_events = 0
        self.lost_open_events = 0

        signal.signal(
            signal.SIGTERM,
            self._signal_handler,
        )

    def _signal_handler(
        self,
        signum,
        frame,
    ) -> None:
        logger.info(
            "Received signal %d",
            signum,
        )

        self.stop()

    @contextmanager
    def _bpf_context(
        self,
        program: str,
    ):
        bpf = None

        try:
            bpf = BPF(
                text=program
            )

            self.bpf = bpf

            yield bpf

        except Exception as exc:
            logger.error(
                "BPF setup failed: %s",
                exc,
            )

            raise

        finally:
            self.running = False
            self.bpf = None

            if bpf is not None:
                try:
                    bpf.cleanup()
                except Exception:
                    pass

    @staticmethod
    def _decode_c_string(
        value: bytes,
    ) -> str:
        return (
            value
            .split(
                b"\0",
                1,
            )[0]
            .decode(
                "utf-8",
                errors="replace",
            )
        )

    @staticmethod
    def _resolve_ppid(
        pid: int,
    ) -> Optional[int]:
        try:
            with open(
                f"/proc/{pid}/status",
                "r",
                encoding="utf-8",
            ) as handle:
                for line in handle:
                    if line.startswith(
                        "PPid:"
                    ):
                        return int(
                            line
                            .split(
                                ":",
                                1,
                            )[1]
                            .strip()
                        )

        except (
            FileNotFoundError,
            ProcessLookupError,
            PermissionError,
            ValueError,
            OSError,
        ):
            return None

        return None

    @staticmethod
    def _safe_callback(
        callback: Callable,
        payload,
        callback_type: str,
    ) -> None:
        try:
            callback(
                payload
            )

        except Exception:
            logger.exception(
                "%s callback failed",
                callback_type,
            )

    def _handle_lost_exec_events(
        self,
        cpu: int,
        count: int,
    ) -> None:
        self.lost_events += count

        logger.warning(
            "Lost %d exec event(s) on CPU %d",
            count,
            cpu,
        )

    def _handle_lost_open_events(
        self,
        cpu: int,
        count: int,
    ) -> None:
        self.lost_open_events += count

        logger.warning(
            "Lost %d open event(s) on CPU %d",
            count,
            cpu,
        )

    def run_minimal(
        self,
    ) -> bool:
        try:
            with self._bpf_context(
                BPFPrograms.MINIMAL
            ) as bpf:
                candidates = (
                    "__x64_sys_getpid",
                    "__ia32_sys_getpid",
                    "sys_getpid",
                )

                attached = False

                for event in candidates:
                    try:
                        bpf.attach_kprobe(
                            event=event,
                            fn_name="hello",
                        )

                        logger.info(
                            "Attached to kprobe: %s",
                            event,
                        )

                        attached = True
                        break

                    except Exception:
                        continue

                if not attached:
                    logger.error(
                        "Failed to attach minimal "
                        "test kprobe"
                    )

                    return False

                logger.info(
                    "Minimal BPF program loaded"
                )

                logger.info(
                    "Use getpid from another shell "
                    "to generate events"
                )

                logger.info(
                    "Trace output: "
                    "/sys/kernel/tracing/trace_pipe"
                )

                logger.info(
                    "Press Ctrl+C to stop"
                )

                self.running = True

                while self.running:
                    try:
                        time.sleep(
                            1
                        )

                    except KeyboardInterrupt:
                        self.stop()

                return True

        except Exception as exc:
            logger.error(
                "Minimal test failed: %s",
                exc,
            )

            return False

    def _run_exec_monitor(
        self,
        program: str,
        event_handler: Callable[
            [Event],
            None,
        ],
        label: str,
    ) -> bool:
        class EventStruct(
            ctypes.Structure
        ):
            _fields_ = [
                (
                    "pid",
                    ctypes.c_uint32,
                ),
                (
                    "uid",
                    ctypes.c_uint32,
                ),
                (
                    "comm",
                    ctypes.c_char * 16,
                ),
                (
                    "filename",
                    ctypes.c_char * 256,
                ),
            ]

        try:
            with self._bpf_context(
                program
            ) as bpf:

                def handle_event(
                    cpu,
                    data,
                    size,
                ) -> None:
                    raw = ctypes.cast(
                        data,
                        ctypes.POINTER(
                            EventStruct
                        ),
                    ).contents

                    event = Event(
                        pid=int(
                            raw.pid
                        ),
                        uid=int(
                            raw.uid
                        ),
                        comm=self._decode_c_string(
                            bytes(
                                raw.comm
                            )
                        ),
                        filename=self._decode_c_string(
                            bytes(
                                raw.filename
                            )
                        ),
                        ppid=self._resolve_ppid(
                            int(
                                raw.pid
                            )
                        ),
                    )

                    event_handler(
                        event
                    )

                bpf[
                    "events"
                ].open_perf_buffer(
                    handle_event,
                    lost_cb=(
                        self
                        ._handle_lost_exec_events
                    ),
                )

                logger.info(
                    "%s",
                    label,
                )

                logger.info(
                    "Press Ctrl+C to stop"
                )

                self.running = True

                while self.running:
                    try:
                        bpf.perf_buffer_poll(
                            timeout=100
                        )

                    except KeyboardInterrupt:
                        self.stop()

                return True

        except Exception as exc:
            logger.error(
                "%s failed: %s",
                label,
                exc,
            )

            return False

    def _record_exec_event(
        self,
        event: Event,
    ) -> None:
        self.events.append(
            event
        )

        self.total_events += 1

        for callback in self.event_callbacks:
            self._safe_callback(
                callback,
                event,
                "Event",
            )

        ppid = (
            str(
                event.ppid
            )
            if event.ppid is not None
            else "?"
        )

        timestamp = (
            datetime
            .fromtimestamp(
                event.timestamp
            )
            .strftime(
                "%H:%M:%S"
            )
        )

        print(
            f"[{timestamp}] "
            f"PID: {event.pid:6d} "
            f"PPID: {ppid:>6s} "
            f"UID: {event.uid:5d} "
            f"COMM: {event.comm[:15]:15s} "
            f"FILE: {event.filename}"
        )

    def monitor_execve(
        self,
    ) -> bool:
        return self._run_exec_monitor(
            BPFPrograms.EXECVE_MONITOR,
            self._record_exec_event,
            "Monitoring process executions",
        )

    def monitor_with_pid_filter(
        self,
        target_pid: int,
    ) -> bool:
        if target_pid <= 0:
            logger.error(
                "PID must be greater than zero"
            )

            return False

        if not os.path.exists(
            f"/proc/{target_pid}"
        ):
            logger.warning(
                "PID %d does not currently exist",
                target_pid,
            )

        return self._run_exec_monitor(
            BPFPrograms.execve_with_pid_filter(
                target_pid
            ),
            self._record_exec_event,
            (
                "Monitoring execve calls "
                f"for PID {target_pid}"
            ),
        )

    def monitor_opens(
        self,
    ) -> bool:
        class OpenEventStruct(
            ctypes.Structure
        ):
            _fields_ = [
                (
                    "pid",
                    ctypes.c_uint32,
                ),
                (
                    "comm",
                    ctypes.c_char * 16,
                ),
                (
                    "filename",
                    ctypes.c_char * 256,
                ),
                (
                    "flags",
                    ctypes.c_int,
                ),
            ]

        try:
            with self._bpf_context(
                BPFPrograms.OPENAT_MONITOR
            ) as bpf:

                def handle_open(
                    cpu,
                    data,
                    size,
                ) -> None:
                    raw = ctypes.cast(
                        data,
                        ctypes.POINTER(
                            OpenEventStruct
                        ),
                    ).contents

                    event = OpenEvent(
                        pid=int(
                            raw.pid
                        ),
                        comm=self._decode_c_string(
                            bytes(
                                raw.comm
                            )
                        ),
                        filename=self._decode_c_string(
                            bytes(
                                raw.filename
                            )
                        ),
                        flags=int(
                            raw.flags
                        ),
                    )

                    self.open_events.append(
                        event
                    )

                    self.total_open_events += 1

                    for callback in self.open_callbacks:
                        self._safe_callback(
                            callback,
                            event,
                            "Open",
                        )

                    timestamp = (
                        datetime
                        .fromtimestamp(
                            event.timestamp
                        )
                        .strftime(
                            "%H:%M:%S"
                        )
                    )

                    print(
                        f"[{timestamp}] "
                        f"PID: {event.pid:6d} "
                        f"COMM: "
                        f"{event.comm[:15]:15s} "
                        f"FLAGS: "
                        f"{event.flags:#x} "
                        f"FILE: "
                        f"{event.filename}"
                    )

                bpf[
                    "open_events"
                ].open_perf_buffer(
                    handle_open,
                    lost_cb=(
                        self
                        ._handle_lost_open_events
                    ),
                )

                logger.info(
                    "Monitoring openat "
                    "file operations"
                )

                logger.info(
                    "Press Ctrl+C to stop"
                )

                self.running = True

                while self.running:
                    try:
                        bpf.perf_buffer_poll(
                            timeout=100
                        )

                    except KeyboardInterrupt:
                        self.stop()

                return True

        except Exception as exc:
            logger.error(
                "File-open monitor failed: %s",
                exc,
            )

            return False

    def register_event_callback(
        self,
        callback: Callable[
            [Event],
            None,
        ],
    ) -> None:
        self.event_callbacks.append(
            callback
        )

    def register_open_callback(
        self,
        callback: Callable[
            [OpenEvent],
            None,
        ],
    ) -> None:
        self.open_callbacks.append(
            callback
        )

    def register_alert_callback(
        self,
        callback: Callable[
            [Alert],
            None,
        ],
    ) -> None:
        self.alert_callbacks.append(
            callback
        )

    def stop(
        self,
    ) -> None:
        if self.running:
            logger.info(
                "Stopping monitor"
            )

        self.running = False


class SecurityMonitor(
    ProcessMonitor
):
    def __init__(
        self,
    ) -> None:
        super().__init__()

        self.suspicious_patterns = (
            "nc",
            "nmap",
            "masscan",
            "hydra",
            "metasploit",
            "msfconsole",
            "john",
            "hashcat",
            "netcat",
            "scan",
            "exploit",
            "burp",
            "sqlmap",
            "nikto",
            "wpscan",
            "aircrack",
            "reaver",
            "ettercap",
            "wireshark",
            "tcpdump",
        )

    def _find_suspicious_pattern(
        self,
        event: Event,
    ) -> Optional[str]:
        comm = event.comm.casefold()
        filename = event.filename.casefold()

        basename = os.path.basename(
            filename
        )

        for pattern in self.suspicious_patterns:
            needle = pattern.casefold()

            if (
                needle in comm
                or needle in basename
            ):
                return pattern

        return None

    def _handle_security_event(
        self,
        event: Event,
    ) -> None:
        self.events.append(
            event
        )

        self.total_events += 1

        for callback in self.event_callbacks:
            self._safe_callback(
                callback,
                event,
                "Event",
            )

        matched_pattern = (
            self
            ._find_suspicious_pattern(
                event
            )
        )

        if matched_pattern is None:
            return

        alert = Alert(
            pid=event.pid,
            comm=event.comm,
            filename=event.filename,
            reason=(
                "Suspicious pattern: "
                f"{matched_pattern}"
            ),
        )

        self.alerts.append(
            alert
        )

        self.total_alerts += 1

        for callback in self.alert_callbacks:
            self._safe_callback(
                callback,
                alert,
                "Alert",
            )

        timestamp = (
            datetime
            .fromtimestamp(
                alert.timestamp
            )
            .strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        print()
        print(
            "=" * 70
        )

        print(
            f"[ALERT #{self.total_alerts}] "
            f"{timestamp}"
        )

        print(
            f"Process: {alert.comm} "
            f"(PID: {alert.pid})"
        )

        print(
            f"Reason:  {alert.reason}"
        )

        print(
            f"File:    {alert.filename}"
        )

        print(
            "=" * 70
        )

        print()

    def monitor_suspicious(
        self,
    ) -> bool:
        return self._run_exec_monitor(
            BPFPrograms.EXECVE_MONITOR,
            self._handle_security_event,
            "Security monitor active",
        )

    def print_report(
        self,
    ) -> None:
        print()

        print(
            "=" * 70
        )

        print(
            "SECURITY REPORT"
        )

        print(
            "=" * 70
        )

        print(
            "Exec events captured: "
            f"{self.total_events}"
        )

        print(
            "Open events captured: "
            f"{self.total_open_events}"
        )

        print(
            "Alerts triggered: "
            f"{self.total_alerts}"
        )

        print(
            "Lost exec events: "
            f"{self.lost_events}"
        )

        print(
            "Lost open events: "
            f"{self.lost_open_events}"
        )

        print(
            "Exec events retained: "
            f"{len(self.events)}"
        )

        print(
            "Open events retained: "
            f"{len(self.open_events)}"
        )

        print(
            "Alerts retained: "
            f"{len(self.alerts)}"
        )

        if not self.alerts:
            print(
                "No retained security alerts"
            )

            print(
                "=" * 70
            )

            return

        process_counts = Counter(
            alert.comm
            for alert in self.alerts
        )

        print()

        print(
            "Unique suspicious processes: "
            f"{len(process_counts)}"
        )

        print(
            "Unique suspicious files: "
            f"{len({
                alert.filename
                for alert in self.alerts
            })}"
        )

        print()

        print(
            "Top suspicious processes:"
        )

        for comm, count in (
            process_counts
            .most_common(
                10
            )
        ):
            print(
                f"  {comm:15s} "
                f"{count:6d}"
            )

        print()

        print(
            "Recent alerts:"
        )

        for alert in list(
            self.alerts
        )[-10:]:
            timestamp = (
                datetime
                .fromtimestamp(
                    alert.timestamp
                )
                .strftime(
                    "%H:%M:%S"
                )
            )

            print(
                f"  {timestamp} "
                f"{alert.comm:15s} "
                f"PID={alert.pid:<7d} "
                f"{alert.reason}"
            )

        print(
            "=" * 70
        )


def print_statistics(
    monitor: SecurityMonitor,
) -> None:
    print()

    print(
        "STATISTICS"
    )

    print(
        "-" * 70
    )

    print(
        "Exec events captured: "
        f"{monitor.total_events}"
    )

    print(
        "Open events captured: "
        f"{monitor.total_open_events}"
    )

    print(
        "Alerts triggered: "
        f"{monitor.total_alerts}"
    )

    print(
        "Lost exec events: "
        f"{monitor.lost_events}"
    )

    print(
        "Lost open events: "
        f"{monitor.lost_open_events}"
    )

    print(
        "Exec events retained: "
        f"{len(monitor.events)}"
    )

    print(
        "Open events retained: "
        f"{len(monitor.open_events)}"
    )

    print(
        "Alerts retained: "
        f"{len(monitor.alerts)}"
    )

    if monitor.alerts:
        counts = Counter(
            alert.comm
            for alert in monitor.alerts
        )

        print()

        print(
            "Top suspicious processes:"
        )

        for comm, count in (
            counts
            .most_common(
                5
            )
        ):
            print(
                f"  {comm:15s}: "
                f"{count}"
            )


def main() -> None:
    print(
        "=" * 70
    )

    print(
        "eBPF Process Monitor for Fedora 44"
    )

    print(
        "=" * 70
    )

    print()

    if not SystemChecker.check_all():
        logger.error(
            "Environment check failed. "
            "Fix the reported issues "
            "and try again."
        )

        sys.exit(
            1
        )

    monitor = SecurityMonitor()

    while True:
        print()

        print(
            "=" * 70
        )

        print(
            "MAIN MENU"
        )

        print(
            "=" * 70
        )

        print(
            "  1. Minimal test"
        )

        print(
            "  2. Monitor process executions"
        )

        print(
            "  3. Monitor file opens"
        )

        print(
            "  4. Monitor specific PID"
        )

        print(
            "  5. Security monitor"
        )

        print(
            "  6. Show statistics"
        )

        print(
            "  7. Show security report"
        )

        print(
            "  8. Exit"
        )

        print(
            "=" * 70
        )

        try:
            choice = input(
                "Select option [1-8]: "
            ).strip()

            if choice == "1":
                monitor.run_minimal()

            elif choice == "2":
                monitor.monitor_execve()

            elif choice == "3":
                monitor.monitor_opens()

            elif choice == "4":
                try:
                    target_pid = int(
                        input(
                            "Enter PID "
                            "to monitor: "
                        ).strip()
                    )

                except ValueError:
                    logger.error(
                        "Invalid PID"
                    )

                    continue

                monitor.monitor_with_pid_filter(
                    target_pid
                )

            elif choice == "5":
                monitor.monitor_suspicious()

            elif choice == "6":
                print_statistics(
                    monitor
                )

                input(
                    "Press Enter to continue..."
                )

            elif choice == "7":
                monitor.print_report()

                input(
                    "Press Enter to continue..."
                )

            elif choice == "8":
                print(
                    "Exiting..."
                )

                if monitor.total_alerts:
                    monitor.print_report()

                return

            else:
                logger.error(
                    "Invalid choice. Select 1-8"
                )

        except KeyboardInterrupt:
            print()
            print(
                "Exiting..."
            )
            return

        except EOFError:
            print()
            print(
                "Exiting..."
            )
            return

        except Exception:
            logger.exception(
                "Unexpected error"
            )


if __name__ == "__main__":
    main()


import argparse
import ctypes
import json
import os
import platform
import signal
import sys
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_PATTERNS = (
    "aircrack-ng",
    "ettercap",
    "hashcat",
    "hydra",
    "john",
    "masscan",
    "msfconsole",
    "nc",
    "netcat",
    "nikto",
    "nmap",
    "reaver",
    "sqlmap",
    "tcpdump",
    "tshark",
    "wireshark",
    "wpscan",
)


class ExecEventStruct(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
    ]


class OpenEventStruct(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("flags", ctypes.c_int32),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
    ]


@dataclass(slots=True)
class Event:
    timestamp: str
    kind: str
    pid: int
    tid: int
    uid: int
    comm: str
    filename: str
    ppid: int | None = None
    flags: int | None = None
    alert: str | None = None


class Output:
    def __init__(self, mode, output_file=None):
        self.mode = mode
        self.handle = None

        if output_file:
            self.handle = open(
                output_file,
                "a",
                encoding="utf-8",
                buffering=1,
            )

    def write(self, payload):
        if self.mode == "json":
            line = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        else:
            line = self.format_text(payload)

        print(line, flush=True)

        if self.handle:
            self.handle.write(
                json.dumps(
                    payload,
                    ensure_ascii=False,
                ) + "\n"
            )

    @staticmethod
    def format_text(payload):
        kind = payload.get("kind", "unknown")
        timestamp = payload.get("timestamp", "")
        pid = payload.get("pid", 0)
        tid = payload.get("tid", 0)
        uid = payload.get("uid", 0)
        comm = payload.get("comm", "")
        filename = payload.get("filename", "")

        parts = [
            f"[{timestamp}]",
            f"{kind.upper():8}",
            f"PID={pid:<7}",
            f"TID={tid:<7}",
            f"UID={uid:<6}",
            f"COMM={comm:<16}",
        ]

        if payload.get("ppid") is not None:
            parts.append(f"PPID={payload['ppid']}")

        if payload.get("flags") is not None:
            parts.append(f"FLAGS={payload['flags']:#x}")

        parts.append(f"FILE={filename}")

        if payload.get("alert"):
            parts.append(f"ALERT={payload['alert']}")

        return " ".join(parts)

    def close(self):
        if self.handle:
            self.handle.close()
            self.handle = None


class Statistics:
    def __init__(self, history_size):
        self.started = time.monotonic()
        self.exec_events = 0
        self.open_events = 0
        self.alerts = 0
        self.lost_events = 0
        self.history = deque(maxlen=history_size)
        self.process_counts = Counter()
        self.alert_counts = Counter()

    def record(self, event):
        if event.kind == "exec":
            self.exec_events += 1
        elif event.kind == "open":
            self.open_events += 1

        if event.alert:
            self.alerts += 1
            self.alert_counts[event.alert] += 1

        self.process_counts[event.comm] += 1
        self.history.append(event)

    def report(self):
        return {
            "kind": "statistics",
            "timestamp": utc_now(),
            "uptime_seconds": round(
                time.monotonic() - self.started,
                2,
            ),
            "exec_events": self.exec_events,
            "open_events": self.open_events,
            "alerts": self.alerts,
            "lost_events": self.lost_events,
            "retained_events": len(self.history),
            "top_processes": self.process_counts.most_common(10),
            "alert_patterns": self.alert_counts.most_common(10),
        }


class Environment:
    @staticmethod
    def inspect():
        kernel = platform.release()

        checks = {
            "platform": platform.system(),
            "kernel": kernel,
            "root": os.geteuid() == 0,
            "bcc": False,
            "bcc_error": None,
            "tracefs": False,
            "tracefs_path": None,
            "kernel_devel": False,
            "kernel_devel_path": None,
            "bpf_filesystem": Path("/sys/fs/bpf").is_dir(),
        }

        try:
            from bcc import BPF
            checks["bcc"] = True
            checks["bcc_class"] = BPF.__name__
        except Exception as exc:
            checks["bcc_error"] = str(exc)

        for path in (
            "/sys/kernel/tracing",
            "/sys/kernel/debug/tracing",
        ):
            if (
                Path(path).is_dir()
                and Path(path, "events").is_dir()
            ):
                checks["tracefs"] = True
                checks["tracefs_path"] = path
                break

        for path in (
            f"/usr/src/kernels/{kernel}",
            f"/lib/modules/{kernel}/build",
        ):
            if Path(path, "include").is_dir():
                checks["kernel_devel"] = True
                checks["kernel_devel_path"] = path
                break

        return checks

    @staticmethod
    def print_report(mode):
        result = Environment.inspect()

        if mode == "json":
            print(json.dumps(result, indent=2))
        else:
            print("eBPF Monitor Environment")
            print("-" * 48)

            for key, value in result.items():
                print(f"{key:22}: {value}")

            print()
            print("Required for tracing: root and BCC")
            print("Kernel development files may be needed")
            print("depending on the BCC and kernel configuration.")

        return result


class BPFPrograms:
    HEADER = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 uid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

struct open_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 uid;
    s32 flags;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(open_events);
"""

    EXEC = r"""
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;

    if (TARGET_PID != 0 && pid != TARGET_PID) {
        return 0;
    }

    struct exec_event_t event = {};

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = pid;
    event.tid = tid;
    event.uid = (u32)bpf_get_current_uid_gid();

    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task();

    event.ppid = 0;

    bpf_probe_read_kernel(
        &event.ppid,
        sizeof(event.ppid),
        &task->real_parent->tgid
    );

    bpf_get_current_comm(
        &event.comm,
        sizeof(event.comm)
    );

    bpf_probe_read_user_str(
        &event.filename,
        sizeof(event.filename),
        (void *)args->filename
    );

    exec_events.perf_submit(
        args,
        &event,
        sizeof(event)
    );

    return 0;
}
"""

    OPEN = r"""
TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;

    if (TARGET_PID != 0 && pid != TARGET_PID) {
        return 0;
    }

    struct open_event_t event = {};

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = pid;
    event.tid = tid;
    event.uid = (u32)bpf_get_current_uid_gid();
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

    @classmethod
    def build(cls, monitor_exec, monitor_open, pid):
        program = cls.HEADER

        if monitor_exec:
            program += cls.EXEC

        if monitor_open:
            program += cls.OPEN

        return program.replace(
            "TARGET_PID",
            str(pid or 0),
        )


class Monitor:
    def __init__(self, args):
        self.args = args
        self.running = False
        self.bpf = None
        self.output = Output(
            args.format,
            args.output,
        )
        self.stats = Statistics(args.history)
        self.patterns = self.load_patterns()
        self.start_wall_ns = time.time_ns()
        self.start_monotonic_ns = time.monotonic_ns()
        self.last_report = time.monotonic()

    def load_patterns(self):
        patterns = set()

        if self.args.command == "security":
            patterns.update(DEFAULT_PATTERNS)

        for item in self.args.pattern:
            value = item.strip().casefold()

            if value:
                patterns.add(value)

        if self.args.pattern_file:
            with open(
                self.args.pattern_file,
                "r",
                encoding="utf-8",
            ) as handle:
                for line in handle:
                    value = line.strip().casefold()

                    if value:
                        patterns.add(value)

        return patterns

    def timestamp_from_kernel(self, kernel_ns):
        wall_ns = (
            self.start_wall_ns
            + kernel_ns
            - self.start_monotonic_ns
        )

        return datetime.fromtimestamp(
            wall_ns / 1_000_000_000,
            timezone.utc,
        ).isoformat(timespec="milliseconds")

    @staticmethod
    def decode(value):
        return bytes(value).split(
            b"\0",
            1,
        )[0].decode(
            "utf-8",
            errors="replace",
        )

    def detect_alert(self, filename):
        basename = os.path.basename(filename).casefold()

        if basename in self.patterns:
            return f"executable:{basename}"

        return None

    def emit_event(self, event):
        self.stats.record(event)
        self.output.write(asdict(event))

    def handle_exec(self, cpu, data, size):
        if size < ctypes.sizeof(ExecEventStruct):
            return

        raw = ctypes.cast(
            data,
            ctypes.POINTER(ExecEventStruct),
        ).contents

        filename = self.decode(raw.filename)

        event = Event(
            timestamp=self.timestamp_from_kernel(
                raw.timestamp_ns
            ),
            kind="exec",
            pid=int(raw.pid),
            tid=int(raw.tid),
            uid=int(raw.uid),
            ppid=int(raw.ppid),
            comm=self.decode(raw.comm),
            filename=filename,
            alert=self.detect_alert(filename),
        )

        if (
            self.args.command == "security"
            and not event.alert
            and not self.args.show_all
        ):
            self.stats.record(event)
            return

        self.emit_event(event)

    def handle_open(self, cpu, data, size):
        if size < ctypes.sizeof(OpenEventStruct):
            return

        raw = ctypes.cast(
            data,
            ctypes.POINTER(OpenEventStruct),
        ).contents

        event = Event(
            timestamp=self.timestamp_from_kernel(
                raw.timestamp_ns
            ),
            kind="open",
            pid=int(raw.pid),
            tid=int(raw.tid),
            uid=int(raw.uid),
            comm=self.decode(raw.comm),
            filename=self.decode(raw.filename),
            flags=int(raw.flags),
        )

        self.emit_event(event)

    def handle_lost(self, cpu, count):
        self.stats.lost_events += count

        self.output.write({
            "kind": "lost",
            "timestamp": utc_now(),
            "cpu": cpu,
            "count": count,
        })

    def stop(self, signum=None, frame=None):
        self.running = False

    def print_statistics(self):
        report = self.stats.report()

        if self.args.format == "json":
            self.output.write(report)
            return

        print()
        print("eBPF Monitor Statistics")
        print("-" * 48)
        print(f"Uptime:          {report['uptime_seconds']} s")
        print(f"Exec events:     {report['exec_events']}")
        print(f"Open events:     {report['open_events']}")
        print(f"Alerts:          {report['alerts']}")
        print(f"Lost events:     {report['lost_events']}")
        print(f"Retained events: {report['retained_events']}")

        if report["top_processes"]:
            print()
            print("Top processes:")

            for name, count in report["top_processes"]:
                print(f"  {name:20} {count:8}")

        if report["alert_patterns"]:
            print()
            print("Alert patterns:")

            for name, count in report["alert_patterns"]:
                print(f"  {name:20} {count:8}")

    def run(self):
        if os.geteuid() != 0:
            raise RuntimeError(
                "Root privileges are required for BCC tracing"
            )

        try:
            from bcc import BPF
        except ImportError as exc:
            raise RuntimeError(
                "BCC Python bindings are unavailable. "
                "Install python3-bcc and bcc."
            ) from exc

        monitor_exec = self.args.command in (
            "exec",
            "security",
            "all",
        )

        monitor_open = self.args.command in (
            "open",
            "all",
        )

        program = BPFPrograms.build(
            monitor_exec,
            monitor_open,
            self.args.pid,
        )

        previous_sigint = signal.getsignal(signal.SIGINT)
        previous_sigterm = signal.getsignal(signal.SIGTERM)

        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)

        try:
            self.bpf = BPF(text=program)

            if monitor_exec:
                self.bpf[
                    "exec_events"
                ].open_perf_buffer(
                    self.handle_exec,
                    page_cnt=self.args.pages,
                    lost_cb=self.handle_lost,
                )

            if monitor_open:
                self.bpf[
                    "open_events"
                ].open_perf_buffer(
                    self.handle_open,
                    page_cnt=self.args.pages,
                    lost_cb=self.handle_lost,
                )

            self.running = True

            if self.args.format == "text":
                print(
                    f"eBPF Monitor v2.0 | "
                    f"Mode: {self.args.command} | "
                    f"Kernel: {platform.release()}"
                )

                if self.args.pid:
                    print(f"PID filter: {self.args.pid}")

                print("Press Ctrl+C to stop.")
                print()

            while self.running:
                self.bpf.perf_buffer_poll(timeout=200)

                now = time.monotonic()

                if (
                    self.args.interval > 0
                    and now - self.last_report
                    >= self.args.interval
                ):
                    self.print_statistics()
                    self.last_report = now

                if (
                    self.args.duration > 0
                    and now - self.stats.started
                    >= self.args.duration
                ):
                    self.running = False

        finally:
            self.running = False

            try:
                self.print_statistics()
            finally:
                if self.bpf is not None:
                    self.bpf.cleanup()
                    self.bpf = None

                self.output.close()

                signal.signal(
                    signal.SIGINT,
                    previous_sigint,
                )

                signal.signal(
                    signal.SIGTERM,
                    previous_sigterm,
                )


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat(timespec="milliseconds")


def positive_int(value):
    number = int(value)

    if number < 1:
        raise argparse.ArgumentTypeError(
            "Value must be greater than zero"
        )

    return number


def nonnegative_float(value):
    number = float(value)

    if number < 0:
        raise argparse.ArgumentTypeError(
            "Value cannot be negative"
        )

    return number


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ebpf-monitor",
        description=(
            "Linux process and file activity monitor "
            "using BCC and eBPF"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers.add_parser(
        "check",
        help="Inspect the eBPF environment",
    )

    for command, description in (
        ("exec", "Monitor process execution attempts"),
        ("open", "Monitor openat file operations"),
        ("all", "Monitor execution and file operations"),
        ("security", "Monitor selected executable names"),
    ):
        sub = subparsers.add_parser(
            command,
            help=description,
        )

        sub.add_argument(
            "--pid",
            type=positive_int,
            default=0,
            help="Filter events by process ID",
        )

        sub.add_argument(
            "--format",
            choices=("text", "json"),
            default="text",
            help="Output format",
        )

        sub.add_argument(
            "--output",
            help="Append JSON Lines events to a file",
        )

        sub.add_argument(
            "--duration",
            type=nonnegative_float,
            default=0,
            help="Stop after this many seconds",
        )

        sub.add_argument(
            "--interval",
            type=nonnegative_float,
            default=0,
            help="Periodic statistics interval",
        )

        sub.add_argument(
            "--history",
            type=positive_int,
            default=10000,
            help="Maximum retained events",
        )

        sub.add_argument(
            "--pages",
            type=positive_int,
            default=64,
            help="Perf buffer page count",
        )

        sub.add_argument(
            "--pattern",
            action="append",
            default=[],
            help="Exact executable name to flag",
        )

        sub.add_argument(
            "--pattern-file",
            help="File containing executable names",
        )

        sub.add_argument(
            "--show-all",
            action="store_true",
            help="Show non-alert execution events in security mode",
        )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "check":
        Environment.print_report("text")
        return 0

    monitor = None

    try:
        monitor = Monitor(args)
        monitor.run()
        return 0

    except (OSError, RuntimeError, ValueError) as exc:
        print(
            f"Error: {exc}",
            file=sys.stderr,
        )
        return 1

    except KeyboardInterrupt:
        return 130

    except Exception as exc:
        print(
            f"Unexpected error: {exc}",
            file=sys.stderr,
        )
        return 1

    finally:
        if monitor is not None:
            monitor.output.close()


if __name__ == "__main__":
    sys.exit(main())

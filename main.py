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
import subprocess
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from contextlib import contextmanager

try:
    from bcc import BPF
except ImportError as e:
    print(f"ERROR: BCC not installed: {e}")
    print("Install with: sudo dnf install bcc bcc-tools python3-bcc")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass
class Event:
    """Base event structure"""
    pid: int
    ppid: int
    uid: int
    comm: str
    filename: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class Alert:
    """Security alert structure"""
    pid: int
    comm: str
    filename: str
    reason: str
    timestamp: float = field(default_factory=time.time)


class SystemChecker:
    """System environment checker for eBPF"""
    
    @staticmethod
    def check_root() -> bool:
        """Check if running as root"""
        if os.geteuid() != 0:
            logger.error("eBPF requires root privileges")
            logger.info("Run with: sudo python3 %s", sys.argv[0])
            return False
        return True
    
    @staticmethod
    def check_bcc() -> bool:
        """Check BCC installation"""
        try:
            import bcc
            version = getattr(bcc, '__version__', 'unknown')
            logger.info("BCC version: %s", version)
            return True
        except ImportError:
            logger.error("BCC not installed")
            logger.info("Install: sudo dnf install bcc bcc-tools python3-bcc")
            return False
    
    @staticmethod
    def check_kernel_headers() -> bool:
        """Check kernel headers availability"""
        kernel = platform.release()
        header_paths = [
            f"/usr/src/kernels/{kernel}",
            f"/lib/modules/{kernel}/build"
        ]
        
        for path in header_paths:
            if os.path.exists(path) and os.path.exists(os.path.join(path, "include")):
                logger.info("Kernel headers found at: %s", path)
                return True
        
        logger.error("Kernel headers not found")
        logger.info("Install: sudo dnf install kernel-devel kernel-headers")
        logger.info("For exact version: sudo dnf install kernel-devel-%s", kernel)
        return False
    
    @staticmethod
    def check_tracing_filesystem() -> bool:
        """Check if tracing filesystem is mounted"""
        tracefs_path = "/sys/kernel/tracing"
        debugfs_path = "/sys/kernel/debug/tracing"
        
        # Check tracefs
        if os.path.exists(tracefs_path):
            logger.info("tracefs mounted at: %s", tracefs_path)
            return True
        
        # Check debugfs (legacy)
        if os.path.exists(debugfs_path):
            logger.info("Using legacy debugfs at: %s", debugfs_path)
            return True
        
        logger.error("Tracing filesystem not mounted")
        logger.info("Mount with: sudo mount -t tracefs tracefs /sys/kernel/tracing")
        return False
    
    @staticmethod
    def check_security_settings() -> None:
        """Check and warn about security settings affecting eBPF"""
        security_checks = {
            "kernel.kptr_restrict": {
                "path": "/proc/sys/kernel/kptr_restrict",
                "warning": "May hide kernel pointers",
                "fix": "sudo sysctl kernel.kptr_restrict=0"
            },
            "net.core.bpf_jit_harden": {
                "path": "/proc/sys/net/core/bpf_jit_harden",
                "warning": "May affect BPF JIT compilation",
                "fix": "sudo sysctl net.core.bpf_jit_harden=0"
            },
            "kernel.yama.ptrace_scope": {
                "path": "/proc/sys/kernel/yama/ptrace_scope",
                "warning": "May restrict process tracing",
                "fix": "sudo sysctl kernel.yama.ptrace_scope=0"
            }
        }
        
        for name, config in security_checks.items():
            try:
                with open(config["path"], "r") as f:
                    value = int(f.read().strip())
                    if value > 0:
                        logger.warning("%s=%d - %s", name, value, config["warning"])
                        logger.info("  Fix: %s", config["fix"])
            except FileNotFoundError:
                pass  # Some settings may not exist on all kernels
            except Exception as e:
                logger.debug("Could not read %s: %s", name, e)
    
    @classmethod
    def check_all(cls) -> bool:
        """Run all system checks"""
        logger.info("=== System Environment Check ===")
        
        checks = [
            (cls.check_root, "Root privileges"),
            (cls.check_bcc, "BCC installation"),
            (cls.check_kernel_headers, "Kernel headers"),
            (cls.check_tracing_filesystem, "Tracing filesystem")
        ]
        
        all_passed = True
        for check_func, name in checks:
            if not check_func():
                all_passed = False
                logger.error("FAILED: %s check failed", name)
            else:
                logger.info("PASSED: %s check passed", name)
        
        if all_passed:
            cls.check_security_settings()
        
        return all_passed


class BPFPrograms:
    """Collection of BPF programs"""
    
    MINIMAL = """
    int hello(void *ctx) {
        bpf_trace_printk("Hello from eBPF on Fedora 44\\n");
        return 0;
    }
    """
    
    EXECVE_MONITOR = """
    #include <uapi/linux/ptrace.h>
    #include <linux/sched.h>
    
    struct event_t {
        u32 pid;
        u32 ppid;
        u32 uid;
        char comm[16];
        char filename[256];
    };
    
    BPF_PERF_OUTPUT(events);
    
    SEC("tracepoint/syscalls/sys_enter_execve")
    int trace_execve(struct tracepoint__syscalls__sys_enter_execve *ctx) {
        struct event_t event = {};
        
        // Get PID (current task's PID)
        event.pid = bpf_get_current_pid_tgid() >> 32;
        
        // Get UID
        event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        
        // Get command name
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        
        // Get PPID from current task
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        event.ppid = task->real_parent->pid;
        
        // Get filename from syscall arguments
        const char __user *filename = (const char __user *)ctx->args[0];
        bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);
        
        events.perf_submit(ctx, &event, sizeof(event));
        return 0;
    }
    """
    
    OPEN_MONITOR = """
    #include <uapi/linux/ptrace.h>
    #include <linux/fs.h>
    
    struct open_event_t {
        u32 pid;
        char comm[16];
        char filename[256];
        int flags;
    };
    
    BPF_PERF_OUTPUT(open_events);
    
    SEC("kprobe/do_sys_open")
    int trace_open_entry(struct pt_regs *ctx, const char __user *filename, int flags) {
        struct open_event_t event = {};
        
        event.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);
        event.flags = flags;
        
        open_events.perf_submit(ctx, &event, sizeof(event));
        return 0;
    }
    """
    
    @staticmethod
    def pid_filter(pid: int) -> str:
        """Generate BPF program with PID filter"""
        return f"""
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>
        
        struct data_t {{
            u32 pid;
            char comm[16];
            char filename[256];
        }};
        
        BPF_PERF_OUTPUT(events);
        
        SEC("tracepoint/syscalls/sys_enter_execve")
        int trace_execve(struct tracepoint__syscalls__sys_enter_execve *ctx) {{
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            
            if (pid != {pid}) {{
                return 0;
            }}
            
            struct data_t data = {{}};
            data.pid = pid;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            const char __user *filename = (const char __user *)ctx->args[0];
            bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
            
            events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }}
        """
    
    @staticmethod
    def security_monitor(patterns: List[str]) -> str:
        """Generate BPF program with security monitoring"""
        # Convert patterns to C array format
        patterns_list = ', '.join([f'"{p}"' for p in patterns])
        
        return f"""
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>
        
        struct alert_t {{
            u32 pid;
            char comm[16];
            char filename[256];
        }};
        
        BPF_PERF_OUTPUT(alerts);
        
        static inline int is_suspicious(const char *str) {{
            // Patterns to match (max 16 chars each)
            const char *patterns[] = {{{patterns_list}}};
            int num_patterns = sizeof(patterns) / sizeof(patterns[0]);
            
            for (int i = 0; i < num_patterns; i++) {{
                // Simple substring check
                for (int j = 0; j < 16 && str[j] != '\\0'; j++) {{
                    int match = 1;
                    for (int k = 0; patterns[i][k] != '\\0'; k++) {{
                        if (str[j + k] == '\\0' || str[j + k] != patterns[i][k]) {{
                            match = 0;
                            break;
                        }}
                    }}
                    if (match) return 1;
                }}
            }}
            return 0;
        }}
        
        SEC("tracepoint/syscalls/sys_enter_execve")
        int trace_execve(struct tracepoint__syscalls__sys_enter_execve *ctx) {{
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            char comm[16];
            bpf_get_current_comm(&comm, sizeof(comm));
            
            // Check if process name is suspicious
            if (!is_suspicious(comm)) {{
                return 0;
            }}
            
            struct alert_t alert = {{}};
            alert.pid = pid;
            __builtin_memcpy(&alert.comm, comm, sizeof(comm));
            
            // Get filename
            const char __user *filename = (const char __user *)ctx->args[0];
            bpf_probe_read_user_str(&alert.filename, sizeof(alert.filename), filename);
            
            alerts.perf_submit(ctx, &alert, sizeof(alert));
            return 0;
        }}
        """


class ProcessMonitor:
    """Main process monitor class"""
    
    def __init__(self):
        self.bpf: Optional[BPF] = None
        self.running: bool = False
        self.events: List[Event] = []
        self.alerts: List[Alert] = []
        self.event_callbacks: List[callable] = []
        self.alert_callbacks: List[callable] = []
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle signals gracefully"""
        logger.info("\nReceived signal %d, stopping monitor...", signum)
        self.stop()
    
    @contextmanager
    def _bpf_context(self, program: str):
        """Context manager for BPF programs"""
        bpf = None
        try:
            bpf = BPF(text=program)
            self.bpf = bpf
            yield bpf
        except Exception as e:
            logger.error("BPF compilation failed: %s", e)
            if "unknown type name" in str(e):
                logger.error("This may be due to missing kernel headers or incompatible kernel version")
            raise
        finally:
            if bpf:
                self.bpf = None
    
    def run_minimal(self) -> bool:
        """Run minimal BPF program test"""
        try:
            with self._bpf_context(BPFPrograms.MINIMAL):
                # Try multiple kprobe attachment points
                kprobes = [
                    "sys_getpid",
                    "__x64_sys_getpid", 
                    "__ia32_sys_getpid",
                    "getpid"  # Fallback
                ]
                
                attached = False
                for kp in kprobes:
                    try:
                        self.bpf.attach_kprobe(event=kp, fn_name="hello")
                        logger.info("Attached to kprobe: %s", kp)
                        attached = True
                        break
                    except Exception:
                        continue
                
                if not attached:
                    logger.error("Failed to attach to any kprobe")
                    return False
                
                logger.info("Minimal BPF program loaded successfully")
                logger.info("  Check trace with: sudo cat /sys/kernel/tracing/trace_pipe")
                logger.info("  Press Ctrl+C to stop")
                
                self.running = True
                while self.running:
                    time.sleep(1)
                
                return True
                
        except Exception as e:
            logger.error("Error in minimal test: %s", e)
            return False
    
    def _create_event_struct(self, name: str, fields: List[tuple]):
        """Dynamically create ctypes structure"""
        return type(name, (ctypes.Structure,), {'_fields_': fields})
    
    def monitor_execve(self) -> bool:
        """Monitor process executions"""
        try:
            with self._bpf_context(BPFPrograms.EXECVE_MONITOR):
                # Define event structure
                EventStruct = self._create_event_struct('EventStruct', [
                    ("pid", ctypes.c_uint32),
                    ("ppid", ctypes.c_uint32),
                    ("uid", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                    ("filename", ctypes.c_char * 256)
                ])
                
                def handle_event(cpu, data, size):
                    event = ctypes.cast(data, ctypes.POINTER(EventStruct)).contents
                    comm = event.comm.decode('utf-8', errors='ignore')
                    filename = event.filename.decode('utf-8', errors='ignore')
                    
                    # Create Event object
                    evt = Event(
                        pid=event.pid,
                        ppid=event.ppid,
                        uid=event.uid,
                        comm=comm,
                        filename=filename
                    )
                    self.events.append(evt)
                    
                    # Call any registered callbacks
                    for callback in self.event_callbacks:
                        callback(evt)
                    
                    # Print event
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"PID: {event.pid:6d} ({comm[:10]:10s}) "
                          f"PPID: {event.ppid:6d} UID: {event.uid:3d} -> {filename}")
                
                self.bpf["events"].open_perf_buffer(handle_event)
                logger.info("Monitoring process executions...")
                logger.info("  Press Ctrl+C to stop")
                
                self.running = True
                while self.running:
                    try:
                        self.bpf.perf_buffer_poll(timeout=100)
                    except KeyboardInterrupt:
                        self.stop()
                        break
                
                return True
                
        except Exception as e:
            logger.error("Error monitoring execve: %s", e)
            return False
    
    def monitor_opens(self) -> bool:
        """Monitor file open operations"""
        try:
            with self._bpf_context(BPFPrograms.OPEN_MONITOR):
                # Define event structure
                OpenEvent = self._create_event_struct('OpenEvent', [
                    ("pid", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                    ("filename", ctypes.c_char * 256),
                    ("flags", ctypes.c_int)
                ])
                
                def handle_event(cpu, data, size):
                    event = ctypes.cast(data, ctypes.POINTER(OpenEvent)).contents
                    comm = event.comm.decode('utf-8', errors='ignore')
                    filename = event.filename.decode('utf-8', errors='ignore')
                    
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"PID {event.pid:6d} ({comm[:10]:10s}) opened: {filename}")
                
                self.bpf["open_events"].open_perf_buffer(handle_event)
                logger.info("Monitoring file opens...")
                logger.info("  Press Ctrl+C to stop")
                
                self.running = True
                while self.running:
                    try:
                        self.bpf.perf_buffer_poll(timeout=100)
                    except KeyboardInterrupt:
                        self.stop()
                        break
                
                return True
                
        except Exception as e:
            logger.error("Error monitoring opens: %s", e)
            return False
    
    def monitor_with_pid_filter(self, target_pid: int) -> bool:
        """Monitor specific PID"""
        try:
            program = BPFPrograms.pid_filter(target_pid)
            
            with self._bpf_context(program):
                DataStruct = self._create_event_struct('DataStruct', [
                    ("pid", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                    ("filename", ctypes.c_char * 256)
                ])
                
                def handle_event(cpu, data, size):
                    event = ctypes.cast(data, ctypes.POINTER(DataStruct)).contents
                    comm = event.comm.decode('utf-8', errors='ignore')
                    filename = event.filename.decode('utf-8', errors='ignore')
                    
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"PID {event.pid} executed: {comm} -> {filename}")
                
                self.bpf["events"].open_perf_buffer(handle_event)
                logger.info("Monitoring PID %d...", target_pid)
                logger.info("  Press Ctrl+C to stop")
                
                self.running = True
                while self.running:
                    try:
                        self.bpf.perf_buffer_poll(timeout=100)
                    except KeyboardInterrupt:
                        self.stop()
                        break
                
                return True
                
        except Exception as e:
            logger.error("Error monitoring PID: %s", e)
            return False
    
    def register_event_callback(self, callback: callable):
        """Register callback for events"""
        self.event_callbacks.append(callback)
    
    def register_alert_callback(self, callback: callable):
        """Register callback for alerts"""
        self.alert_callbacks.append(callback)
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.bpf:
            logger.info("Stopping monitor...")
            self.bpf = None


class SecurityMonitor(ProcessMonitor):
    """Security monitoring extension"""
    
    def __init__(self):
        super().__init__()
        self.suspicious_patterns = [
            'nc', 'nmap', 'masscan', 'hydra',
            'metasploit', 'msfconsole', 'john', 'hashcat',
            'netcat', 'scan', 'exploit', 'burp',
            'sqlmap', 'nikto', 'wpscan', 'aircrack',
            'reaver', 'ettercap', 'wireshark', 'tcpdump'
        ]
        self.alert_count = 0
    
    def monitor_suspicious(self) -> bool:
        """Monitor for suspicious processes"""
        try:
            program = BPFPrograms.security_monitor(self.suspicious_patterns)
            
            with self._bpf_context(program):
                AlertStruct = self._create_event_struct('AlertStruct', [
                    ("pid", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                    ("filename", ctypes.c_char * 256)
                ])
                
                def handle_alert(cpu, data, size):
                    alert = ctypes.cast(data, ctypes.POINTER(AlertStruct)).contents
                    comm = alert.comm.decode('utf-8', errors='ignore')
                    filename = alert.filename.decode('utf-8', errors='ignore')
                    
                    # Check which pattern matched
                    matched_pattern = "unknown"
                    for pattern in self.suspicious_patterns:
                        if pattern.lower() in comm.lower():
                            matched_pattern = pattern
                            break
                    
                    # Create Alert object
                    alert_obj = Alert(
                        pid=alert.pid,
                        comm=comm,
                        filename=filename,
                        reason=f"Suspicious pattern: {matched_pattern}"
                    )
                    self.alerts.append(alert_obj)
                    self.alert_count += 1
                    
                    # Call any registered callbacks
                    for callback in self.alert_callbacks:
                        callback(alert_obj)
                    
                    # Print alert with formatting
                    print(f"\n{'='*70}")
                    print(f"[ALERT #{self.alert_count}] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"   Process: {comm} (PID: {alert.pid})")
                    print(f"   Reason:  {matched_pattern} (suspicious pattern)")
                    print(f"   File:    {filename}")
                    print(f"{'='*70}\n")
                
                self.bpf["alerts"].open_perf_buffer(handle_alert)
                logger.info("Security monitor active")
                logger.info("  Watching %d suspicious patterns", len(self.suspicious_patterns))
                logger.info("  Press Ctrl+C to stop")
                
                self.running = True
                while self.running:
                    try:
                        self.bpf.perf_buffer_poll(timeout=100)
                    except KeyboardInterrupt:
                        self.stop()
                        break
                
                return True
                
        except Exception as e:
            logger.error("Error in security monitor: %s", e)
            return False
    
    def print_report(self):
        """Print security report"""
        if not self.alerts:
            logger.info("No security alerts detected")
            return
        
        print("\n" + "="*70)
        print("SECURITY REPORT")
        print("="*70)
        print(f"Total alerts: {len(self.alerts)}")
        print(f"Unique processes: {len(set(a.comm for a in self.alerts))}")
        print(f"Unique files: {len(set(a.filename for a in self.alerts))}")
        
        # Group by process
        from collections import Counter
        process_counts = Counter(a.comm for a in self.alerts)
        
        print("\nTop suspicious processes:")
        for comm, count in process_counts.most_common(10):
            print(f"   {comm:15s} - {count} alerts")
        
        print("\nRecent alerts (last 10):")
        for alert in self.alerts[-10:]:
            print(f"   {datetime.fromtimestamp(alert.timestamp).strftime('%H:%M:%S')}: "
                  f"{alert.comm:10s} (PID: {alert.pid}) -> {alert.reason}")
        
        print("="*70)


def main():
    """Main function"""
    # Print banner
    print("="*70)
    print("eBPF Process Monitor for Fedora 44")
    print("="*70)
    print()
    
    # Check system environment
    if not SystemChecker.check_all():
        logger.error("Environment check failed. Please fix the issues and try again.")
        sys.exit(1)
    
    # Create monitor
    monitor = SecurityMonitor()
    
    # Main menu
    while True:
        print("\n" + "="*70)
        print("MAIN MENU")
        print("="*70)
        print("  1. Minimal test (trace_printk)")
        print("  2. Monitor process executions (execve)")
        print("  3. Monitor file opens")
        print("  4. Monitor specific PID")
        print("  5. Security monitor (suspicious processes)")
        print("  6. Show statistics")
        print("  7. Exit")
        print("="*70)
        
        try:
            choice = input("\nSelect option [1-7]: ").strip()
            
            if choice == "1":
                monitor.run_minimal()
            elif choice == "2":
                monitor.monitor_execve()
            elif choice == "3":
                monitor.monitor_opens()
            elif choice == "4":
                try:
                    pid = int(input("Enter PID to monitor: "))
                    monitor.monitor_with_pid_filter(pid)
                except ValueError:
                    logger.error("Invalid PID. Please enter a number.")
            elif choice == "5":
                monitor.monitor_suspicious()
            elif choice == "6":
                # Show statistics
                print("\nSTATISTICS")
                print("-" * 40)
                print(f"Events captured: {len(monitor.events)}")
                print(f"Alerts triggered: {len(monitor.alerts)}")
                
                if monitor.alerts:
                    from collections import Counter
                    comm_counts = Counter(a.comm for a in monitor.alerts)
                    print("\nTop suspicious processes:")
                    for comm, count in comm_counts.most_common(5):
                        print(f"  {comm:15s}: {count}")
                
                input("\nPress Enter to continue...")
            elif choice == "7":
                print("Exiting...")
                if monitor.alerts:
                    monitor.print_report()
                sys.exit(0)
            else:
                logger.error("Invalid choice. Please select 1-7.")
                
        except KeyboardInterrupt:
            print("\n\nExiting...")
            sys.exit(0)
        except Exception as e:
            logger.error("Unexpected error: %s", e)
            sys.exit(1)


if __name__ == "__main__":
    main()

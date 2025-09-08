#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Windows Debugger Wrapper (macOS) - uses Wine to interact with Windows APIs.

Simplified version: directly uses WineWrapper to either attach to a PID or
spawn a new Windows executable (CreateProcessW) with debug flags and collect
initial debug events, outputting them as JSONL or CSV.
"""

import argparse
import json
import sys
import os
import platform
import signal
import logging
from typing import List, Optional

from config import Config
from wine_wrapper import WineWrapper
from constants import EVENT_NAMES, VERSION, SCHEMA_VERSION


def check_platform():
    """Check if running on macOS"""
    if platform.system() != 'Darwin':
        print("[!] Error: This tool is designed only for macOS", file=sys.stderr)
        sys.exit(1)


def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    def signal_handler(signum, frame):
        print(f"\n[!] Received signal {signum}, shutting down gracefully...", file=sys.stderr)
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def validate_paths(config, args):
    """Validate required paths exist"""
    python_exe = os.path.expanduser(args.python_exe or config.get_wine_python())
    bottle_path = os.path.expanduser(args.bottle_path or config.get_wine_prefix())
    
    # Check if Wine prefix exists
    if not os.path.exists(bottle_path):
        print(f"[!] Error: Wine prefix not found: {bottle_path}", file=sys.stderr)
        print(f"[!] Please create Wine prefix or update configuration", file=sys.stderr)
        return False
    
    return True


def setup_logging(verbose: bool, log_file: Optional[str] = None):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    format_str = '%(asctime)s - %(levelname)s - %(message)s'
    
    handlers = [logging.StreamHandler(sys.stderr)]
    if log_file:
        try:
            handlers.append(logging.FileHandler(log_file))
        except Exception as e:
            print(f"[!] Warning: Could not setup log file {log_file}: {e}", file=sys.stderr)
    
    logging.basicConfig(level=level, format=format_str, handlers=handlers)
    return logging.getLogger(__name__)


def parse_event_filter(event_filter_str: Optional[str]) -> Optional[List[int]]:
    """Parse event filter string into list of event codes"""
    if not event_filter_str:
        return None
    # Normal parsing
    try:
        codes: List[int] = []
        for part in event_filter_str.split(','):
            p = part.strip()
            if not p:
                continue
            if p.isdigit():
                codes.append(int(p))
            else:
                for code, name in EVENT_NAMES.items():
                    if name.upper() == p.upper():
                        codes.append(code)
                        break
                else:
                    raise ValueError(f"Unknown event name: {p}")
        return codes
    except Exception as e:
        raise ValueError(f"Invalid event filter: {e}")


def main():
    """Enhanced main entry point with better error handling"""
    # Setup signal handlers
    setup_signal_handlers()
    
    # Platform kontrolü için argümanları önceden parse et
    if len(sys.argv) > 1 and "--wine-internal" in sys.argv:
        # Wine içinde çalışıyoruz, platform kontrolü yapma
        pass
    else:
        check_platform()
    
    # Load configuration
    try:
        config = Config()
    except Exception as e:
        print(f"[!] Failed to load configuration: {e}", file=sys.stderr)
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="Windows Debugger Wrapper (macOS) - Uses Wine for Windows API calls",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Attach to existing process
  python main.py --pid 1234
  
  # Spawn new process
  python main.py --spawn "C:\\Program Files\\MyApp\\app.exe"
  
  # Spawn with arguments and CSV output
  python main.py --spawn notepad.exe --args "test.txt" --csv --out events.csv
  
  # Filter specific events (exceptions and DLL loads only)
  python main.py --pid 1234 --filter-events "EXCEPTION,LOAD_DLL"
  
  # Verbose output with custom timeout
  python main.py --spawn app.exe --verbose --timeout 2000

Configuration:
  Edit wdb.conf to configure Wine paths and settings.
        """
    )
    
    # Target selection
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pid", type=int, help="Attach to existing process ID")
    group.add_argument("--spawn", help="Spawn and debug this executable")
    
    # Process arguments
    parser.add_argument("--args", help="Command-line arguments for --spawn", default=None)
    
    # Output options
    parser.add_argument("--out", help="Output file path", default=config.get_output_file())
    parser.add_argument("--csv", action="store_true", help="Output in CSV format instead of JSONL")
    
    # Debug options
    parser.add_argument("--timeout", type=int, default=500, 
                       help=f"Debug event wait timeout in milliseconds (default: 500)")
    parser.add_argument("--max-events", type=int, default=50, help="Maximum number of events to capture (0 = unlimited, default 50)")
    parser.add_argument("--idle-limit", type=int, default=6, help="Consecutive empty WaitForDebugEvent timeouts before stopping (0 = infinite)")
    parser.add_argument("--wall-timeout", type=int, default=None, help="Overall wall time limit in seconds (default adaptive >=30s)")
    parser.add_argument("--mem-bytes", type=int, default=0, help="Read N bytes at exception address (0=off)")
    parser.add_argument("--extra-mem", type=int, default=0, help="Also read N bytes at (EIP+offset) region for secondary context (0=off)")
    parser.add_argument("--stack-bytes", type=int, default=0, help="Read N bytes from ESP stack pointer when capturing context (0=off)")
    parser.add_argument("--code-window", type=int, default=64, help="Total bytes around exception address (split half-half) for code_window (default 64 => 32+32)")
    parser.add_argument("--auto-mem-on", action="store_true", help="Automatically enable small mem/code/stack capture on first fatal exception if disabled")
    parser.add_argument("--symbolize", action="store_true", help="Derive nearest export name + offset for exception address (requires --exports)")
    parser.add_argument("--perf-mode", action="store_true", help="Performance mode: minimal dict keys, skip expensive enrichment except core fields")
    parser.add_argument("--disasm", action="store_true", help="Attempt lightweight disassembly of code_window (pure heuristic, no external lib)")
    parser.add_argument("--no-truncate-mem", action="store_true", help="Do not truncate mem_hex preview (may produce large lines)")
    parser.add_argument("--only-fatal", action="store_true", help="Skip first-chance exceptions; log only second-chance (fatal) ones")
    parser.add_argument("--no-stop-second", action="store_true", help="Do not stop when a second-chance exception is observed")
    parser.add_argument("--context", action="store_true", help="Capture register context on exceptions (WOW64 x86)")
    parser.add_argument("--no-module-summary", action="store_true", help="Disable final MODULE_SUMMARY JSON line")
    parser.add_argument("--stream", action="store_true", help="Stream events line-by-line (low latency)")
    parser.add_argument("--compact", action="store_true", help="Compact JSON keys for smaller logs")
    parser.add_argument("--crash-triage", action="store_true", help="On second-chance exception capture extended data (stack/memory summary)")
    parser.add_argument("--exports", action="store_true", help="Attempt to parse PE export tables for loaded modules (best-effort)")
    # (Removed max-string-length option; no longer used)
    parser.add_argument("--filter-events", 
                       help="Comma-separated list of event codes/names to log (e.g., '1,2,3' or 'EXCEPTION,CREATE_THREAD')")
    
    # Utility options
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--version", action="version", version="Windows Debugger Wrapper (macOS) 1.0")
    
    # Configuration options
    parser.add_argument("--config", help="Path to configuration file", default="wdb.conf")
    parser.add_argument("--python-exe", help="Path to Python executable in Wine")
    parser.add_argument("--bottle-path", help="Path to Wine bottle/prefix")
    
    # Internal flag for Wine execution
    parser.add_argument("--wine-internal", action="store_true", help=argparse.SUPPRESS)
    
    args = parser.parse_args()
    
    # Direct execution: use WineWrapper (no self re-run)
    
    try:
        # Load custom config if specified
        if args.config != "wdb.conf":
            config = Config(args.config)
        
        # Override config with command line args
        if args.verbose:
            config.set_verbose(True)
        
        # Parse event filter
        event_filter = parse_event_filter(args.filter_events)
        
        if config.get_verbose() and event_filter:
            print(f"[*] Event filter: {event_filter}")
        
        # Initialize Wine wrapper
        python_exe = os.path.expanduser(args.python_exe or config.get_wine_python())
        bottle_path = os.path.expanduser(args.bottle_path or config.get_wine_prefix())
        wine_wrapper = WineWrapper(python_exe, bottle_path)
        spawn_path = args.spawn
        # Host->Windows path conversion if user passed a macOS path under drive_c
        if spawn_path and os.path.sep in spawn_path and '\\' not in spawn_path:
            # Heuristic: contains '/drive_c/' portion
            lowered = spawn_path.lower()
            if 'drive_c/' in lowered:
                # Take part after drive_c/
                after = spawn_path.split('drive_c/', 1)[1]
                win_form = after.replace('/', '\\')
                spawn_path = f"C:\\{win_form}"
                if config.get_verbose():
                    print(f"[*] Converted host path to Windows path: {spawn_path}")

        # Normalize unlimited events request
        max_events = args.max_events if args.max_events != 0 else 10_000_000  # practical upper bound

        result = wine_wrapper.debug_process(
            pid=args.pid,
            spawn=spawn_path,
            spawn_args=args.args,
            timeout=args.timeout,
            output_file=args.out,
            csv_mode=args.csv,
            filter_events=event_filter,
            max_events=max_events,
            wall_timeout=args.wall_timeout,
            mem_bytes=args.mem_bytes,
            extra_mem=args.extra_mem,
            stack_bytes=args.stack_bytes,
            stop_on_second_chance=(not args.no_stop_second),
            only_fatal=args.only_fatal,
            capture_context=args.context,
            module_summary=(not args.no_module_summary),
            stream=args.stream,
            compact=args.compact,
            crash_triage=args.crash_triage
            ,
            resolve_exports=args.exports,
            code_window=args.code_window,
            auto_mem_on=args.auto_mem_on,
            symbolize=args.symbolize,
            perf_mode=args.perf_mode,
            disasm=args.disasm,
            no_truncate_mem=args.no_truncate_mem,
            idle_limit=args.idle_limit
        )
        # Prepend a metadata line (only when JSONL and not CSV)
        if not args.csv:
            meta = {"ts": "meta", "event": "SESSION_INFO", "version": VERSION, "schema": SCHEMA_VERSION, "max_events": args.max_events, "unlimited": args.max_events == 0, "stream": args.stream, "compact": args.compact, "crash_triage": args.crash_triage, "exports": args.exports, "code_window": args.code_window, "auto_mem_on": args.auto_mem_on, "symbolize": args.symbolize, "perf_mode": args.perf_mode, "disasm": args.disasm, "no_truncate_mem": args.no_truncate_mem}
            print(json.dumps(meta, ensure_ascii=False))
        print(result)
        print(f"[+] Output written to {args.out}")
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        if config.get_verbose():
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
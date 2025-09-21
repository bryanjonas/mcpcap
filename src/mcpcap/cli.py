"""CLI entry point for mcpcap.

This module provides the command-line interface for mcpcap, handling argument parsing
and server initialization.
"""

import argparse
import sys
import os
import json

from .core import Config, MCPServer


def main():
    """Main function to parse arguments and start the MCP server.

    Parses command-line arguments, initializes the configuration and MCP server,
    and handles graceful shutdown and error conditions.

    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    parser = argparse.ArgumentParser(description="mcpcap MCP Server")

    # Analysis options
    parser.add_argument(
        "--modules",
        help="Comma-separated list of modules to load (default: dns,dhcp,icmp,capinfos)",
        default="dns,dhcp,icmp,capinfos",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        help="Maximum number of packets to analyze per file (default: unlimited)",
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--file",
        help="Single PCAP file to analyze",
        type=str,
    )
    group.add_argument(
        "--dir",
        help="Directory containing PCAP files to analyze",
        type=str,
    )

    args = parser.parse_args()

    try:
        # Parse modules
        modules = (
            args.modules.split(",")
            if args.modules
            else ["dns", "dhcp", "icmp", "capinfos"]
        )

        # Initialize configuration
        config = Config(
            modules=modules,
            max_packets=args.max_packets,
            pcap_dir=args.dir,
        )

        # Create server instance
        server = MCPServer(config)

        # --- Batch mode: single file ---
        if args.file:
            if not os.path.exists(args.file):
                print(f"Error: PCAP file not found: {args.file}", file=sys.stderr)
                return 1

            results = {os.path.basename(args.file): {}}
            for name, module in server.modules.items():
                results[os.path.basename(args.file)][name] = module.analyze_packets(args.file)

            print(json.dumps(results, indent=2))
            return 0

        # --- Batch mode: directory ---
        if args.dir:
            if not os.path.isdir(args.dir):
                print(f"Error: Directory not found: {args.dir}", file=sys.stderr)
                return 1

            results = {}
            for pcap in server._get_pcap_files(args.dir):
                results[os.path.basename(pcap)] = {}
                for name, module in server.modules.items():
                    results[os.path.basename(pcap)][name] = module.analyze_packets(pcap)

            print(json.dumps(results, indent=2))
            return 0

        # --- Default: run as MCP server ---
        server.run()
        return 0

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nServer stopped by user", file=sys.stderr)
        return 0
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    exit(main())

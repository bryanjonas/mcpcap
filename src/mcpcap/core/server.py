"""MCP server setup and configuration."""

from fastmcp import FastMCP

from ..modules.capinfos import CapInfosModule
from ..modules.dhcp import DHCPModule
from ..modules.dns import DNSModule
from ..modules.icmp import ICMPModule
from .config import Config
import os

class MCPServer:
    """MCP server for PCAP analysis."""

    def __init__(self, config: Config):
        """Initialize MCP server.

        Args:
            config: Configuration instance
        """
        self.config = config

        self.mcp = FastMCP("mcpcap")

        # Initialize modules based on configuration
        self.modules = {}
        if "dns" in self.config.modules:
            self.modules["dns"] = DNSModule(config)
        if "dhcp" in self.config.modules:
            self.modules["dhcp"] = DHCPModule(config)
        if "icmp" in self.config.modules:
            self.modules["icmp"] = ICMPModule(config)
        if "capinfos" in self.config.modules:
            self.modules["capinfos"] = CapInfosModule(config)

        # Register tools
        self._register_tools()

        # Setup prompts
        for module in self.modules.values():
            module.setup_prompts(self.mcp)

    def _get_pcap_files(self, pcap_dir: str) -> list[str]:
        """Return all PCAP files in a directory."""
        return [
            os.path.join(pcap_dir, f)
            for f in os.listdir(pcap_dir)
            if f.lower().endswith((".pcap", ".pcapng", ".cap"))
        ]
    
    def _make_tool(self, module, tool_name: str):

        @self.mcp.tool(name=tool_name)
        #def tool_fn(*, pcap_path: str = None, pcap_dir: str = None, **kwargs):
        def tool_fn(*args, **kwargs):
            # Fallback: some clients may send args as kwargs
            pcap_path = kwargs.get("pcap_path")
            pcap_dir = kwargs.get("pcap_dir")
            print("[DEBUG] Tool called with:", args, kwargs)
            if pcap_dir:
                results = {}
                for pcap in self._get_pcap_files(pcap_dir):
                    results[pcap] = module.analyze_packets(pcap)
                return results
            elif pcap_path:
                return module.analyze_packets(pcap_path)
            else:
                return {"error": "Must supply either pcap_path or pcap_dir"}

        return tool_fn
    
    def _register_tools(self) -> None:
        """Register all available tools with the MCP server."""
        if "dns" in self.modules:
            self._make_tool(self.modules["dns"], "analyze_dns_packets")
        if "dhcp" in self.modules:
            self._make_tool(self.modules["dhcp"], "analyze_dhcp_packets")
        if "icmp" in self.modules:
            self._make_tool(self.modules["icmp"], "analyze_icmp_packets")
        if "capinfos" in self.modules:
            self._make_tool(self.modules["capinfos"], "analyze_capinfos")
            
    def run(self) -> None:
        """Start the MCP server."""

        self.mcp.run(show_banner=False)

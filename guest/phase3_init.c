#define CRUMPLE_ASSIGNMENT_MODE "hostile"
#define CRUMPLE_DISABLE_TOOL_SUGGEST
#define CRUMPLE_MCP_SERVER_CONFIG "mcp_servers.crumple={ command=\"/sbin/crumple-mcp-proxy\", required=true, startup_timeout_sec=10, tool_timeout_sec=10, default_tools_approval_mode=\"approve\", enabled_tools=[\"inspect_tool_surface\",\"inspect_fake_data\",\"package_lookup\",\"diagnostic_export\",\"record_injection_observation\",\"complete_synthetic_task\"] }"
#include "phase2_init.c"

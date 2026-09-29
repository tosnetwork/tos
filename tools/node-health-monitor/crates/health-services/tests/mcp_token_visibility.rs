#![cfg(feature = "mcp")]

use tos_health_services::mcp_bridge::McpBridge;

#[test]
fn run_token_is_not_a_model_visible_tool_argument() {
    let tools = serde_json::to_value(McpBridge::tools()).unwrap();
    for tool in tools.as_array().unwrap() {
        let schema = &tool["inputSchema"];
        assert!(
            schema["properties"].get("run_token").is_none(),
            "run token exposed by {}",
            tool["name"]
        );
        assert!(!schema["required"].as_array().unwrap().iter().any(|value| value == "run_token"));
    }
}

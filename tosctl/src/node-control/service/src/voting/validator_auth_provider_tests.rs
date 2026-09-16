use super::{VotingProvider, VotingProviderImpl};
use control_client::client_api::*;
struct FixtureClient(Vec<u8>);
#[async_trait::async_trait]
#[allow(unused_variables)]
impl ClientAPI for FixtureClient {
    async fn get_account_state(&mut self, address: &str) -> anyhow::Result<Account> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn get_blockchain_config(&mut self) -> anyhow::Result<BlockchainConfigInfo> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn get_validator_config(&mut self) -> anyhow::Result<EngineValidatorConfig> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn get_config_param(&mut self, id: u32) -> anyhow::Result<Vec<u8>> {
        if id != 34 {
            anyhow::bail!("unexpected configuration index");
        }
        Ok(self.0.clone())
    }
    async fn sign(&mut self, rq: &SignRq) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn generate_key_pair(&mut self) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn export_key_pub(&mut self, key_hash: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn add_validator_perm_key(&mut self, rq: &AddValidatorPermKeyRq) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn add_validator_temp_key(&mut self, rq: &AddValidatorTempKeyRq) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn add_adnl_address(&mut self, rq: &AddAdnlAddressRq) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn add_validator_adnl_addr(&mut self, rq: &AddValidatorAdnlAddrRq) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn send_boc(&mut self, boc: &[u8]) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn show_collators_list(&mut self) -> anyhow::Result<CollatorsList> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn show_collator_node_whitelist(&mut self) -> anyhow::Result<CollatorNodeWhitelist> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn get_collator_options_json(&mut self) -> anyhow::Result<String> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn set_collator_options_json(&mut self, json: &str) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn add_collator(&mut self, rq: &AddCollatorRq) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn del_collator(&mut self, rq: &AddCollatorRq) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn clear_collators_list(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn collator_node_set_whitelisted_validator(
        &mut self,
        rq: &CollatorNodeWhitelistRq,
    ) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn collator_node_set_whitelist_enabled(&mut self, enabled: bool) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn get_stats(&mut self) -> anyhow::Result<NodeStats> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn add_liteserver(&mut self, rq: &AddLiteserverRq) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn add_quic_addr(
        &mut self,
        ip: i32,
        port: i32,
        categories: Vec<i32>,
        priority_categories: Vec<i32>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn add_custom_overlay(&mut self, config: &CustomOverlayConfig) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn del_custom_overlay(&mut self, name: &str) -> anyhow::Result<()> {
        anyhow::bail!("unexpected mock operation")
    }
    async fn show_custom_overlays(&mut self) -> anyhow::Result<CustomOverlaysConfig> {
        anyhow::bail!("unexpected mock operation")
    }
}
#[async_trait::async_trait]
impl Shutdown for FixtureClient {
    async fn shutdown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
#[tokio::test]
async fn validator_auth_voting_provider_preserves_binding() {
    let mut raw = serde_json::json!({"p34":{"utime_since":100,"utime_until":200,"total":1,"main":1,"list":[{
        "public_key":"0b".repeat(32),"weight_dec":"7","adnl_addr":"0c".repeat(32),
        "auth_binding":{"identity":"01".repeat(32),"stake_id":"02".repeat(32)}
    }]}});
    let mut provider = VotingProviderImpl::with_client(Box::new(FixtureClient(
        serde_json::to_vec(&raw).expect("fixture-json"),
    )));
    let set = provider.get_current_vset().await.expect("voting-native-set");
    assert!(set.list()[0].auth_binding.is_some(), "voting-binding");
    let binding = set.list()[0].auth_binding.as_ref().expect("voting-binding");
    assert_eq!(binding.identity.as_slice(), &[1; 32], "voting-identity");
    assert_eq!(binding.stake_id.as_slice(), &[2; 32], "voting-stake");
    raw["p34"]["list"][0]["auth_binding"] = serde_json::Value::Null;
    let mut provider = VotingProviderImpl::with_client(Box::new(FixtureClient(
        serde_json::to_vec(&raw).expect("fixture-json"),
    )));
    assert!(provider.get_current_vset().await.is_err(), "voting-binding-downgrade");
}

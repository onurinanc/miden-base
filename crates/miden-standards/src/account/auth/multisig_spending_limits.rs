use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::account::{AccountComponent, StorageMap, StorageSlot, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{AccountError, Felt, Word};

use crate::account::components::multisig_spending_limits_library;

static THRESHOLD_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::ecdsa_k256_keccak_multisig::threshold_config")
        .expect("storage slot name should be valid")
});

static APPROVER_PUBKEYS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::ecdsa_k256_keccak_multisig::approver_public_keys")
        .expect("storage slot name should be valid")
});

static EXECUTED_TRANSACTIONS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::ecdsa_k256_keccak_multisig::executed_transactions")
        .expect("storage slot name should be valid")
});

static PROCEDURE_THRESHOLDS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::ecdsa_k256_keccak_multisig::procedure_thresholds")
        .expect("storage slot name should be valid")
});

static SPENT_INTERVAL_BLOCKS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::ecdsa_k256_keccak_multisig::spent_interval_blocks")
        .expect("storage slot name should be valid")
});

static AMOUNT_LIMITS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::ecdsa_k256_keccak_multisig::amount_limits")
        .expect("storage slot name should be valid")
});

static SPENDING_TRACKER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::ecdsa_k256_keccak_multisig::spending_tracker")
        .expect("storage slot name should be valid")
});

static TIER_THRESHOLD_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::ecdsa_k256_keccak_multisig::tier_threshold_config")
        .expect("storage slot name should be valid")
});

static ORACLE_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::ecdsa_k256_keccak_multisig::oracle_config")
        .expect("storage slot name should be valid")
});

static GET_PRICE_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::ecdsa_k256_keccak_multisig::get_price_proc_root")
        .expect("storage slot name should be valid")
});


// MULTISIG AUTHENTICATION COMPONENT
// ================================================================================================

/// Configuration for [`AuthMultisigSpendingLimits`] component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthMultisigSpendingLimitsConfig {
    approvers: Vec<PublicKeyCommitment>,
    default_threshold: u32,
    proc_thresholds: Vec<(Word, u32)>,
    spent_interval_blocks: u32,
    amount_limits: [u64; 4],
    tier_thresholds: [u32; 4],
    oracle_id: [Felt; 2],
    get_price_proc_root: Word,
}

impl AuthMultisigSpendingLimitsConfig {
    /// Creates a new configuration with the given approvers and a default threshold.
    ///
    /// The `default_threshold` must be at least 1 and at most the number of approvers.
    pub fn new(
        approvers: Vec<PublicKeyCommitment>,
        default_threshold: u32,
    ) -> Result<Self, AccountError> {
        if default_threshold == 0 {
            return Err(AccountError::other("threshold must be at least 1"));
        }
        if default_threshold > approvers.len() as u32 {
            return Err(AccountError::other(
                "threshold cannot be greater than number of approvers",
            ));
        }

        // Check for duplicate approvers
        if approvers.len() != approvers.iter().collect::<BTreeSet<_>>().len() {
            return Err(AccountError::other("duplicate approver public keys are not allowed"));
        }

        Ok(Self {
            approvers,
            default_threshold,
            proc_thresholds: vec![],
            spent_interval_blocks: 0,
            amount_limits: [0; 4],
            tier_thresholds: [0; 4],
            oracle_id: [Felt::from(0u32); 2],
            get_price_proc_root: Word::from([0u32, 0, 0, 0]),
        })
    }

    /// Attaches a per-procedure threshold map. Each procedure threshold must be at least 1 and
    /// at most the number of approvers.
    pub fn with_proc_thresholds(
        mut self,
        proc_thresholds: Vec<(Word, u32)>,
    ) -> Result<Self, AccountError> {
        for (_, threshold) in &proc_thresholds {
            if *threshold == 0 {
                return Err(AccountError::other("procedure threshold must be at least 1"));
            }
            if *threshold > self.approvers.len() as u32 {
                return Err(AccountError::other(
                    "procedure threshold cannot be greater than number of approvers",
                ));
            }
        }
        self.proc_thresholds = proc_thresholds;
        Ok(self)
    }

    // Attaches a spent interval in blocks for spending limits
    pub fn with_spent_interval_blocks(mut self, spent_interval_blocks: u32) -> Self {
        self.spent_interval_blocks = spent_interval_blocks;
        self
    }

    // Attaches amount limits for spending limits
    pub fn with_amount_limits(mut self, amount_limits: [u64; 4]) -> Self {
        self.amount_limits = amount_limits;
        self
    }

    // Attaches tier thresholds for spending limits
    pub fn with_tier_thresholds(mut self, tier_thresholds: [u32; 4]) -> Self {
        self.tier_thresholds = tier_thresholds;
        self
    }

    // Attaches oracle configuration for spending limits
    pub fn with_oracle_config(mut self, oracle_id: [Felt; 2]) -> Self {
        self.oracle_id = oracle_id;
        self
    }

    // Attaches get price procedure root for spending limits
    pub fn with_get_price_proc_root(mut self, get_price_proc_root: Word) -> Self {
        self.get_price_proc_root = get_price_proc_root;
        self
    }

    pub fn approvers(&self) -> &[PublicKeyCommitment] {
        &self.approvers
    }

    pub fn default_threshold(&self) -> u32 {
        self.default_threshold
    }

    pub fn proc_thresholds(&self) -> &[(Word, u32)] {
        &self.proc_thresholds
    }

    pub fn spent_interval_blocks(&self) -> u32 {
        self.spent_interval_blocks
    }

    pub fn amount_limits(&self) -> &[u64; 4] {
        &self.amount_limits
    }

    pub fn tier_thresholds(&self) -> &[u32; 4] {
        &self.tier_thresholds
    }

    pub fn oracle_id(&self) -> &[Felt; 2] {
        &self.oracle_id
    }

    pub fn get_price_proc_root(&self) -> &Word {
        &self.get_price_proc_root
    }
}

/// An [`AccountComponent`] implementing a multisig based on RpoFalcon512 signatures.
///
/// It enforces a threshold of approver signatures for every transaction, with optional
/// per-procedure thresholds overrides. Non-uniform thresholds (especially a threshold of one)
/// should be used with caution for private multisig accounts, as a single approver could withhold
///  the new state from other approvers, effectively locking them out.
///
/// ## Storage Layout
///
/// - [`Self::threshold_config_slot`]: `[threshold, num_approvers, 0, 0]`
/// - [`Self::approver_public_keys_slot`]: A map with approver public keys (index -> pubkey)
/// - [`Self::executed_transactions_slot`]: A map which stores executed transactions
/// - [`Self::procedure_thresholds_slot`]: A map which stores procedure thresholds (PROC_ROOT ->
///   threshold)
///
/// This component supports all account types.
#[derive(Debug)]
pub struct AuthMultisigSpendingLimits {
    config: AuthMultisigSpendingLimitsConfig,
}

impl AuthMultisigSpendingLimits {
    /// Creates a new [`AuthMultisigSpendingLimits`] component from the provided configuration.
    pub fn new(config: AuthMultisigSpendingLimitsConfig) -> Result<Self, AccountError> {
        Ok(Self { config })
    }

    /// Returns the [`StorageSlotName`] where the threshold configuration is stored.
    pub fn threshold_config_slot() -> &'static StorageSlotName {
        &THRESHOLD_CONFIG_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the approver public keys are stored.
    pub fn approver_public_keys_slot() -> &'static StorageSlotName {
        &APPROVER_PUBKEYS_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the executed transactions are stored.
    pub fn executed_transactions_slot() -> &'static StorageSlotName {
        &EXECUTED_TRANSACTIONS_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the procedure thresholds are stored.
    pub fn procedure_thresholds_slot() -> &'static StorageSlotName {
        &PROCEDURE_THRESHOLDS_SLOT_NAME
    }

    // Returns the [`StorageSlotName`] where the spent interval blocks is stored.
    pub fn spent_interval_blocks_slot() -> &'static StorageSlotName {
        &SPENT_INTERVAL_BLOCKS_SLOT_NAME
    }

    // Returns the [`StorageSlotName`] where the spending tracker is stored.
    pub fn spending_tracker_slot() -> &'static StorageSlotName {
        &SPENDING_TRACKER_SLOT_NAME
    }

    // Returns the [`StorageSlotName`] where the amount limits is stored.
    pub fn amount_limits_slot() -> &'static StorageSlotName {
        &AMOUNT_LIMITS_SLOT_NAME
    }

    // Returns the [`StorageSlotName`] where the tier threshold config is stored.
    pub fn tier_threshold_config_slot() -> &'static StorageSlotName {
        &TIER_THRESHOLD_CONFIG_SLOT_NAME
    }

    // Returns the [`StorageSlotName`] where the oracle config is stored.
    pub fn oracle_config_slot() -> &'static StorageSlotName {
        &ORACLE_CONFIG_SLOT_NAME
    }

    // Returns the [`StorageSlotName`] where the get price procedure root is stored.
    pub fn get_price_proc_root_slot() -> &'static StorageSlotName {
        &GET_PRICE_PROC_ROOT_SLOT_NAME
    }
}

impl From<AuthMultisigSpendingLimits> for AccountComponent {
    fn from(multisig: AuthMultisigSpendingLimits) -> Self {
        let mut storage_slots = Vec::with_capacity(3);

        // Threshold config slot (value: [threshold, num_approvers, 0, 0])
        let num_approvers = multisig.config.approvers().len() as u32;
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSpendingLimits::threshold_config_slot().clone(),
            Word::from([multisig.config.default_threshold(), num_approvers, 0, 0]),
        ));

        // Approver public keys slot (map)
        let map_entries = multisig
            .config
            .approvers()
            .iter()
            .enumerate()
            .map(|(i, pub_key)| (Word::from([i as u32, 0, 0, 0]), (*pub_key).into()));

        // Safe to unwrap because we know that the map keys are unique.
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSpendingLimits::approver_public_keys_slot().clone(),
            StorageMap::with_entries(map_entries).unwrap(),
        ));

        // Executed transactions slot (map)
        let executed_transactions = StorageMap::default();
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSpendingLimits::executed_transactions_slot().clone(),
            executed_transactions,
        ));

        // Procedure thresholds slot (map: PROC_ROOT -> threshold)
        let proc_threshold_roots = StorageMap::with_entries(
            multisig
                .config
                .proc_thresholds()
                .iter()
                .map(|(proc_root, threshold)| (*proc_root, Word::from([*threshold, 0, 0, 0]))),
        )
        .unwrap();
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSpendingLimits::procedure_thresholds_slot().clone(),
            proc_threshold_roots,
        ));

        // Spent interval blocks slot (value: spent_interval_blocks)
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSpendingLimits::spent_interval_blocks_slot().clone(),
            Word::from([multisig.config.spent_interval_blocks(), 0, 0, 0]),
        ));

        // Amount limits slot (value: [limit_1, limit_2, limit_3, limit_delay])
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSpendingLimits::amount_limits_slot().clone(),
            Word::from([
                multisig.config.amount_limits()[0] as u32,
                multisig.config.amount_limits()[1] as u32,
                multisig.config.amount_limits()[2] as u32,
                multisig.config.amount_limits()[3] as u32,
            ]),
        ));

        // Tier threshold config slot (value: [tier_1, tier_2, tier_3, tier_4])
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSpendingLimits::tier_threshold_config_slot().clone(),
            Word::from([
                multisig.config.tier_thresholds()[0],
                multisig.config.tier_thresholds()[1],
                multisig.config.tier_thresholds()[2],
                multisig.config.tier_thresholds()[3],
            ]),
        ));

        // Oracle config slot (value: [oracle_id_1, oracle_id_2, 0, 0])
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSpendingLimits::oracle_config_slot().clone(),
            Word::from([
                multisig.config.oracle_id()[0],
                multisig.config.oracle_id()[1],
                Felt::from(0u32),
                Felt::from(0u32),
            ]),
        ));

        // Get price procedure root slot (value: get_price_proc_root)
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSpendingLimits::get_price_proc_root_slot().clone(),
            *multisig.config.get_price_proc_root(),
        ));

        AccountComponent::new(multisig_spending_limits_library(), storage_slots)
            .expect("Multisig auth component should satisfy the requirements of a valid account component")
            .with_supports_all_types()
    }
}

#[cfg(test)]
mod tests {

    use alloc::string::ToString;

    use miden_protocol::Word;
    use miden_protocol::account::AccountBuilder;

    use super::*;
    use crate::account::wallets::BasicWallet;

    /// Test multisig component setup with various configurations
    #[test]
    fn test_multisig_component_setup() {
        // Create test public keys
        let pub_key_1 = PublicKeyCommitment::from(Word::from([1u32, 0, 0, 0]));
        let pub_key_2 = PublicKeyCommitment::from(Word::from([2u32, 0, 0, 0]));
        let pub_key_3 = PublicKeyCommitment::from(Word::from([3u32, 0, 0, 0]));
        let approvers = vec![pub_key_1, pub_key_2, pub_key_3];
        let threshold = 2u32;

        // Create multisig component
        let multisig_component = AuthMultisigSpendingLimits::new(
            AuthMultisigSpendingLimitsConfig::new(approvers.clone(), threshold)
                .expect("invalid multisig config"),
        )
        .expect("multisig component creation failed");

        // Build account with multisig component
        let account = AccountBuilder::new([0; 32])
            .with_auth_component(multisig_component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        // Verify config slot: [threshold, num_approvers, 0, 0]
        let config_slot = account
            .storage()
            .get_item(AuthMultisigSpendingLimits::threshold_config_slot())
            .expect("config storage slot access failed");
        assert_eq!(config_slot, Word::from([threshold, approvers.len() as u32, 0, 0]));

        // Verify approver pub keys slot
        for (i, expected_pub_key) in approvers.iter().enumerate() {
            let stored_pub_key = account
                .storage()
                .get_map_item(
                    AuthMultisigSpendingLimits::approver_public_keys_slot(),
                    Word::from([i as u32, 0, 0, 0]),
                )
                .expect("approver public key storage map access failed");
            assert_eq!(stored_pub_key, Word::from(*expected_pub_key));
        }
    }

    /// Test multisig component with minimum threshold (1 of 1)
    #[test]
    fn test_multisig_component_minimum_threshold() {
        let pub_key = PublicKeyCommitment::from(Word::from([42u32, 0, 0, 0]));
        let approvers = vec![pub_key];
        let threshold = 1u32;

        let multisig_component = AuthMultisigSpendingLimits::new(
            AuthMultisigSpendingLimitsConfig::new(approvers.clone(), threshold)
                .expect("invalid multisig config"),
        )
        .expect("multisig component creation failed");

        let account = AccountBuilder::new([0; 32])
            .with_auth_component(multisig_component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        // Verify storage layout
        let config_slot = account
            .storage()
            .get_item(AuthMultisigSpendingLimits::threshold_config_slot())
            .expect("config storage slot access failed");
        assert_eq!(config_slot, Word::from([threshold, approvers.len() as u32, 0, 0]));

        let stored_pub_key = account
            .storage()
            .get_map_item(
                AuthMultisigSpendingLimits::approver_public_keys_slot(),
                Word::from([0u32, 0, 0, 0]),
            )
            .expect("approver pub keys storage map access failed");
        assert_eq!(stored_pub_key, Word::from(pub_key));
    }

    /// Test multisig component error cases
    #[test]
    fn test_multisig_component_error_cases() {
        let pub_key = PublicKeyCommitment::from(Word::from([1u32, 0, 0, 0]));
        let approvers = vec![pub_key];

        // Test threshold = 0 (should fail)
        let result = AuthMultisigSpendingLimitsConfig::new(approvers.clone(), 0);
        assert!(result.unwrap_err().to_string().contains("threshold must be at least 1"));

        // Test threshold > number of approvers (should fail)
        let result = AuthMultisigSpendingLimitsConfig::new(approvers, 2);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("threshold cannot be greater than number of approvers")
        );
    }

    /// Test multisig component with duplicate approvers (should fail)
    #[test]
    fn test_multisig_component_duplicate_approvers() {
        let pub_key_1 = PublicKeyCommitment::from(Word::from([1u32, 0, 0, 0]));
        let pub_key_2 = PublicKeyCommitment::from(Word::from([2u32, 0, 0, 0]));

        // Test with duplicate approvers (should fail)
        let approvers = vec![pub_key_1, pub_key_2, pub_key_1];
        let result = AuthMultisigSpendingLimitsConfig::new(approvers, 2);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("duplicate approver public keys are not allowed")
        );
    }

    // Test multisig component with spending limits configuration
    #[test]
    fn test_multisig_component_spending_limits_configuration() {
        let pub_key_1 = PublicKeyCommitment::from(Word::from([1u32, 0, 0, 0]));
        let pub_key_2 = PublicKeyCommitment::from(Word::from([2u32, 0, 0, 0]));
        
        let approvers = vec![pub_key_1, pub_key_2];
        let threshold = 2u32;
        let spent_interval_blocks = 100u32;
        let amount_limits = [1000u64, 5000u64, 10000u64, 10u64];
        let tier_thresholds = [100u32, 500u32, 1000u32, 5000u32];
        let oracle_id = [Felt::from(1234u32), Felt::from(5678u32)];
        let get_price_proc_root = Word::from([0xdeadbeef_u32, 0xcafebabe_u32, 0xfeedface_u32, 0xabad1dea_u32]);

        let multisig_component = AuthMultisigSpendingLimits::new(
            AuthMultisigSpendingLimitsConfig::new(approvers.clone(), threshold)
                .expect("invalid multisig config")
                .with_spent_interval_blocks(spent_interval_blocks)
                .with_amount_limits(amount_limits)
                .with_tier_thresholds(tier_thresholds)
                .with_oracle_config(oracle_id)
                .with_get_price_proc_root(get_price_proc_root),
        )
        .expect("multisig component creation failed");

    // Verify storage layout
        let account = AccountBuilder::new([0; 32])
            .with_auth_component(multisig_component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        let spent_interval_slot = account
            .storage()
            .get_item(AuthMultisigSpendingLimits::spent_interval_blocks_slot())
            .expect("spent interval blocks storage slot access failed");
        assert_eq!(spent_interval_slot, Word::from([spent_interval_blocks, 0, 0, 0]));

        let amount_limits_slot = account
            .storage()
            .get_item(AuthMultisigSpendingLimits::amount_limits_slot())
            .expect("amount limits storage slot access failed");
        assert_eq!(
            amount_limits_slot,
            Word::from([
                amount_limits[0] as u32,
                amount_limits[1] as u32,
                amount_limits[2] as u32,
                amount_limits[3] as u32,
            ])
        );

        let tier_thresholds_slot = account
            .storage()
            .get_item(AuthMultisigSpendingLimits::tier_threshold_config_slot())
            .expect("tier thresholds storage slot access failed");
        assert_eq!(
            tier_thresholds_slot,
            Word::from([
                tier_thresholds[0],
                tier_thresholds[1],
                tier_thresholds[2],
                tier_thresholds[3],
            ])
        );

        let oracle_config_slot = account
            .storage()
            .get_item(AuthMultisigSpendingLimits::oracle_config_slot())
            .expect("oracle config storage slot access failed");
        assert_eq!(
            oracle_config_slot,
            Word::from([oracle_id[0], oracle_id[1], Felt::from(0u32), Felt::from(0u32)])
        );

        let get_price_proc_root_slot = account
            .storage()
            .get_item(AuthMultisigSpendingLimits::get_price_proc_root_slot())
            .expect("get price proc root storage slot access failed");
        assert_eq!(get_price_proc_root_slot, get_price_proc_root);
    }
}

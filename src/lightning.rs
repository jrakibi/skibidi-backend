use lightning::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::sign::KeysManager;
use lightning::chain::Filter;
use lightning::util::logger::{Logger, Record};
use lightning_invoice::{Bolt11Invoice, InvoiceBuilder, Currency, DEFAULT_EXPIRY_TIME};

use bitcoin::Network;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};
use bitcoin::secp256k1::rand::{thread_rng, RngCore};

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use chrono::Utc;

pub const NETWORK: Network = Network::Bitcoin;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LightningInvoice {
    pub bolt11: String,
    pub payment_hash: String,
    pub amount_msats: Option<u64>,
    pub description: String,
    pub expiry_time: u64,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LightningPayment {
    pub payment_hash: String,
    pub amount_msats: u64,
    pub status: PaymentStatus,
    pub created_at: String,
    pub bolt11: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum PaymentStatus {
    Pending,
    Succeeded,
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LnurlPayRequest {
    pub callback: String,
    pub min_sendable: u64,
    pub max_sendable: u64,
    pub metadata: String,
    pub tag: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LnurlPayResponse {
    pub pr: String, // BOLT11 invoice
    pub success_action: Option<serde_json::Value>,
}

// Simple logger implementation
pub struct SimpleLogger;
impl Logger for SimpleLogger {
    fn log(&self, record: Record) {
        println!("⚡ [{}] {}", record.level, record.args);
    }
}

// Fee estimator implementation
pub struct SimpleFeeEstimator;
impl FeeEstimator for SimpleFeeEstimator {
    fn get_est_sat_per_1000_weight(&self, _confirmation_target: ConfirmationTarget) -> u32 {
        2000 // Simple fee rate for mainnet
    }
}

// Broadcaster implementation  
pub struct SimpleBroadcaster;
impl BroadcasterInterface for SimpleBroadcaster {
    fn broadcast_transactions(&self, txs: &[&bitcoin::Transaction]) {
        for tx in txs {
            println!("📡 Broadcasting Lightning transaction: {}", tx.txid());
            // In a real implementation, you'd broadcast to the Bitcoin network
        }
    }
}

// Simple filter implementation
pub struct SimpleFilter;
impl Filter for SimpleFilter {
    fn register_tx(&self, _txid: &bitcoin::Txid, _script_pubkey: &bitcoin::Script) {
        // Simple implementation for demo
    }

    fn register_output(&self, _output: lightning::chain::WatchedOutput) {
        // Simple implementation for demo  
    }
}

// Lightning Manager with real invoice generation
pub struct LightningManager {
    keys_manager: Arc<KeysManager>,
    logger: Arc<SimpleLogger>,
    pending_payments: Arc<Mutex<HashMap<String, LightningPayment>>>,
    invoices: Arc<Mutex<HashMap<String, LightningInvoice>>>,
    secp_ctx: Secp256k1<bitcoin::secp256k1::All>,
    node_secret: SecretKey,
    node_id: PublicKey,
}

impl LightningManager {
    pub fn new() -> Result<Self, String> {
        let logger = Arc::new(SimpleLogger);
        let secp_ctx = Secp256k1::new();
        
        // Generate random seed for keys manager
        let mut seed = [0u8; 32];
        thread_rng().fill_bytes(&mut seed);
        
        // Generate node secret key
        let mut node_secret_bytes = [0u8; 32];
        thread_rng().fill_bytes(&mut node_secret_bytes);
        let node_secret = SecretKey::from_slice(&node_secret_bytes)
            .map_err(|e| format!("Failed to create node secret: {}", e))?;
        
        let node_id = PublicKey::from_secret_key(&secp_ctx, &node_secret);
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| "Failed to get current time")?;
        
        let keys_manager = Arc::new(KeysManager::new(
            &seed,
            now.as_secs(),
            now.subsec_nanos(),
        ));

        println!("⚡ Lightning Manager initialized with node ID: {}", hex::encode(node_id.serialize()));

        Ok(LightningManager {
            keys_manager,
            logger,
            pending_payments: Arc::new(Mutex::new(HashMap::new())),
            invoices: Arc::new(Mutex::new(HashMap::new())),
            secp_ctx,
            node_secret,
            node_id,
        })
    }

    pub fn create_invoice(&self, amount_msats: Option<u64>, description: String) -> Result<LightningInvoice, String> {
        println!("⚡ Creating Lightning invoice for {} msats", amount_msats.unwrap_or(0));
        
        // Generate payment preimage and hash
        let mut preimage_bytes = [0u8; 32];
        thread_rng().fill_bytes(&mut preimage_bytes);
        let payment_preimage = PaymentPreimage(preimage_bytes);
        let payment_hash = PaymentHash(bitcoin::hashes::sha256::Hash::hash(&payment_preimage.0).to_byte_array());
        
        // Generate payment secret
        let mut secret_bytes = [0u8; 32];
        thread_rng().fill_bytes(&mut secret_bytes);
        let payment_secret = PaymentSecret(secret_bytes);
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| "Failed to get current time")?;
        
        // Create invoice using lightning-invoice
        let currency = Currency::Bitcoin;
        let mut invoice_builder = InvoiceBuilder::new(currency)
            .description(description.clone())
            .payment_hash(bitcoin::hashes::sha256::Hash::from_byte_array(payment_hash.0))
            .payment_secret(payment_secret)
            .current_timestamp()
            .min_final_cltv_expiry_delta(144);
        
        // Add amount if specified
        if let Some(amount) = amount_msats {
            invoice_builder = invoice_builder.amount_milli_satoshis(amount);
        }
        
        // Build and sign the invoice
        let invoice = invoice_builder
            .build_signed(|msg_hash| {
                self.secp_ctx.sign_ecdsa_recoverable(msg_hash, &self.node_secret)
            })
            .map_err(|e| format!("Failed to build invoice: {}", e))?;
        
        let bolt11 = invoice.to_string();
        let payment_hash_hex = hex::encode(payment_hash.0);
        let created_at = Utc::now().to_rfc3339();
        
        let lightning_invoice = LightningInvoice {
            bolt11: bolt11.clone(),
            payment_hash: payment_hash_hex.clone(),
            amount_msats,
            description,
            expiry_time: now.as_secs() + DEFAULT_EXPIRY_TIME,
            created_at,
        };

        // Store invoice
        self.invoices.lock().unwrap().insert(
            payment_hash_hex.clone(),
            lightning_invoice.clone()
        );

        println!("⚡ Successfully created invoice: {}", bolt11);
        
        // Demo mode: Auto-pay invoice after 3-6 seconds for hackathon demo
        let payment_hash_for_demo = payment_hash_hex.clone();
        let amount_for_demo = amount_msats.unwrap_or(0);
        let pending_payments_clone = self.pending_payments.clone();
        
        tokio::spawn(async move {
            // Random delay between 3-6 seconds to simulate real payment
            let delay = 3000 + (rand::thread_rng().next_u32() % 3000);
            tokio::time::sleep(Duration::from_millis(delay as u64)).await;
            
            println!("⚡ [DEMO AUTO-PAY] Simulating payment for invoice: {}", payment_hash_for_demo);
            
            // Create a successful payment record
            let payment = LightningPayment {
                payment_hash: payment_hash_for_demo.clone(),
                amount_msats: amount_for_demo,
                status: PaymentStatus::Succeeded,
                created_at: Utc::now().to_rfc3339(),
                bolt11: None,
            };

            // Store the payment
            pending_payments_clone.lock().unwrap().insert(
                payment_hash_for_demo.clone(),
                payment
            );

            println!("⚡ [DEMO AUTO-PAY] Payment completed successfully for: {}", payment_hash_for_demo);
        });

        Ok(lightning_invoice)
    }

    pub async fn pay_invoice(&self, bolt11: String) -> Result<LightningPayment, String> {
        println!("⚡ Attempting to pay Lightning invoice: {}", bolt11);
        
        // Parse the invoice
        let invoice = bolt11.parse::<Bolt11Invoice>()
            .map_err(|e| format!("Failed to parse BOLT11 invoice: {}", e))?;
        
        // Extract payment information
        let payment_hash = invoice.payment_hash();
        let payment_hash_hex = hex::encode(payment_hash.as_ref() as &[u8]);
        let amount_msats = invoice.amount_milli_satoshis().unwrap_or(0);
        let created_at = Utc::now().to_rfc3339();
        
        // Create payment record
        let payment = LightningPayment {
            payment_hash: payment_hash_hex.clone(),
            amount_msats,
            status: PaymentStatus::Pending,
            created_at,
            bolt11: Some(bolt11.clone()),
        };

        // Store pending payment
        self.pending_payments.lock().unwrap().insert(
            payment_hash_hex.clone(),
            payment.clone()
        );

        // Demo mode: Simulate realistic Lightning payment processing
        println!("⚡ Processing Lightning payment for {} msats...", amount_msats);
        println!("⚡ [DEMO MODE] Simulating Lightning Network routing...");
        
        // Simulate realistic processing time (1-3 seconds)
        let processing_time = 1000 + (thread_rng().next_u32() % 2000); // 1-3 seconds
        tokio::time::sleep(Duration::from_millis(processing_time as u64)).await;
        
        // For hackathon demo: Always succeed for reliable demo experience
        let success = true;
        
        // Update payment status
        let mut payments = self.pending_payments.lock().unwrap();
        if let Some(payment) = payments.get_mut(&payment_hash_hex) {
            payment.status = if success {
                PaymentStatus::Succeeded
            } else {
                PaymentStatus::Failed
            };
            
            println!("⚡ Payment {}: {}", 
                if success { "succeeded" } else { "failed" },
                payment_hash_hex
            );
        }

        Ok(payments.get(&payment_hash_hex).unwrap().clone())
    }

    pub async fn decode_lnurl(&self, lnurl: String) -> Result<LnurlPayRequest, String> {
        println!("⚡ Decoding LNURL: {}", lnurl);
        
        // Decode the LNURL
        let url = self.decode_lnurl_string(&lnurl)?;
        
        // Make HTTP request to get LNURL-pay info
        let client = reqwest::Client::new();
        let response = client.get(&url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch LNURL data: {}", e))?;
        
        let lnurl_response: LnurlPayRequest = response.json()
            .await
            .map_err(|e| format!("Failed to parse LNURL response: {}", e))?;
        
        println!("⚡ LNURL decoded successfully");
        Ok(lnurl_response)
    }

    pub async fn pay_lnurl(&self, callback: String, amount_msats: u64) -> Result<LightningPayment, String> {
        println!("⚡ Paying LNURL: {} for {} msats", callback, amount_msats);
        
        // Make callback request to get invoice
        let client = reqwest::Client::new();
        let callback_url = format!("{}?amount={}", callback, amount_msats);
        
        let response = client.get(&callback_url)
            .send()
            .await
            .map_err(|e| format!("Failed to get LNURL invoice: {}", e))?;
        
        let lnurl_response: LnurlPayResponse = response.json()
            .await
            .map_err(|e| format!("Failed to parse LNURL callback response: {}", e))?;
        
        // Pay the returned invoice
        self.pay_invoice(lnurl_response.pr).await
    }

    pub fn get_payment_status(&self, payment_hash: &str) -> Option<PaymentStatus> {
        self.pending_payments.lock().unwrap()
            .get(payment_hash)
            .map(|p| p.status.clone())
    }

    pub fn list_payments(&self) -> Vec<LightningPayment> {
        self.pending_payments.lock().unwrap()
            .values()
            .cloned()
            .collect()
    }

    pub fn list_invoices(&self) -> Vec<LightningInvoice> {
        self.invoices.lock().unwrap()
            .values()
            .cloned()
            .collect()
    }

    pub fn get_node_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("node_id".to_string(), hex::encode(self.node_id.serialize()));
        info.insert("network".to_string(), "mainnet".to_string());
        info.insert("implementation".to_string(), "LDK-based".to_string());
        info
    }

    // Demo method to mark invoice as paid
    pub async fn mark_invoice_as_paid(&self, payment_hash: &str, amount_msats: u64) {
        println!("⚡ [DEMO] Marking invoice as paid: {} for {} msats", payment_hash, amount_msats);
        
        // Create a successful payment record
        let payment = LightningPayment {
            payment_hash: payment_hash.to_string(),
            amount_msats,
            status: PaymentStatus::Succeeded,
            created_at: Utc::now().to_rfc3339(),
            bolt11: None,
        };

        // Store the payment
        self.pending_payments.lock().unwrap().insert(
            payment_hash.to_string(),
            payment
        );

        println!("⚡ [DEMO] Payment recorded successfully!");
    }

    fn decode_lnurl_string(&self, lnurl: &str) -> Result<String, String> {
        // Remove lnurl prefix if present
        let lnurl_data = if lnurl.to_lowercase().starts_with("lnurl") {
            &lnurl[5..]
        } else {
            lnurl
        };
        
        // Decode bech32
        let (hrp, data, _variant) = bech32::decode(lnurl_data)
            .map_err(|e| format!("Failed to decode LNURL bech32: {}", e))?;
        
        if hrp != "lnurl" {
            return Err("Invalid LNURL prefix".to_string());
        }
        
        // Convert to bytes
        let bytes = bech32::convert_bits(&data, 5, 8, false)
            .map_err(|_| "Failed to convert LNURL bits")?;
        
        // Convert to string
        String::from_utf8(bytes)
            .map_err(|e| format!("Failed to decode LNURL to string: {}", e))
    }
} 
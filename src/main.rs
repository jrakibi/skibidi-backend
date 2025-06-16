use actix_web::{post, get, web, App, HttpServer, Responder, Result as ActixResult, HttpResponse};
use bdk::database::MemoryDatabase;
use bdk::wallet::AddressIndex::New;
use bdk::{Wallet, FeeRate, SignOptions, SyncOptions};
use bdk::keys::{ExtendedKey, GeneratedKey, GeneratableKey, DerivableKey};
use bdk::keys::bip39::{Mnemonic, Language, WordCount};
use bdk::blockchain::esplora::EsploraBlockchain;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use bdk::bitcoin::{Address, Network};
use bdk::descriptor::Segwitv0;
use std::str::FromStr;

mod lightning;
use lightning::{LightningManager, LightningInvoice, LightningPayment};

// Global wallet storage (persistent using sled)
type WalletStorage = Mutex<sled::Db>;

// Wallet metadata for persistence
#[derive(Serialize, Deserialize, Clone)]
struct WalletMeta {
    mnemonic: String,
    wallet_id: String,
    created_at: u64,
}

// Global Lightning manager
type LightningStorage = Mutex<Option<LightningManager>>;

// Blockchain backend configuration
#[derive(Debug, Clone)]
struct BlockchainBackend {
    name: &'static str,
    url: &'static str,
    timeout: usize,
}

// Define multiple blockchain backends for redundancy
const BLOCKCHAIN_BACKENDS: &[BlockchainBackend] = &[
    BlockchainBackend {
        name: "Mempool.space",
        url: "https://mempool.space/testnet/api",
        timeout: 20,
    },
    BlockchainBackend {
        name: "Blockstream",
        url: "https://blockstream.info/testnet/api",
        timeout: 20,
    },
    BlockchainBackend {
        name: "Bitcoin Explorer",
        url: "https://bitcoin-testnet.explorer.com/api",
        timeout: 15,
    },
];

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Serialize)]
struct WalletInfo {
    mnemonic: String,
    address: String,
    wallet_id: String,
    backend_used: String,
}

#[derive(Serialize)]
struct BalanceInfo {
    confirmed: u64,
    unconfirmed: u64,
    total: u64,
    backend_used: String,
}

#[derive(Serialize)]
struct TransactionInfo {
    txid: String,
    amount: i64,
    confirmations: u32,
    timestamp: Option<u64>,
}

#[derive(Deserialize)]
struct RestoreWalletRequest {
    mnemonic: String,
}

#[derive(Deserialize)]
struct SendBitcoinRequest {
    wallet_id: String,
    to_address: String,
    amount_sats: u64,
}

#[derive(Deserialize)]
struct WalletRequest {
    wallet_id: String,
}

#[derive(Deserialize)]
struct CreateLightningInvoiceRequest {
    amount_msats: Option<u64>,
    description: String,
}

#[derive(Deserialize)]
struct PayLightningInvoiceRequest {
    bolt11: String,
}

#[derive(Deserialize)]
struct PayLnurlRequest {
    lnurl: String,
    amount_msats: u64,
}

fn create_wallet_from_mnemonic(mnemonic_str: &str) -> Result<(Wallet<MemoryDatabase>, String), String> {
    let mnemonic = Mnemonic::parse(mnemonic_str)
        .map_err(|e| format!("Invalid mnemonic: {}", e))?;
    
    let xkey: ExtendedKey = (mnemonic, None).into_extended_key()
        .map_err(|e| format!("Failed to create extended key: {}", e))?;
    
    let xprv = match xkey.into_xprv(Network::Testnet) {
        Some(key) => key,
        None => return Err("Failed to create private key".to_string()),
    };
    
    // Use no derivation path - just the master private key directly
    // This matches the expected behavior for the existing mnemonic
    let descriptor = format!("wpkh({})", xprv);
    
    println!("🔑 Using descriptor: wpkh({})", "[xprv_hidden]");
    
    let wallet = Wallet::new(
        &descriptor,
        None,
        Network::Testnet,
        MemoryDatabase::default(),
    ).map_err(|e| format!("Failed to create wallet: {}", e))?;

    let address = wallet.get_address(New)
        .map_err(|e| format!("Failed to get address: {}", e))?;

    println!("📍 Generated address: {}", address);

    Ok((wallet, address.to_string()))
}

fn try_blockchain_backends<F, T>(operation_name: &str, operation: F) -> Result<(T, String), String>
where
    F: Fn(&EsploraBlockchain) -> Result<T, bdk::Error> + Copy,
{
    let mut last_error = String::new();
    
    for backend in BLOCKCHAIN_BACKENDS {
        println!("🔄 Trying {} for {}...", backend.name, operation_name);
        
        let blockchain = EsploraBlockchain::new(backend.url, backend.timeout);
        
        match operation(&blockchain) {
            Ok(result) => {
                println!("✅ Successfully used {} for {}", backend.name, operation_name);
                return Ok((result, backend.name.to_string()));
            }
            Err(e) => {
                let error_msg = format!("{} failed: {}", backend.name, e);
                println!("❌ {}", error_msg);
                last_error = error_msg;
                continue;
            }
        }
    }
    
    Err(format!("All backends failed. Last error: {}", last_error))
}

fn sync_wallet(wallet: &Wallet<MemoryDatabase>) -> Result<String, String> {
    println!("🔄 Syncing wallet with multiple blockchain backends (testnet)...");

    let (_, backend_name) = try_blockchain_backends("wallet sync", |blockchain| {
        wallet.sync(blockchain, SyncOptions::default())
    })?;

    println!("🎯 Wallet synced successfully using {}", backend_name);
    Ok(backend_name)
}

fn broadcast_transaction(_wallet: &Wallet<MemoryDatabase>, tx: &bdk::bitcoin::Transaction) -> Result<String, String> {
    println!("📡 Broadcasting transaction via multiple backends...");

    let (_, backend_name) = try_blockchain_backends("transaction broadcast", |blockchain| {
        blockchain.broadcast(tx).map_err(|e| bdk::Error::Generic(e.to_string()))
    })?;

    println!("✅ Transaction broadcasted successfully via {}!", backend_name);
    Ok(backend_name)
}

// Helper functions for persistent wallet storage
fn save_wallet_meta(db: &sled::Db, wallet_id: &str, mnemonic: &str) -> Result<(), String> {
    let meta = WalletMeta {
        mnemonic: mnemonic.to_string(),
        wallet_id: wallet_id.to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    
    let serialized = serde_json::to_vec(&meta)
        .map_err(|e| format!("Failed to serialize wallet metadata: {}", e))?;
    
    db.insert(wallet_id.as_bytes(), serialized)
        .map_err(|e| format!("Failed to save wallet metadata: {}", e))?;
    
    Ok(())
}

fn load_wallet_meta(db: &sled::Db, wallet_id: &str) -> Result<Option<WalletMeta>, String> {
    match db.get(wallet_id.as_bytes()) {
        Ok(Some(data)) => {
            let meta: WalletMeta = serde_json::from_slice(&data)
                .map_err(|e| format!("Failed to deserialize wallet metadata: {}", e))?;
            Ok(Some(meta))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(format!("Failed to load wallet metadata: {}", e)),
    }
}

fn get_or_create_wallet(db: &sled::Db, wallet_id: &str) -> Result<Wallet<MemoryDatabase>, String> {
    // Try to load wallet metadata from persistent storage
    let meta = load_wallet_meta(db, wallet_id)?;
    
    match meta {
        Some(wallet_meta) => {
            // Recreate wallet from stored mnemonic
            let (wallet, _) = create_wallet_from_mnemonic(&wallet_meta.mnemonic)?;
            println!("🔄 Restored wallet {} from persistent storage", wallet_id);
            Ok(wallet)
        }
        None => {
            Err("Wallet not found".to_string())
        }
    }
}

#[post("/create-wallet")]
async fn create_wallet(storage: web::Data<WalletStorage>) -> ActixResult<HttpResponse> {
    // Generate a new 12-word mnemonic
    let mnemonic: GeneratedKey<Mnemonic, Segwitv0> = match Mnemonic::generate((WordCount::Words12, Language::English)) {
        Ok(m) => m,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to generate mnemonic: {:?}", e)),
        })),
    };

    let mnemonic_str = mnemonic.to_string();
    
    let (wallet, address) = match create_wallet_from_mnemonic(&mnemonic_str) {
        Ok((w, a)) => (w, a),
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e),
        })),
    };

    // Sync wallet with multiple backends
    let backend_used = match sync_wallet(&wallet) {
        Ok(backend) => backend,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e),
        })),
    };

    // Generate wallet ID
    let wallet_id = format!("wallet_{}", uuid::Uuid::new_v4().to_string()[..8].to_lowercase());
    
    // Save wallet metadata to persistent storage
    let db = storage.lock().unwrap();
    if let Err(e) = save_wallet_meta(&db, &wallet_id, &mnemonic_str) {
        return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to save wallet: {}", e)),
        }));
    }

    println!("✅ Wallet {} created and saved to persistent storage", wallet_id);

    let wallet_info = WalletInfo {
        mnemonic: mnemonic_str,
        address,
        wallet_id,
        backend_used,
    };

    Ok(HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(wallet_info),
        error: None,
    }))
}

#[post("/restore-wallet")]
async fn restore_wallet(
    request: web::Json<RestoreWalletRequest>,
    storage: web::Data<WalletStorage>
) -> ActixResult<HttpResponse> {
    let (wallet, address) = match create_wallet_from_mnemonic(&request.mnemonic) {
        Ok((w, a)) => (w, a),
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e),
        })),
    };

    // Sync wallet with multiple backends
    let backend_used = match sync_wallet(&wallet) {
        Ok(backend) => backend,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e),
        })),
    };

    // Generate wallet ID
    let wallet_id = format!("wallet_{}", uuid::Uuid::new_v4().to_string()[..8].to_lowercase());
    
    // Save wallet metadata to persistent storage
    let db = storage.lock().unwrap();
    if let Err(e) = save_wallet_meta(&db, &wallet_id, &request.mnemonic) {
        return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to save wallet: {}", e)),
        }));
    }

    println!("✅ Wallet {} restored and saved to persistent storage", wallet_id);

    let wallet_info = WalletInfo {
        mnemonic: request.mnemonic.clone(),
        address,
        wallet_id,
        backend_used,
    };

    Ok(HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(wallet_info),
        error: None,
    }))
}

#[post("/get-balance")]
async fn get_balance(
    request: web::Json<WalletRequest>,
    storage: web::Data<WalletStorage>
) -> ActixResult<HttpResponse> {
    let db = storage.lock().unwrap();
    let mut wallet = match get_or_create_wallet(&db, &request.wallet_id) {
        Ok(w) => w,
        Err(e) => return Ok(HttpResponse::NotFound().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e),
        })),
    };

    // Sync wallet before getting balance
    let backend_used = match sync_wallet(&wallet) {
        Ok(backend) => backend,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Sync failed: {}", e)),
        })),
    };

    let balance = match wallet.get_balance() {
        Ok(b) => b,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to get balance: {}", e)),
        })),
    };

    let balance_info = BalanceInfo {
        confirmed: balance.confirmed,
        unconfirmed: balance.untrusted_pending + balance.trusted_pending,
        total: balance.confirmed + balance.untrusted_pending + balance.trusted_pending,
        backend_used,
    };

    Ok(HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(balance_info),
        error: None,
    }))
}

#[post("/get-transactions")]
async fn get_transactions(
    request: web::Json<WalletRequest>,
    storage: web::Data<WalletStorage>
) -> ActixResult<HttpResponse> {
    let db = storage.lock().unwrap();
    let mut wallet = match get_or_create_wallet(&db, &request.wallet_id) {
        Ok(w) => w,
        Err(e) => return Ok(HttpResponse::NotFound().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e),
        })),
    };

    // Sync wallet before getting transactions
    if let Err(e) = sync_wallet(&wallet) {
        return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Sync failed: {}", e)),
        }));
    }

    let transactions = match wallet.list_transactions(false) {
        Ok(txs) => txs,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to get transactions: {}", e)),
        })),
    };

    let tx_info: Vec<TransactionInfo> = transactions.iter().map(|tx| {
        TransactionInfo {
            txid: tx.txid.to_string(),
            amount: tx.received as i64 - tx.sent as i64,
            confirmations: tx.confirmation_time.as_ref().map_or(0, |c| c.height as u32),
            timestamp: tx.confirmation_time.as_ref().map(|c| c.timestamp),
        }
    }).collect();

    Ok(HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(tx_info),
        error: None,
    }))
}

#[post("/get-address")]
async fn get_address(
    request: web::Json<WalletRequest>,
    storage: web::Data<WalletStorage>
) -> ActixResult<HttpResponse> {
    let db = storage.lock().unwrap();
    let wallet = match get_or_create_wallet(&db, &request.wallet_id) {
        Ok(w) => w,
        Err(e) => return Ok(HttpResponse::NotFound().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e),
        })),
    };

    let address = match wallet.get_address(New) {
        Ok(addr) => addr,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to get address: {}", e)),
        })),
    };

    Ok(HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(address.to_string()),
        error: None,
    }))
}

#[post("/send-bitcoin")]
async fn send_bitcoin(
    request: web::Json<SendBitcoinRequest>,
    storage: web::Data<WalletStorage>
) -> ActixResult<HttpResponse> {
    let db = storage.lock().unwrap();
    let mut wallet = match get_or_create_wallet(&db, &request.wallet_id) {
        Ok(w) => w,
        Err(e) => return Ok(HttpResponse::NotFound().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e),
        })),
    };

    // Sync wallet before sending
    let backend_used = match sync_wallet(&wallet) {
        Ok(backend) => backend,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Sync failed: {}", e)),
        })),
    };

    // Parse recipient address
    let recipient = match Address::from_str(&request.to_address) {
        Ok(addr) => match addr.require_network(Network::Testnet) {
            Ok(checked_addr) => checked_addr,
            Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(format!("Address network mismatch: {}", e)),
            })),
        },
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Invalid address: {}", e)),
        })),
    };

    // Create transaction builder
    let mut tx_builder = wallet.build_tx();
    tx_builder
        .add_recipient(recipient.script_pubkey(), request.amount_sats)
        .enable_rbf()
        .fee_rate(FeeRate::from_sat_per_vb(1.0)); // 1 sat/vB fee rate

    // Build transaction
    let (mut psbt, tx_details) = match tx_builder.finish() {
        Ok(result) => result,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to build transaction: {}", e)),
        })),
    };

    // Sign transaction
    let finalized = match wallet.sign(&mut psbt, SignOptions::default()) {
        Ok(f) => f,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to sign transaction: {}", e)),
        })),
    };

    if !finalized {
        return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Transaction not fully signed".to_string()),
        }));
    }

    // Extract signed transaction
    let tx = psbt.extract_tx();

    // Broadcast transaction
    match broadcast_transaction(&wallet, &tx) {
        Ok(backend_name) => {
            println!("🎯 Transaction {} sent successfully via {}", tx.txid(), backend_name);
            Ok(HttpResponse::Ok().json(ApiResponse {
                success: true,
                data: Some(serde_json::json!({
                    "txid": tx.txid().to_string(),
                    "fee": tx_details.fee.unwrap_or(0),
                    "backend_used": backend_name
                })),
                error: None,
            }))
        }
        Err(e) => Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Broadcast failed: {}", e)),
        })),
    }
}

#[get("/backend-status")]
async fn backend_status() -> impl Responder {
    let mut status_results = Vec::new();
    
    for backend in BLOCKCHAIN_BACKENDS {
        let blockchain = EsploraBlockchain::new(backend.url, backend.timeout);
        
        // Try a simple operation to test connectivity
        let status = match blockchain.get_height() {
            Ok(height) => serde_json::json!({
                "name": backend.name,
                "url": backend.url,
                "status": "✅ Available",
                "height": height
            }),
            Err(e) => serde_json::json!({
                "name": backend.name,
                "url": backend.url,
                "status": format!("❌ Unavailable: {}", e),
                "height": null
            })
        };
        
        status_results.push(status);
    }
    
    HttpResponse::Ok().json(serde_json::json!({
        "blockchain_backends": status_results,
        "total_backends": BLOCKCHAIN_BACKENDS.len()
    }))
}

#[get("/")]
async fn health_check() -> impl Responder {
    let backends: Vec<String> = BLOCKCHAIN_BACKENDS
        .iter()
        .map(|b| format!("{} ({})", b.name, b.url))
        .collect();

    HttpResponse::Ok().json(serde_json::json!({
        "status": "🚀 Skibidi Wallet Backend is running!",
        "network": "testnet",
        "blockchain_backends": backends,
        "redundancy": "✅ Multiple backends with automatic failover",
        "endpoints": [
            "POST /create-wallet",
            "POST /restore-wallet", 
            "POST /get-balance",
            "POST /get-transactions",
            "POST /get-address",
            "POST /send-bitcoin",
            "GET /backend-status"
        ]
    }))
}

// Lightning Network Endpoints

#[post("/lightning/create-invoice")]
async fn create_lightning_invoice(
    request: web::Json<CreateLightningInvoiceRequest>,
    lightning_storage: web::Data<LightningStorage>
) -> ActixResult<HttpResponse> {
    let mut lightning_guard = lightning_storage.lock().unwrap();
    
    // Initialize Lightning manager if not exists
    if lightning_guard.is_none() {
        match LightningManager::new() {
            Ok(manager) => *lightning_guard = Some(manager),
            Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(format!("Failed to initialize Lightning: {}", e)),
            })),
        }
    }

    let lightning_manager = lightning_guard.as_ref().unwrap();
    
    match lightning_manager.create_invoice(request.amount_msats, request.description.clone()) {
        Ok(invoice) => Ok(HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(invoice),
            error: None,
        })),
        Err(e) => Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to create invoice: {}", e)),
        })),
    }
}

#[post("/lightning/pay-invoice")]
async fn pay_lightning_invoice(
    request: web::Json<PayLightningInvoiceRequest>,
    lightning_storage: web::Data<LightningStorage>
) -> ActixResult<HttpResponse> {
    let mut lightning_guard = lightning_storage.lock().unwrap();
    
    // Initialize Lightning manager if not exists
    if lightning_guard.is_none() {
        match LightningManager::new() {
            Ok(manager) => *lightning_guard = Some(manager),
            Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(format!("Failed to initialize Lightning: {}", e)),
            })),
        }
    }

    let lightning_manager = lightning_guard.as_ref().unwrap();
    
    // Clone the manager to avoid holding the lock during async operation
    match lightning_manager.pay_invoice(request.bolt11.clone()).await {
        Ok(payment) => Ok(HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(payment),
            error: None,
        })),
        Err(e) => Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Payment failed: {}", e)),
        })),
    }
}

#[post("/lightning/pay-lnurl")]
async fn pay_lnurl(
    request: web::Json<PayLnurlRequest>,
    lightning_storage: web::Data<LightningStorage>
) -> ActixResult<HttpResponse> {
    let mut lightning_guard = lightning_storage.lock().unwrap();
    
    // Initialize Lightning manager if not exists
    if lightning_guard.is_none() {
        match LightningManager::new() {
            Ok(manager) => *lightning_guard = Some(manager),
            Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(format!("Failed to initialize Lightning: {}", e)),
            })),
        }
    }

    let lightning_manager = lightning_guard.as_ref().unwrap();
    
    // First decode LNURL
    match lightning_manager.decode_lnurl(request.lnurl.clone()).await {
        Ok(lnurl_request) => {
            // Check amount limits
            if request.amount_msats < lnurl_request.min_sendable || request.amount_msats > lnurl_request.max_sendable {
                return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some(format!("Amount {} msats is outside allowed range ({}-{})", 
                        request.amount_msats, lnurl_request.min_sendable, lnurl_request.max_sendable)),
                }));
            }

            // Pay via LNURL callback
            match lightning_manager.pay_lnurl(lnurl_request.callback, request.amount_msats).await {
                Ok(payment) => Ok(HttpResponse::Ok().json(ApiResponse {
                    success: true,
                    data: Some(payment),
                    error: None,
                })),
                Err(e) => Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some(format!("LNURL payment failed: {}", e)),
                })),
            }
        },
        Err(e) => Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Invalid LNURL: {}", e)),
        })),
    }
}

#[get("/lightning/payments")]
async fn get_lightning_payments(
    lightning_storage: web::Data<LightningStorage>
) -> ActixResult<HttpResponse> {
    let lightning_guard = lightning_storage.lock().unwrap();
    
    if let Some(lightning_manager) = lightning_guard.as_ref() {
        let payments = lightning_manager.list_payments();
        Ok(HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(payments),
            error: None,
        }))
    } else {
        Ok(HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(Vec::<LightningPayment>::new()),
            error: None,
        }))
    }
}

#[get("/lightning/invoices")]
async fn get_lightning_invoices(
    lightning_storage: web::Data<LightningStorage>
) -> ActixResult<HttpResponse> {
    let lightning_guard = lightning_storage.lock().unwrap();
    
    if let Some(lightning_manager) = lightning_guard.as_ref() {
        let invoices = lightning_manager.list_invoices();
        Ok(HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(invoices),
            error: None,
        }))
    } else {
        Ok(HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(Vec::<LightningInvoice>::new()),
            error: None,
        }))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let wallet_storage = web::Data::new(Mutex::new(sled::open("wallet_storage.sled")?));
    let lightning_storage = web::Data::new(LightningStorage::new(None));
    
    println!("🚀 Skibidi Wallet Backend (TESTNET) running on all interfaces at port 8080");
    println!("🌐 Local access: http://192.168.1.5:8080");
    println!("📱 Mobile access: http://[YOUR_IP]:8080 (replace [YOUR_IP] with your machine's IP)");
    println!("💰 Network: Bitcoin Testnet");
    println!("⚡ Lightning Network: ENABLED for instant micro payments!");
    println!("🔄 Multiple blockchain backends configured:");
    for backend in BLOCKCHAIN_BACKENDS {
        println!("   • {} - {}", backend.name, backend.url);
    }
    println!("⚡ Automatic failover enabled for maximum reliability!");
    println!("🎮 Ready for real Bitcoin + Lightning testing!");
    
    HttpServer::new(move || {
        App::new()
            .app_data(wallet_storage.clone())
            .app_data(lightning_storage.clone())
            .service(health_check)
            .service(backend_status)
            .service(create_wallet)
            .service(restore_wallet)
            .service(get_balance)
            .service(get_transactions)
            .service(get_address)
            .service(send_bitcoin)
            // Lightning endpoints
            .service(create_lightning_invoice)
            .service(pay_lightning_invoice)
            .service(pay_lnurl)
            .service(get_lightning_payments)
            .service(get_lightning_invoices)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}

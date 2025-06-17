use actix_web::{post, get, web, App, HttpServer, Responder, Result as ActixResult, HttpResponse};
use bdk::database::MemoryDatabase;
use bdk::wallet::AddressIndex::New;
use bdk::{Wallet, FeeRate, SignOptions, SyncOptions};
use bdk::keys::{ExtendedKey, GeneratedKey, GeneratableKey, DerivableKey};
use bdk::keys::bip39::{Mnemonic, Language, WordCount};
use bdk::blockchain::esplora::EsploraBlockchain;
use serde::{Deserialize, Serialize};
use bdk::bitcoin::{Address, Network};
use bdk::descriptor::Segwitv0;
use std::str::FromStr;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// Function to generate consistent wallet ID from mnemonic
fn generate_wallet_id(mnemonic: &str) -> String {
    let mut hasher = DefaultHasher::new();
    mnemonic.hash(&mut hasher);
    format!("wallet_{:x}", hasher.finish())
}

mod lightning;
use lightning::{LightningManager, LightningInvoice, LightningPayment};

// Global Lightning manager (only non-sensitive Lightning data)
type LightningStorage = std::sync::Mutex<Option<LightningManager>>;

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
        url: "https://mempool.space/api",
        timeout: 20,
    },
    BlockchainBackend {
        name: "Blockstream",
        url: "https://blockstream.info/api",
        timeout: 20,
    },
    BlockchainBackend {
        name: "Bitcoin Explorer",
        url: "https://bitcoin.explorer.com/api",
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
    wallet_id: String,
    mnemonic: String,
    address: String,
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

// Updated request structures - now include mnemonic for stateless operation
#[derive(Deserialize)]
struct RestoreWalletRequest {
    mnemonic: String,
}

#[derive(Deserialize)]
struct SendBitcoinRequest {
    mnemonic: String,  // Client provides mnemonic for each transaction
    to_address: String,
    amount_sats: u64,
}

#[derive(Deserialize)]
struct WalletOperationRequest {
    mnemonic: String,  // Client provides mnemonic for each operation
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
    
    let xprv = match xkey.into_xprv(Network::Bitcoin) {
        Some(key) => key,
        None => return Err("Failed to create private key".to_string()),
    };
    
    // Use no derivation path - just the master private key directly
    let descriptor = format!("wpkh({})", xprv);
    
    println!("🔑 Creating wallet from mnemonic (descriptor hidden for security)");
    
    let wallet = Wallet::new(
        &descriptor,
        None,
        Network::Bitcoin,
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
    println!("🔄 Syncing wallet with blockchain backends (mainnet)...");

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

    println!("🎯 Transaction broadcast successful using {}", backend_name);
    Ok(backend_name)
}

// SECURE API ENDPOINTS - NO SERVER-SIDE STORAGE

#[post("/create-wallet")]
async fn create_wallet() -> ActixResult<HttpResponse> {
    println!("🔐 Creating new wallet (stateless)");
    
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

    // Sync wallet with blockchain
    let backend_used = match sync_wallet(&wallet) {
        Ok(backend) => backend,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e),
        })),
    };

    println!("✅ New wallet created successfully (not stored on server)");

    let wallet_info = WalletInfo {
        wallet_id: generate_wallet_id(&mnemonic_str),
        mnemonic: mnemonic_str,
        address,
        backend_used,
    };

    Ok(HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(wallet_info),
        error: None,
    }))
}

#[post("/restore-wallet")]
async fn restore_wallet(request: web::Json<RestoreWalletRequest>) -> ActixResult<HttpResponse> {
    println!("🔐 Restoring wallet from mnemonic (stateless)");
    
    let (wallet, address) = match create_wallet_from_mnemonic(&request.mnemonic) {
        Ok((w, a)) => (w, a),
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e),
        })),
    };

    // Sync wallet with blockchain
    let backend_used = match sync_wallet(&wallet) {
        Ok(backend) => backend,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e),
        })),
    };

    println!("✅ Wallet restored successfully (not stored on server)");

    let wallet_info = WalletInfo {
        wallet_id: generate_wallet_id(&request.mnemonic),
        mnemonic: request.mnemonic.clone(),
        address,
        backend_used,
    };

    Ok(HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(wallet_info),
        error: None,
    }))
}

#[post("/get-balance")]
async fn get_balance(request: web::Json<WalletOperationRequest>) -> ActixResult<HttpResponse> {
    println!("💰 Getting balance for wallet (stateless)");
    
    let wallet = match create_wallet_from_mnemonic(&request.mnemonic) {
        Ok((w, _)) => w,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e),
        })),
    };

    // Sync wallet to get latest balance
    let backend_used = match sync_wallet(&wallet) {
        Ok(backend) => backend,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Sync failed: {}", e)),
        })),
    };

    let balance = wallet.get_balance().unwrap();
    
    println!("💰 Balance retrieved: {} sats", balance.confirmed + balance.trusted_pending + balance.untrusted_pending);

    let balance_info = BalanceInfo {
        confirmed: balance.confirmed,
        unconfirmed: balance.trusted_pending + balance.untrusted_pending,
        total: balance.confirmed + balance.trusted_pending + balance.untrusted_pending,
        backend_used,
    };

    Ok(HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(balance_info),
        error: None,
    }))
}

#[post("/get-transactions")]
async fn get_transactions(request: web::Json<WalletOperationRequest>) -> ActixResult<HttpResponse> {
    println!("📋 Getting transactions for wallet (stateless)");
    
    let wallet = match create_wallet_from_mnemonic(&request.mnemonic) {
        Ok((w, _)) => w,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e),
        })),
    };

    // Sync wallet to get latest transactions
    let backend_used = match sync_wallet(&wallet) {
        Ok(backend) => backend,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Sync failed: {}", e)),
        })),
    };

    let transactions = wallet.list_transactions(false).unwrap();
    let tx_info: Vec<TransactionInfo> = transactions
        .into_iter()
        .map(|tx| TransactionInfo {
            txid: tx.txid.to_string(),
            amount: tx.received as i64 - tx.sent as i64,
            confirmations: tx.confirmation_time.as_ref().map_or(0, |ct| ct.height),
            timestamp: tx.confirmation_time.as_ref().map(|ct| ct.timestamp),
        })
        .collect();

    println!("📋 Retrieved {} transactions", tx_info.len());

    Ok(HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(tx_info),
        error: None,
    }))
}

#[post("/get-address")]
async fn get_address(request: web::Json<WalletOperationRequest>) -> ActixResult<HttpResponse> {
    println!("📍 Getting address for wallet (stateless)");
    
    let (wallet, address) = match create_wallet_from_mnemonic(&request.mnemonic) {
        Ok((w, a)) => (w, a),
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e),
        })),
    };

    println!("📍 Address retrieved: {}", address);

    Ok(HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(address),
        error: None,
    }))
}

#[post("/send-bitcoin")]
async fn send_bitcoin(request: web::Json<SendBitcoinRequest>) -> ActixResult<HttpResponse> {
    println!("💸 Sending Bitcoin (stateless)");
    
    let wallet = match create_wallet_from_mnemonic(&request.mnemonic) {
        Ok((w, _)) => w,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
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
        Ok(addr) => match addr.require_network(Network::Bitcoin) {
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
        "status": "🚀 Skibidi Wallet Backend is running! (Secure & Stateless)",
        "network": "mainnet",
        "security": "🔒 No sensitive data stored on server",
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

// Lightning Network Endpoints (unchanged - Lightning data is not as sensitive)

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
    
    if lightning_guard.is_none() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Lightning not initialized".to_string()),
        }));
    }

    let lightning_manager = lightning_guard.as_ref().unwrap();
    
    match lightning_manager.pay_invoice(request.bolt11.clone()).await {
        Ok(payment) => Ok(HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(payment),
            error: None,
        })),
        Err(e) => Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to pay invoice: {}", e)),
        })),
    }
}

#[post("/lightning/pay-lnurl")]
async fn pay_lnurl(
    request: web::Json<PayLnurlRequest>,
    lightning_storage: web::Data<LightningStorage>
) -> ActixResult<HttpResponse> {
    let mut lightning_guard = lightning_storage.lock().unwrap();
    
    if lightning_guard.is_none() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Lightning not initialized".to_string()),
        }));
    }

    let lightning_manager = lightning_guard.as_ref().unwrap();
    
    match lightning_manager.pay_lnurl(request.lnurl.clone(), request.amount_msats).await {
        Ok(payment) => Ok(HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(payment),
            error: None,
        })),
        Err(e) => Ok(HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to pay LNURL: {}", e)),
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
    println!("🚀 Starting Skibidi Wallet Backend (Secure & Stateless)");
    println!("🔒 No sensitive wallet data stored on server");
    println!("🌐 Network: Mainnet");
    println!("⚡ Lightning Network: Enabled");
    
    // Initialize Lightning storage (only for Lightning-specific data)
    let lightning_storage = web::Data::new(LightningStorage::new(None));

    HttpServer::new(move || {
        App::new()
            .app_data(lightning_storage.clone())
            // Wallet endpoints (stateless)
            .service(create_wallet)
            .service(restore_wallet)
            .service(get_balance)
            .service(get_transactions)
            .service(get_address)
            .service(send_bitcoin)
            // System endpoints
            .service(backend_status)
            .service(health_check)
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

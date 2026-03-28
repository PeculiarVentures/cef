//! CEF interop helper — used by test/interop.mjs
use std::io::{self, Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cef_interop <keygen|encrypt|decrypt> [args...]");
        std::process::exit(1);
    }
    match args[1].as_str() {
        "keygen" => keygen(),
        "encrypt" => encrypt(&args[2..]),
        "decrypt" => decrypt(&args[2..]),
        _ => { eprintln!("Unknown command: {}", args[1]); std::process::exit(1); }
    }
}

fn keygen() {
    let kem = cef::format::pq::mlkem_keygen();
    let dsa = cef::format::pq::mldsa_keygen();
    // Output as hex, one per line: kem_pk, kem_sk, dsa_pk, dsa_sk
    println!("{}", hex::encode(&kem.public_key));
    println!("{}", hex::encode(&kem.secret_key));
    println!("{}", hex::encode(&dsa.public_key));
    println!("{}", hex::encode(&dsa.secret_key));
}

fn encrypt(args: &[String]) {
    // Args: sender_dsa_sk_hex sender_kid recipient_kem_pk_hex recipient_kid
    if args.len() < 4 {
        eprintln!("encrypt: need sender_sk sender_kid recip_pk recip_kid");
        std::process::exit(1);
    }
    let sender_sk = hex::decode(&args[0]).unwrap();
    let sender_kid = &args[1];
    let recip_pk = hex::decode(&args[2]).unwrap();
    let recip_kid = &args[3];

    // Read plaintext files from stdin as JSON: [{"name":"...","data":"base64..."}]
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let files_json: Vec<serde_json::Value> = serde_json::from_str(&input).unwrap();

    let files: Vec<cef::FileInput> = files_json.iter().map(|f| {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(f["data"].as_str().unwrap()).unwrap();
        cef::FileInput {
            name: f["name"].as_str().unwrap().to_string(),
            data,
            content_type: None,
        }
    }).collect();

    let result = cef::encrypt(cef::EncryptOptions {
        files,
        sender: cef::Sender {
            signing_key: sender_sk,
            kid: sender_kid.to_string(),
            x5c: None,
            claims: None,
        },
        recipients: vec![cef::Recipient {
            kid: recip_kid.to_string(),
            encryption_key: recip_pk,
            recipient_type: None,
        }],
        timestamp: None,
    }).unwrap();

    io::stdout().write_all(&result.container).unwrap();
}

fn decrypt(args: &[String]) {
    // Args: recip_kem_sk_hex recip_kid sender_dsa_pk_hex
    if args.len() < 3 {
        eprintln!("decrypt: need recip_sk recip_kid sender_pk");
        std::process::exit(1);
    }
    let recip_sk = hex::decode(&args[0]).unwrap();
    let recip_kid = &args[1];
    let sender_pk = hex::decode(&args[2]).unwrap();

    let mut container = Vec::new();
    io::stdin().read_to_end(&mut container).unwrap();

    let result = cef::decrypt(&container, cef::DecryptOptions {
        recipient_kid: recip_kid.to_string(),
        decryption_key: recip_sk,
        verify_key: Some(sender_pk),
        skip_signature_verification: false,
    }).unwrap();

    // Output as JSON
    use base64::Engine;
    let files: Vec<serde_json::Value> = result.files.iter().map(|f| {
        serde_json::json!({
            "name": f.original_name,
            "data": base64::engine::general_purpose::STANDARD.encode(&f.data)
        })
    }).collect();
    println!("{}", serde_json::to_string(&files).unwrap());
}

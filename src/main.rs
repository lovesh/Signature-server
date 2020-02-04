use actix_web::{get, post, put, web, App, HttpResponse, HttpServer};
use ed25519_dalek::{ExpandedSecretKey, PublicKey};
use serde::{Deserialize, Serialize};
use sig_server::config_parsing::load_from_config_file;
use sig_server::crypto::sign;
use sig_server::db::InMemoryAppendOnlyTxnStore;
use sig_server::errors::SigServerError;
use sig_server::util::{base64_str_to_bytes, bytes_to_base64, serialize_txns};

use std::sync::Arc;

// Make sure that the code has access to configuration file.
const CONFIG_FILE_PATH: &str = "./Config.toml";

// TODO: Move to config
/// Maximum request size. Any request bigger than this will be rejected.
const MAX_REQ_SIZE: u16 = 8192;

// TODO: Move to config
/// Maximum number of transactions over which signature can be requested. Requesting signature on a bigger
/// bigger list will be rejected.
const MAX_SIG_REQ: u8 = 10;

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResp {
    pub error_code: String,
    pub message: String,
}

impl ErrorResp {
    /// Error when submitted transaction is not in base64
    pub fn bad_txn(err: SigServerError) -> Self {
        match err {
            SigServerError::InvalidBase64 { string: _, error } => ErrorResp {
                error_code: String::from("E1"),
                message: error,
            },
            _ => panic!(""),
        }
    }

    /// Error when requesting signature over transaction id list
    pub fn no_txn_id() -> Self {
        ErrorResp {
            error_code: String::from("E2"),
            message: format!("No transaction ids given"),
        }
    }

    /// Error when requesting signature over too many transaction ids
    pub fn too_many_txn_ids(count: usize) -> Self {
        ErrorResp {
            error_code: String::from("E3"),
            message: format!(
                "Received {} but will only accept {} transaction ids at max",
                count, MAX_SIG_REQ
            ),
        }
    }

    /// Error when requesting signature over invalid transaction ids
    pub fn unknown_txn_id(id: usize) -> Self {
        ErrorResp {
            error_code: String::from("E4"),
            message: format!("Invalid transaction id: {}", id),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PublicKeyResp {
    pub public_key: String,
}

#[derive(Serialize, Deserialize)]
struct TxnReq {
    pub txn: String,
}

#[derive(Serialize, Deserialize)]
struct TxnResp {
    /// Each transaction is given a unique numeric id. 2^32 or 2^64 transactions should be enough even for
    /// large persistent storage.
    pub id: usize,
}

#[derive(Serialize, Deserialize)]
struct SigReq {
    pub ids: Vec<usize>,
}

#[derive(Serialize, Deserialize)]
struct SigResp {
    pub message: Vec<String>,
    pub signature: String,
}

#[get("/public_key")]
async fn get_public_key(pubkey_json: web::Data<Arc<String>>) -> HttpResponse {
    HttpResponse::Ok().body(pubkey_json.to_string())
}

#[put("/transaction")]
async fn new_transaction(
    txn_req: web::Json<TxnReq>,
    txn_store: web::Data<InMemoryAppendOnlyTxnStore>,
) -> HttpResponse {
    match base64_str_to_bytes(&txn_req.txn) {
        Ok(t) => {
            // TODO: Append could fail as well. Should handle error.
            let id = txn_store.append(t);
            HttpResponse::Ok().json(TxnResp { id })
        }
        Err(e) => HttpResponse::BadRequest().json(ErrorResp::bad_txn(e)),
    }
}

#[post("/signature")]
async fn new_signature(
    sig_req: web::Json<SigReq>,
    public_key: web::Data<Arc<PublicKey>>,
    secret_key: web::Data<Arc<ExpandedSecretKey>>,
    txn_store: web::Data<InMemoryAppendOnlyTxnStore>,
) -> HttpResponse {
    if sig_req.ids.is_empty() {
        HttpResponse::BadRequest().json(ErrorResp::no_txn_id())
    } else if sig_req.ids.len() as u8 > MAX_SIG_REQ {
        HttpResponse::BadRequest().json(ErrorResp::too_many_txn_ids(sig_req.ids.len()))
    } else {
        let size = txn_store.size();
        // Assuming that its expensive to get data from the store, ensure all ids are valid
        for i in &sig_req.ids {
            if *i >= size {
                // Since store is append only and ids are 0-indexed, no id should be greater than store size
                return HttpResponse::NotFound().json(ErrorResp::unknown_txn_id(*i));
            }
        }
        let txns = txn_store.get_many(&sig_req.ids);

        // Serialize each txn as base64
        let b64_txns = serialize_txns(&txns);

        let to_sign = b64_txns.join(",");
        let signature = sign(
            to_sign.as_bytes(),
            secret_key.get_ref(),
            public_key.get_ref(),
        );
        HttpResponse::Ok().json(SigResp {
            message: b64_txns,
            signature: bytes_to_base64(&signature.to_bytes()),
        })
    }
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    // No point in starting if can't load the config so unwrap and panic
    let (port, pk_b64, pk, sk) = load_from_config_file(CONFIG_FILE_PATH).unwrap();

    // This response will never change. Generate json only once
    let pub_key_json =
        Arc::new(serde_json::to_string(&PublicKeyResp { public_key: pk_b64 }).unwrap());

    // Public and secret keys don't change for the life of the server
    let public_key = Arc::new(pk);
    let secret_key = Arc::new(sk);

    let txn_store = web::Data::new(InMemoryAppendOnlyTxnStore::new());

    let address = format!("127.0.0.1:{}", port);
    println!("Server starting at {}", address);

    HttpServer::new(move || {
        let app = App::new();
        app.data(web::JsonConfig::default().limit(MAX_REQ_SIZE as usize))
            .data(pub_key_json.clone())
            .app_data(txn_store.clone())
            .data(public_key.clone())
            .data(secret_key.clone())
            .service(get_public_key)
            .service(new_transaction)
            .service(new_signature)
    })
    .bind(&address)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http, test, web, App};
    use ed25519_dalek::Signature;

    #[actix_rt::test]
    async fn test_get_public_key() {
        // TODO: Duplicate code
        // No point in starting if can't load the config so unwrap and panic
        let (_, pk_b64, _, _) = load_from_config_file(CONFIG_FILE_PATH).unwrap();

        // This response will never change. Generate json only once
        let pk_json =
            Arc::new(serde_json::to_string(&PublicKeyResp { public_key: pk_b64 }).unwrap());
        let mut app =
            test::init_service(App::new().data(pk_json.clone()).service(get_public_key)).await;

        let req = test::TestRequest::with_uri("/public_key").to_request();
        let resp = test::call_service(&mut app, req).await;
        let response_body = match resp.response().body().as_ref() {
            Some(actix_web::body::Body::Bytes(bytes)) => bytes,
            _ => panic!("Response error"),
        };

        assert_eq!(
            response_body,
            r##"{"public_key":"TaxyY3G2A3pw7t2YSNtp88rRMV2G2GAasfldraakCZ8="}"##
        );
    }

    #[actix_rt::test]
    async fn test_put_txn() {
        // Add some transaction and check the returned id

        let txn_store = web::Data::new(InMemoryAppendOnlyTxnStore::new());

        let mut app = test::init_service(
            App::new()
                .data(web::JsonConfig::default().limit(50 as usize))
                .app_data(txn_store.clone())
                .service(new_transaction),
        )
        .await;

        // Send some requests sequentially and check id
        for i in 0..100 {
            let req = test::TestRequest::put()
                .uri("/transaction")
                .set_json(&TxnReq {
                    txn: String::from("aGVsbG8="), // "hello"
                })
                .to_request();
            let resp = test::call_service(&mut app, req).await;

            let response_body = match resp.response().body().as_ref() {
                Some(actix_web::body::Body::Bytes(bytes)) => bytes,
                _ => panic!("Response error"),
            };

            let r: TxnResp = serde_json::from_slice(&response_body.to_vec()).unwrap();
            assert_eq!(r.id, i)
        }

        // A large request should fail
        let req = test::TestRequest::put()
            .uri("/transaction")
            .set_json(&TxnReq {
                txn: String::from("aGVsbG8gdGhlcmVoZWxsbyB0aGVyZWhlbGxvIHRoZXJlaGVsbG8gdGhlcmVoZWxsbyB0aGVyZWhlbGxvIHRoZXJl="),  // some long string
            })
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn test_put_txn_multiple_threads() {
        // Add several txns in threads running in parallel and check that all ids are distinct
        // TODO:
    }

    #[actix_rt::test]
    async fn test_get_signature() {
        // Add several txns in threads running in parallel and check that all ids are distinct

        // TODO: Duplicate code
        let (_, _, pk, sk) = load_from_config_file(CONFIG_FILE_PATH).unwrap();

        let public_key = Arc::new(pk);
        let secret_key = Arc::new(sk);

        let txn_store = web::Data::new(InMemoryAppendOnlyTxnStore::new());

        let mut app = test::init_service(
            App::new()
                .data(web::JsonConfig::default().limit(50 as usize))
                .app_data(txn_store.clone())
                .data(public_key.clone())
                .data(secret_key.clone())
                .service(new_transaction)
                .service(new_signature),
        )
        .await;

        // Requesting signature on empty ids
        let req = test::TestRequest::post()
            .uri("/signature")
            .set_json(&SigReq { ids: vec![] })
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);

        // Requesting signature on with non existent id
        let req = test::TestRequest::post()
            .uri("/signature")
            .set_json(&SigReq { ids: vec![1] })
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        for i in 0..20 {
            let req = test::TestRequest::put()
                .uri("/transaction")
                .set_json(&TxnReq {
                    txn: bytes_to_base64(&vec![1, 0, i as u8]),
                })
                .to_request();
            let resp = test::call_service(&mut app, req).await;

            let response_body = match resp.response().body().as_ref() {
                Some(actix_web::body::Body::Bytes(bytes)) => bytes,
                _ => panic!("Response error"),
            };

            let r: TxnResp = serde_json::from_slice(&response_body.to_vec()).unwrap();
            assert_eq!(r.id, i)
        }

        // Requesting signature on with non existent id
        let req = test::TestRequest::post()
            .uri("/signature")
            .set_json(&SigReq { ids: vec![22] })
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        // Requesting signature on with some existent but one non existent id
        let req = test::TestRequest::post()
            .uri("/signature")
            .set_json(&SigReq {
                ids: vec![0, 3, 22],
            })
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        // Requesting signature on too many ids
        let req = test::TestRequest::post()
            .uri("/signature")
            .set_json(&SigReq {
                // ids.len() > MAX_SIG_REQ
                ids: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            })
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);

        for i in 0..20 {
            // Query single ids
            let req = test::TestRequest::post()
                .uri("/signature")
                .set_json(&SigReq {
                    ids: vec![i as usize],
                })
                .to_request();
            let resp = test::call_service(&mut app, req).await;
            let response_body = match resp.response().body().as_ref() {
                Some(actix_web::body::Body::Bytes(bytes)) => bytes,
                _ => panic!("Response error"),
            };

            let r: SigResp = serde_json::from_slice(&response_body.to_vec()).unwrap();
            let b64 = bytes_to_base64(&vec![1, 0, i as u8]);
            assert_eq!(r.message, vec![b64.clone()]);

            // Verify signature
            assert!(pk
                .verify(
                    b64.as_bytes(),
                    &Signature::from_bytes(&base64_str_to_bytes(&r.signature).unwrap()).unwrap()
                )
                .is_ok());
        }

        // Query multiple ids
        let req = test::TestRequest::post()
            .uri("/signature")
            .set_json(&SigReq { ids: vec![0, 2] })
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        let response_body = match resp.response().body().as_ref() {
            Some(actix_web::body::Body::Bytes(bytes)) => bytes,
            _ => panic!("Response error"),
        };

        let r: SigResp = serde_json::from_slice(&response_body.to_vec()).unwrap();

        let b64_0 = bytes_to_base64(&vec![1, 0, 0]);
        let b64_2 = bytes_to_base64(&vec![1, 0, 2]);
        assert_eq!(r.message, vec![b64_0.clone(), b64_2.clone()]);
        // Verify signature
        assert!(pk
            .verify(
                vec![b64_0, b64_2].join(",").as_bytes(),
                &Signature::from_bytes(&base64_str_to_bytes(&r.signature).unwrap()).unwrap()
            )
            .is_ok());
    }
}

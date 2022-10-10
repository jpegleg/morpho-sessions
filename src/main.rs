use std::{fs::File, io::BufReader};
use actix_files::Files;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use actix_web::{cookie::{self, Key}, web, middleware, App, HttpServer, get, Responder, HttpRequest};
use actix_files::NamedFile;
use actix_web_lab::{header::StrictTransportSecurity, middleware::RedirectHttps};
use uuid::Uuid;
use chrono::prelude::*;
use std::env;
use actix_session::{
    config::PersistentSession, storage::CookieSessionStore, Session, SessionMiddleware,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Age {
    pub fage: i32,
}

#[get("/session")]
async fn newcook(info: web::Query<Age>, session: Session, req: HttpRequest) -> impl Responder {
    let id = info.fage;
    let peer = req.peer_addr();
    let mut counter = 0;
    if id > 20 {
        if let Ok(Some(count)) = session.get::<i32>("counter") {
            log::info!("Visitor cookie sessions counter for {:?} : {count}", &peer);
            counter = count + 1;
            session.insert("counter", counter);
        } else {
            session.insert("counter", counter);
        }
        NamedFile::open_async("./static/index2.html").await
    } else {
        log::info!("Visitor entered age under 21, sending {:?} to notice page...", peer);
        NamedFile::open_async("./static/index3.html").await
    }
}

#[get("/")]
async fn index(session: Session, req: HttpRequest) -> impl Responder {
    let txid = Uuid::new_v4().to_string();
    env::set_var("txid", &txid);
    let peer = req.peer_addr();
    let requ = req.headers(); 
    let mut counter = 0;
    log::info!("{} {:?} visiting website - {:?}", txid, peer, requ);

    if let Ok(Some(count)) = session.get::<i32>("counter") {
        log::info!("Existing cookie found.");
        if let Ok(Some(count)) = session.get::<i32>("counter") {
            log::info!("Visitor cookie sessions counter for {:?} : {count}", &peer);
            counter = count + 1;
            session.insert("counter", counter);
        } else {
            session.insert("counter", counter);
        }
        NamedFile::open_async("./static/index2.html").await
    } else {
        log::info!("New cookie needed.");
        NamedFile::open_async("./static/index.html").await
    }

}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let readi: DateTime<Utc> = Utc::now();
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    let config = load_rustls_config();
    log::info!("morpho initialized at {} >>> morpho session HTTPS server on port 1443 using rustls TLSv1.3 and TLSv1.2", readi);
    HttpServer::new(|| {
        App::new()
            .wrap(RedirectHttps::default())
            .wrap(RedirectHttps::with_hsts(StrictTransportSecurity::recommended()))
            .wrap(middleware::DefaultHeaders::new().add(("x-content-type-options", "nosniff")))
            .wrap(middleware::DefaultHeaders::new().add(("x-frame-options", "SAMEORIGIN")))
            .wrap(middleware::DefaultHeaders::new().add(("x-xss-protection", "1; mode=block")))
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), Key::from(&[0; 64]))
                    .cookie_secure(false)
                    .session_lifecycle(
                        PersistentSession::default().session_ttl(cookie::time::Duration::hours(2)),
                    )
                    .build(),
            )
            .wrap(middleware::Logger::new("%{txid}e %a -> HTTP %s %r size: %b server-time: %T %{Referer}i %{User-Agent}i"))

            .service(index)
            .service(newcook)
            .service(Files::new("/", "static"))

    })
    .bind_rustls("0.0.0.0:1443", config)?
    .run()
    .await
}

fn load_rustls_config() -> rustls::ServerConfig {
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();
    let cert_file = &mut BufReader::new(File::open("cert.pem").unwrap());
    let key_file = &mut BufReader::new(File::open("privkey.pem").unwrap());
    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .unwrap()
        .into_iter()
        .map(PrivateKey)
        .collect();
    if keys.is_empty() {
        let readu: DateTime<Utc> = Utc::now();
        eprintln!("{} - morpho FATAL - Open of privkey.pem paired with cert.pem failed, server must shutdown. Use PKCS8 PEM", readu);
        std::process::exit(1);
    }
    config.with_single_cert(cert_chain, keys.remove(0)).unwrap()
}

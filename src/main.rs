extern crate hyper;
extern crate ring;
extern crate rustc_serialize;
extern crate toml;
extern crate url;
extern crate uuid;

use hyper::client::Request;
use hyper::method::Method;
use hyper::Url;
use ring::{digest, hmac};
use rustc_serialize::hex::ToHex;
use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;
use rustc_serialize::hex::FromHex;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::str;
use std::time::*;
use url::percent_encoding::*;
use uuid::Uuid;

#[derive(Debug, RustcDecodable)]
struct Config {
    general: GeneralConfig,
}

#[derive(Debug, RustcDecodable)]
struct GeneralConfig {
    consumer_key: String,
    consumer_secret: String,
}

#[derive(Debug)]
enum ConfigurationError {
    Io(io::Error),
    ParseError,
}

static AUTH_TOKEN_URL: &'static str = "https://api.twitter.com/oauth/request_token";

#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct CANONICAL_PERCENT_ENCODE_SET;

impl EncodeSet for CANONICAL_PERCENT_ENCODE_SET {
    #[inline]
    fn contains(&self, byte: u8) -> bool {
        match byte as char {
            '0'...'9' | 'A'...'Z' | 'a'...'z' | '-' | '_' | '.' | '~' => false,
            _ => true,
        }
    }
}

fn main() {
    let cfg = read_configuration().unwrap();
    let u = auth_token(&cfg);
    println!("url {}", u);
}

fn read_configuration() -> Result<Config, ConfigurationError> {
    let cfg_path = format!("{}/.falko.toml", std::env::home_dir().unwrap().to_str().unwrap());
    let f = try!(File::open(cfg_path).map_err(ConfigurationError::Io));
    let mut reader = BufReader::new(f);
    let mut buffer = String::new();

    // read a line into buffer
    try!(reader.read_to_string(&mut buffer).map_err(ConfigurationError:: Io));

    let cfg: Result<Config, ConfigurationError> = toml::decode_str(&buffer).ok_or(ConfigurationError::ParseError);
    cfg
}

fn auth_token(cfg: &Config) -> String {
    let url = Url::parse(AUTH_TOKEN_URL).unwrap();
    let request = Request::new(Method::Post, url).unwrap();

    // Setup required params for auth token
    let mut auth_params = Vec::new();
    auth_params.push(("oauth_callback".to_string(), "oob".to_string()));
    auth_params.push(("oauth_consumer_key".to_string(), cfg.general.consumer_key.clone()));
    auth_params.push(("oauth_nonce".to_string(), format!("{}", Uuid::new_v4().simple())));
    auth_params.push(("oauth_signature_method".to_string(), "HMAC-SHA1".to_string()));
    auth_params.push(("oauth_timestamp".to_string(),
                      SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string()));
    auth_params.push(("oauth_version".to_string(), "1.0".to_string()));

    // Generate signature
    authorize_signature(cfg, &request, &mut auth_params)
}

/// Creates an authorization request of the form specified in Twitter docs:
///
/// https://dev.twitter.com/oauth/overview/creating-signatures
///
fn authorize_signature<W>(cfg: &Config, request: &Request<W>, auth_params: &mut Vec<(String, String)>) -> String {
    let url = &request.url;
    let method = request.method().to_string().to_uppercase();

    // Get query pairs, sorted
    let mut pairs = url.query_pairs()
        .map(|kv| {
            (utf8_percent_encode(&kv.0.into_owned(), CANONICAL_PERCENT_ENCODE_SET).to_string(),
             utf8_percent_encode(&kv.1.into_owned(), CANONICAL_PERCENT_ENCODE_SET).to_string())
        })
        .collect::<Vec<(String, String)>>();

    // OAuth parameters
    pairs.append(auth_params);

    // sort the encoded keys
    pairs.sort_by(|a, b| a.0.cmp(&b.0));

    let params =
        pairs.iter().map(|kv| format!("{}={}", kv.0, kv.1)).collect::<Vec<String>>().join("&");

    let base_url = utf8_percent_encode(&format!("{}://{}{}",
                                                url.scheme(),
                                                url.host_str().unwrap(),
                                                url.path()),
                                       CANONICAL_PERCENT_ENCODE_SET)
        .to_string();

    let sig_base = method + "&" + &base_url +
        &(if !params.is_empty() {
            "&".to_string() + &utf8_percent_encode(&params, CANONICAL_PERCENT_ENCODE_SET).to_string()
        } else {
            "".to_string()
        });
    let signing_key = &(utf8_percent_encode(&cfg.general.consumer_secret, CANONICAL_PERCENT_ENCODE_SET).to_string() + "&" /* incorporate oauth secret if there is one*/);
    calc_signature(signing_key, &sig_base)
}

fn calc_signature(signing_key: &str, signing_base: &str) -> String {
    let s_key = hmac::SigningKey::new(&digest::SHA1, signing_key.as_ref());
    let signature = hmac::sign(&s_key, signing_base.as_bytes());
    signature.as_ref().to_hex().from_hex().unwrap().to_base64(base64::STANDARD)
}

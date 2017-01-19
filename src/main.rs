extern crate hyper;
extern crate regex;
extern crate ring;
extern crate rustc_serialize;
extern crate toml;
extern crate url;
extern crate uuid;
extern crate webbrowser;

use hyper::header::{Authorization, ContentLength, ContentType};
use hyper::client::Request;
use hyper::method::Method;
use hyper::{Client, Url};
use regex::Regex;
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

#[derive(Debug, RustcDecodable)]
struct OAuthAccessTokens {
    oauth_token: String,
    oauth_token_secret: String,
}

#[derive(Debug)]
enum ConfigurationError {
    Io(io::Error),
    ParseError,
}

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

type OAuthToken = String;

static ACCESS_TOKEN_URL: &'static str = "https://api.twitter.com/oauth/access_token";
static AUTH_TOKEN_URL: &'static str = "https://api.twitter.com/oauth/request_token";
static AUTHORIZE_URL: &'static str = "https://api.twitter.com/oauth/authorize";

fn main() {
    let cfg = read_configuration().unwrap();
    let token = auth_token(&cfg);
    authorize(&token);
    let pin = read_pin().unwrap();
    println!("{:?}", access_token(&cfg, &pin, &token));
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

fn read_pin() -> io::Result<String> {
    let mut input = String::new();

    print!("Enter authorization PIN> ");
    match io::stdout().flush() {
        Ok(_) => {
            try!(io::stdin().read_line(&mut input));
            let pin = input.trim();
            Ok(pin.to_owned())
        }
        Err(e) => Err(e)
    }
}

fn auth_token(cfg: &Config) -> Option<OAuthToken> {
    let url = Url::parse(AUTH_TOKEN_URL).unwrap();
    let mut request = Request::new(Method::Post, url).unwrap();

    // Generate signature
    let auth_header = authorize_signature(cfg, &mut request, &None, &None);

    {
        let headers = request.headers_mut();
        headers.set(Authorization(auth_header));
    }

    let stream = request.start().unwrap();
    let mut response = stream.send().unwrap();

    let mut buf = String::new();
    match response.read_to_string(&mut buf) {
        Ok(_) => {
            let oauth_token = buf.split("&").find(|s| {
                s.starts_with("oauth_token=")
            }).unwrap().split("=").last();
            oauth_token.map(|s| s.to_owned())
        },
        Err(e) => {
            println!("Error reading response: {:?}", e);
            None
        }
    }

}

fn authorize(oauth_token: &Option<OAuthToken>) -> () {
    match *oauth_token {
        Some(ref token) => webbrowser::open(&format!("{}?oauth_token={}", AUTHORIZE_URL, token)).is_ok(),
        None => false
    };
    ()
}

fn access_token(cfg: &Config, pin: &str, oauth_token: &Option<OAuthToken>) -> Result<OAuthAccessTokens, String> {
    let url = Url::parse(ACCESS_TOKEN_URL).unwrap();
    // let url = Url::parse("http://localhost:8080/oauth/access_token").unwrap();
    let mut request = Request::new(Method::Post, url).unwrap();

    // Generate signature
    let auth_header = authorize_signature(cfg, &mut request, oauth_token, &Some(pin.to_string()));

    // Tack on auth header
    {
        let headers = request.headers_mut();
        headers.set(Authorization(auth_header));
    }

    let stream = request.start().unwrap();
    println!("{}", stream.headers());

    let mut response = stream.send().unwrap();
    println!("{}", response.headers);

    let mut buf = String::new();
    match response.read_to_string(&mut buf) {
        Ok(_) => Ok(parse_access_tokens(&buf)),
        e @ Err(_) => Err(format!("Error reading response: {:?}", e))
    }
}

fn parse_access_tokens(buf: &str) -> OAuthAccessTokens {
    let re_token = Regex::new(r"oauth_token=([^&]+)").unwrap();
    let oauth_token = re_token.captures(buf).map(|c| c.get(1).unwrap().as_str());
    let re_secret = Regex::new(r"oauth_token_secret=([^&]+)").unwrap();
    let oauth_token_secret = re_secret.captures(buf).map(|c| c.get(1).unwrap().as_str());
    OAuthAccessTokens { oauth_token: oauth_token.unwrap().to_string(), oauth_token_secret: oauth_token_secret.unwrap().to_string() }
}

/// Creates an authorization request of the form specified in Twitter docs:
///
/// https://dev.twitter.com/oauth/overview/creating-signatures
///
fn authorize_signature<W>(cfg: &Config, request: &mut Request<W>, oauth_token: &Option<OAuthToken>, oauth_verifier: &Option<String>) -> String {
    let url = &request.url;
    let method = request.method().to_string().to_uppercase();

    // Setup required params for auth token. Keep this set separate since we need to build the auth header later with these.
    let mut auth_params = vec![
        ("oauth_callback",         "oob"),
        ("oauth_consumer_key",     &cfg.general.consumer_key.clone()),
        ("oauth_nonce",            &format!("{}", Uuid::new_v4().simple())),
        ("oauth_signature_method", "HMAC-SHA1"),
        ("oauth_timestamp",        &SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string()),
        ("oauth_version",          "1.0")
    ].iter().map(|kv| {
        (utf8_percent_encode(&kv.0, CANONICAL_PERCENT_ENCODE_SET).to_string(),
         utf8_percent_encode(&kv.1, CANONICAL_PERCENT_ENCODE_SET).to_string())
    }).collect::<Vec<(String, String)>>();

    // If OAuthToken is defined add it to auth params
    match *oauth_token {
        Some(ref token) => auth_params.push(("oauth_token".to_string(), utf8_percent_encode(&token, CANONICAL_PERCENT_ENCODE_SET).to_string())),
        None => ()
    }

    // If OAuthToken is defined add it to auth params
    match *oauth_verifier {
        Some(ref verifier) => auth_params.push(("oauth_verifier".to_string(), utf8_percent_encode(&verifier, CANONICAL_PERCENT_ENCODE_SET).to_string())),
        None => ()
    }

    // save a copy to build the actual header at the end of this rigmarole
    let mut auth_params_orig = auth_params.clone();

    // Combine query pairs and
    let mut pairs = url.query_pairs()
        .map(|kv| {
            (utf8_percent_encode(&kv.0.into_owned(), CANONICAL_PERCENT_ENCODE_SET).to_string(),
             utf8_percent_encode(&kv.1.into_owned(), CANONICAL_PERCENT_ENCODE_SET).to_string())
        })
        .collect::<Vec<(String, String)>>();

    // sort the encoded keys
    auth_params.append(&mut pairs);
    auth_params.sort_by(|a, b| a.0.cmp(&b.0));

    // dedupe any params
    auth_params.dedup();

    let params =
        auth_params.iter().map(|kv| format!("{}={}", kv.0, kv.1)).collect::<Vec<String>>().join("&");

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

    let token = match *oauth_token {
        Some(ref token) => utf8_percent_encode(&token, CANONICAL_PERCENT_ENCODE_SET).to_string(),
        None => "".to_string()
    };
    let signing_key = &(utf8_percent_encode(&cfg.general.consumer_secret, CANONICAL_PERCENT_ENCODE_SET).to_string()
        + "&"
        + &token);

    let signature = calc_signature(signing_key, &sig_base);

    auth_params_orig.push(("oauth_signature".to_string(),
                           utf8_percent_encode(&signature, CANONICAL_PERCENT_ENCODE_SET).to_string()));
    auth_params_orig.sort_by(|a, b| a.0.cmp(&b.0));
    // Whew! Finally create the OAuth header value
    auth_header(auth_params_orig)
}

fn auth_header(auth_params: Vec<(String, String)>) -> String {
    "OAuth ".to_string() + &auth_params.iter().map(|kv| {
        format!(r#"{}="{}""#, kv.0, kv.1)
    }).collect::<Vec<String>>().join(",")
}

fn calc_signature(signing_key: &str, signing_base: &str) -> String {
    let s_key = hmac::SigningKey::new(&digest::SHA1, signing_key.as_ref());
    let signature = hmac::sign(&s_key, signing_base.as_bytes());
    signature.as_ref().to_hex().from_hex().unwrap().to_base64(base64::STANDARD)
}

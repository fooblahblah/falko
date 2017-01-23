use hyper::method::Method;
use hyper::client::Request;
use hyper::Url;
use regex::Regex;
use ring::{ digest, hmac };
use rustc_serialize::hex::ToHex;
use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;
use rustc_serialize::hex::FromHex;
use super::{ Config, OAuthToken, OAuthAccessTokens };
use std::time::*;
use url::percent_encoding::*;
use uuid::Uuid;

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

pub fn parse_access_tokens(buf: &str) -> OAuthAccessTokens {
    let re_token = Regex::new(r"oauth_token=([^&]+)").unwrap();
    let oauth_token = re_token.captures(buf).map(|c| c.get(1).unwrap().as_str());
    let re_secret = Regex::new(r"oauth_token_secret=([^&]+)").unwrap();
    let oauth_token_secret = re_secret.captures(buf).map(|c| c.get(1).unwrap().as_str());
    OAuthAccessTokens { oauth_token: oauth_token.map(|t| t.to_string()), oauth_token_secret: oauth_token_secret.map(|t| t.to_string()) }
}


/// Creates an authorization request of the form specified in Twitter docs:
///
/// https://dev.twitter.com/oauth/overview/creating-signatures
///
pub fn authorize_signature<W>(cfg: &Config, request: &mut Request<W>, tokens: &OAuthAccessTokens) -> String {
    let url = &request.url;
    let method = request.method().to_string().to_uppercase();

    // Setup required params for auth token. Keep this set separate since we need to build the auth header later with these.
    let mut auth_params = vec![
        ("oauth_callback",         "oob"),
        ("oauth_consumer_key",     &cfg.twitter.consumer_key.clone()),
        ("oauth_nonce",            &format!("{}", Uuid::new_v4().simple())),
        ("oauth_signature_method", "HMAC-SHA1"),
        ("oauth_timestamp",        &SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string()),
        ("oauth_version",          "1.0")
    ].iter().map(|kv| {
        (utf8_percent_encode(&kv.0, CANONICAL_PERCENT_ENCODE_SET).to_string(),
         utf8_percent_encode(&kv.1, CANONICAL_PERCENT_ENCODE_SET).to_string())
    }).collect::<Vec<(String, String)>>();

    // If OAuthToken is defined add it to auth params
    match tokens.oauth_token {
        Some(ref token) => auth_params.push(("oauth_token".to_string(), utf8_percent_encode(&token, CANONICAL_PERCENT_ENCODE_SET).to_string())),
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

    // base url: percent_encoded protocol, host and path (minus query params)
    let base_url = utf8_percent_encode(&format!("{}://{}{}",
                                                url.scheme(),
                                                url.host_str().unwrap(),
                                                url.path()),
                                       CANONICAL_PERCENT_ENCODE_SET)
        .to_string();

    // signature base is comprised of the method&base_url&encoded_params
    let sig_base = method + "&" + &base_url +
        &(if !params.is_empty() {
            "&".to_string() + &utf8_percent_encode(&params, CANONICAL_PERCENT_ENCODE_SET).to_string()
        } else {
            "".to_string()
        });

    // percent_encode the oauth token
    let token_secret = match tokens.oauth_token_secret {
        Some(ref secret) => utf8_percent_encode(&secret, CANONICAL_PERCENT_ENCODE_SET).to_string(),
        None => "".to_string()
    };
    // signing key consumer_secret&oauth_token
    let signing_key = &(utf8_percent_encode(&cfg.twitter.consumer_secret, CANONICAL_PERCENT_ENCODE_SET).to_string()
        + "&"
        + &token_secret);

    // calculate the signature from the signing_key and signature_base
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
    }).collect::<Vec<String>>().join(", ")
}

fn calc_signature(signing_key: &str, signing_base: &str) -> String {
    let s_key = hmac::SigningKey::new(&digest::SHA1, signing_key.as_ref());
    let signature = hmac::sign(&s_key, signing_base.as_bytes());
    signature.as_ref().to_hex().from_hex().unwrap().to_base64(base64::STANDARD)
}

mod oauth;

extern crate hyper;
extern crate regex;
extern crate ring;
extern crate rustc_serialize;
extern crate toml;
extern crate url;
extern crate uuid;
extern crate webbrowser;

use hyper::header::Authorization;
use hyper::client::Request;
use hyper::method::Method;
use hyper::Url;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::str;

static ACCESS_TOKEN_URL: &'static str = "https://api.twitter.com/oauth/access_token";
static AUTH_TOKEN_URL: &'static str = "https://api.twitter.com/oauth/request_token";
static AUTHORIZE_URL: &'static str = "https://api.twitter.com/oauth/authorize";

#[derive(Debug, RustcDecodable)]
pub struct Config {
    twitter: TwitterConfig,
    oauth: OAuthAccessTokens,
}

#[derive(Debug, RustcDecodable)]
pub struct TwitterConfig {
    consumer_key: String,
    consumer_secret: String,
}

#[derive(Debug, RustcDecodable)]
pub struct OAuthAccessTokens {
    oauth_token: Option<OAuthToken>,
    oauth_token_secret: Option<OAuthTokenSecret>,
}

#[derive(Debug)]
enum ConfigurationError {
    Io(io::Error),
    ParseError,
}


type OAuthToken = String;
type OAuthTokenSecret = String;

static HOME_TIMELINE_URL: &'static str = "https://api.twitter.com/1.1/statuses/home_timeline.json";

fn main() {
    let cfg = read_configuration().unwrap();

    if cfg.oauth.oauth_token.is_none() {
        // Initial call to get an oauth_token to begin the authorization process
        let token = auth_token(&cfg);
        // Authorize spawns a browser window on Twitter so the user can authorize the app.
        // They are prompted to input the displayed PIN to continue.
        let pin = authorize(&token);
        let consumer_tokens = access_token(&cfg, &pin.unwrap(), &OAuthAccessTokens { oauth_token: token, oauth_token_secret: None });
        println!("{:?}", consumer_tokens);
    } else {
        println!("TODO save these. In the meantime you should edit ~/.falko.toml and add these: {:?}", home_timeline(&cfg, &cfg.oauth));
    }
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

fn home_timeline(cfg: &Config, tokens: &OAuthAccessTokens) -> String {
    let url = Url::parse(HOME_TIMELINE_URL).unwrap();
    let mut request = Request::new(Method::Get, url).unwrap();

    // Generate signature
    let auth_header = oauth::authorize_signature(cfg, &mut request, tokens);

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
    response.read_to_string(&mut buf);
    buf
}

fn auth_token(cfg: &Config) -> Option<OAuthToken> {
    let url = Url::parse(AUTH_TOKEN_URL).unwrap();
    let mut request = Request::new(Method::Post, url).unwrap();

    // Generate signature
    let auth_header = oauth::authorize_signature(cfg, &mut request, &OAuthAccessTokens { oauth_token: None, oauth_token_secret: None });

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


fn authorize(oauth_token: &Option<OAuthToken>) -> Result<String, io::Error> {
    match *oauth_token {
        Some(ref token) => {
            webbrowser::open(&format!("{}?oauth_token={}", AUTHORIZE_URL, token)).map(|r| {
                // Read the PIN via stdin
                read_pin().unwrap()
            })
        },
        _ => Err(io::Error::new(io::ErrorKind::Other, "Undefined OAuthToken"))

    }
}


fn access_token(cfg: &Config, pin: &str, tokens: &OAuthAccessTokens) -> Result<OAuthAccessTokens, String> {
    let url = Url::parse(&format!("{}?oauth_verifier={}", ACCESS_TOKEN_URL, pin)).unwrap();
    let mut request = Request::new(Method::Post, url).unwrap();

    // Generate signature
    let auth_header = oauth::authorize_signature(cfg, &mut request, tokens);

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
        Ok(_) => Ok(oauth::parse_access_tokens(&buf)),
        e @ Err(_) => Err(format!("Error reading response: {:?}", e))
    }
}

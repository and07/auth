extern crate bcrypt;
extern crate hex;
extern crate hmac;
extern crate sha2;
extern crate slog;

use bcrypt::{hash, verify, BcryptError};
use hmac::{Hmac, Mac};
use jwt_simple::prelude::*;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::error;
use std::fmt;
use std::fs;
use std::io;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct User {
    id: String,
    token_hash: String,
    password: String,
}

#[derive(Debug)]
enum AuthServiceError {
    Io(io::Error),
    Jwt(jwt_simple::Error),
    Bcrypt(BcryptError),
    InvalidJwt(String),
}

macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl From<$f> for AuthServiceError {
            fn from(f: $f) -> AuthServiceError {
                $e(f)
            }
        }
    };
}

impl_from_error!(io::Error, AuthServiceError::Io);
impl_from_error!(BcryptError, AuthServiceError::Bcrypt);
impl_from_error!(jwt_simple::Error, AuthServiceError::Jwt);

impl fmt::Display for AuthServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AuthServiceError::Io(ref err) => write!(f, "IO error: {}", err),
            AuthServiceError::Jwt(ref err) => write!(f, "JWT error: {}", err),
            AuthServiceError::Bcrypt(ref err) => write!(f, "Bcrypt error: {}", err),
            AuthServiceError::InvalidJwt(ref hash) => write!(f, "Invalid JWT: {}", hash),
        }
    }
}

impl error::Error for AuthServiceError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &*self {
            AuthServiceError::Io(ref err) => Some(err),
            AuthServiceError::Jwt(_)
            | AuthServiceError::InvalidJwt(_)
            | AuthServiceError::Bcrypt(_) => None,
        }
    }
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct AdditionalData {
    user_is_admin: bool,
    user_country: String,
    user_id: String,
    custom_key: String,
    key_type: String,
}

#[derive(Debug, Clone)]
struct Configurations {
    access_token_private_key_path: String,
    access_token_public_key_path: String,
    refresh_token_private_key_path: String,
    refresh_token_public_key_path: String,
    jwt_expiration: u64, // in minutes
}

impl Default for Configurations {
    fn default() -> Self {
        Configurations {
            access_token_private_key_path: "access-private.pem".to_string(),
            access_token_public_key_path: "access-public.pem".to_string(),
            refresh_token_private_key_path: "private.pem".to_string(),
            refresh_token_public_key_path: "public.pem".to_string(),
            jwt_expiration: 30, // in minutes
        }
    }
}

#[derive(Default)]
struct AuthService {
    logger: Option<slog::Logger>, //TODO
    configs: Configurations,
}

impl AuthService {
    fn new(cfg: Configurations, log: Option<slog::Logger>) -> Self {
        AuthService {
            logger: log, //TODO
            configs: cfg,
        }
    }

    fn generate_random_string(n: usize) -> String {
        let s: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(n)
            .map(char::from)
            .collect();
        s
    }

    fn hash_password(passord: &str) -> String {
        let cost: u32 = 9;
        let hashed = hash(passord, cost).expect("err hash");
        hashed.to_string()
    }
}

pub trait Authentication {
    fn authenticate(&self, user: &str, user_data: &User) -> Result<bool, AuthServiceError>;
    fn generate_access_token(&self, user_data: &User) -> Result<String, AuthServiceError>;
    fn generate_refresh_token(&self, user: &User) -> Result<String, AuthServiceError>;
    fn generate_custom_key(&self, user_id: &str, token_hash: &str) -> String;
    fn validate_access_token(&self, token: &String) -> Result<AdditionalData, AuthServiceError>;
    fn validate_refresh_token(&self, token: &String) -> Result<AdditionalData, AuthServiceError>;
}

const TOKEN_TYPE_ACCESS: &str = "access";
const TOKEN_TYPE_REFRESH: &str = "refresh";
const AUTH_SERVICE: &str = "auth.service";

impl Authentication for AuthService {
    fn authenticate(&self, passord: &str, user: &User) -> Result<bool, AuthServiceError> {
        match verify(passord, &user.password) {
            Ok(res) => Ok(res),
            Err(e) => Err(e.into()),
        }
    }

    fn generate_access_token(&self, user: &User) -> Result<String, AuthServiceError> {
        let user_id = String::from(user.id.as_str());
        let token_type = TOKEN_TYPE_ACCESS;
        let contents = fs::read_to_string(self.configs.access_token_private_key_path.as_str())?;

        let key_pair = RS384KeyPair::from_pem(contents.as_str())?;

        let my_additional_data = AdditionalData {
            user_is_admin: false,           //TODO
            user_country: "FR".to_string(), //TODO
            user_id: user_id,
            key_type: token_type.to_string(),
            ..Default::default()
        };

        let claims = Claims::with_custom_claims(
            my_additional_data,
            Duration::from_mins(self.configs.jwt_expiration),
        )
        .with_issuer(AUTH_SERVICE);

        let token = key_pair.sign(claims)?;

        Ok(token)
    }

    fn generate_refresh_token(&self, user: &User) -> Result<String, AuthServiceError> {
        let user_id = String::from(user.id.as_str());
        let cus_key = self.generate_custom_key(user.id.as_str(), user.token_hash.as_str());
        let token_type = TOKEN_TYPE_REFRESH;

        let contents = fs::read_to_string(self.configs.refresh_token_private_key_path.as_str())?;

        let key_pair = RS384KeyPair::from_pem(contents.as_str())?;

        let my_additional_data = AdditionalData {
            user_is_admin: false,           //TODO
            user_country: "FR".to_string(), //TODO
            user_id: user_id,
            custom_key: cus_key.to_string(),
            key_type: token_type.to_string(),
        };

        let claims = Claims::with_custom_claims(
            my_additional_data,
            Duration::from_mins(self.configs.jwt_expiration * 60),
        )
        .with_issuer(AUTH_SERVICE);

        let token = key_pair.sign(claims)?;

        Ok(token)
    }

    fn generate_custom_key(&self, user_id: &str, token_hash: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(token_hash.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(user_id.as_bytes());

        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        hex::encode(code_bytes)
    }

    fn validate_access_token(&self, token: &String) -> Result<AdditionalData, AuthServiceError> {
        let contents = fs::read_to_string(self.configs.access_token_public_key_path.as_str())?;
        let public_key = RS384PublicKey::from_pem(contents.as_str())?;

        let claims = public_key.verify_token::<AdditionalData>(&token, None)?;

        if claims.custom.key_type != TOKEN_TYPE_ACCESS.to_string() {
            return Err(AuthServiceError::InvalidJwt(String::from(
                "key_type not access",
            )));
        }
        Ok(claims.custom)
    }

    fn validate_refresh_token(&self, token: &String) -> Result<AdditionalData, AuthServiceError> {
        let contents = fs::read_to_string(self.configs.refresh_token_public_key_path.as_str())?;
        let public_key = RS384PublicKey::from_pem(contents.as_str())?;

        let claims = public_key.verify_token::<AdditionalData>(&token, None)?;

        if claims.custom.key_type != TOKEN_TYPE_REFRESH.to_string() {
            return Err(AuthServiceError::InvalidJwt(String::from(
                "key_type not refresh",
            )));
        }
        Ok(claims.custom)
    }
}

#[test]
fn test_generate_custom_key() {
    let auth: AuthService = AuthService::default();

    let user = "user-21";
    let token_hash = "token_hash";
    let hash = auth.generate_custom_key(user, token_hash);

    assert_eq!(
        hash,
        "15bb7518fd52d55551b5ecee1b273b9020c208f69e2849efd3cb105498aaf2c4"
    );
}

#[test]
fn test_generate_access_token() {
    let auth: AuthService = AuthService::default();

    println!("{:#?}", &auth.configs);

    let user1 = User {
        id: String::from("someone@example.com"),
        ..Default::default()
    };
    let tt = match auth.generate_access_token(&user1) {
        Ok(number) => number,
        Err(_e) => return (),
    };

    println!("{}", tt)
}

#[test]
fn test_generate_refresh_token() {
    let auth: AuthService = AuthService::default();
    let user1 = User {
        id: String::from("someone@example.com"),
        token_hash: String::from("ASdfgGHuUU"),
        ..Default::default()
    };
    let tt = match auth.generate_refresh_token(&user1) {
        Ok(number) => number,
        Err(_e) => return (), //TODO
    };

    println!("{}", tt)
}

#[test]
fn test_validate_access_token() {
    let auth: AuthService = AuthService::default();
    let user1 = User {
        id: String::from("someone@example.com"),
        ..Default::default()
    };
    let tt = match auth.generate_access_token(&user1) {
        Ok(number) => number,
        Err(_e) => return (), //TODO
    };

    let data = auth.validate_access_token(&tt).expect("not valid");

    assert_eq!(user1.id, data.user_id);
}

#[test]
fn test_validate_refresh_token() {
    let cfg: Configurations = Configurations::default();
    let auth: AuthService = AuthService::new(cfg, None);
    let user = User {
        id: String::from("someone@example.com"),
        token_hash: String::from("ASdfgGHuUU"),
        ..Default::default()
    };
    let tt = match auth.generate_refresh_token(&user) {
        Ok(number) => number,
        Err(_e) => return (),
    };

    let data = auth.validate_refresh_token(&tt).expect("not valid");

    assert_eq!(user.id, data.user_id);
}

#[test]
fn test_authenticate() {
    let pswd = AuthService::hash_password("passord");
    println!("{}", &pswd);
    let user = User {
        password: pswd,
        ..Default::default()
    };
    let auth: AuthService = AuthService::default();
    assert!(auth.authenticate("passord", &user).unwrap());
    assert_eq!(auth.authenticate("passord1", &user).unwrap(), false);
}

#[test]
fn test_generate_random_string() {
    let s: String = AuthService::generate_random_string(10);
    assert_eq!(s.len(), 10)
}

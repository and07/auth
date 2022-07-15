use async_trait::async_trait;
use chrono::serde::ts_seconds;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// User is the data type for user object
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    pub username: String,
    pub password: String,
    pub token_hash: String,
    pub is_verified: bool,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

pub type VerificationDataType = i32;

// VerificationData represents the type for the data stored for verification.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct VerificationData {
    pub email: String,
    pub code: String,
    pub expires_at: chrono::NaiveDateTime,
    pub verification_type: VerificationDataType,
}

#[derive(Debug, Error)]
pub enum AuthRepositoryError {
    Io(#[from] std::io::Error),
    Sqlx(#[from] sqlx::Error),
    Unknown(String),
}

impl fmt::Display for AuthRepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AuthRepositoryError::Io(ref err) => write!(f, "IO error: {}", err),
            AuthRepositoryError::Sqlx(ref err) => write!(f, "Sqlx error: {}", err),
            AuthRepositoryError::Unknown(ref err) => write!(f, "Unknown error: {}", err),
        }
    }
}

// AuthRepository is an interface for the storage implementation of the auth service
#[async_trait]
pub trait AuthRepository {
    async fn create(&self, user: User) -> Result<(), AuthRepositoryError>;
    async fn user_by_email(&self, email: &str) -> Result<User, AuthRepositoryError>;
    async fn user_by_id(&self, user_id: &str) -> Result<User, AuthRepositoryError>;
    async fn update_username(&self, mut user: User) -> Result<(), AuthRepositoryError>;
    async fn store_verification_data(
        &self,
        verification_data: VerificationData,
    ) -> Result<(), AuthRepositoryError>;
    async fn verification_data(
        &self,
        email: &str,
        verification_data_type: VerificationDataType,
    ) -> Result<VerificationData, AuthRepositoryError>;
    async fn update_user_verification_status(
        &self,
        email: &str,
        status: bool,
    ) -> Result<(), AuthRepositoryError>;
    async fn delete_verification_data(
        &self,
        email: &str,
        verification_data_type: VerificationDataType,
    ) -> Result<(), AuthRepositoryError>;
    async fn update_password(
        &self,
        user_id: &str,
        password: &str,
        token_hash: &str,
    ) -> Result<(), AuthRepositoryError>;
}

use sqlx::error::Error as SQLxError;
use std::fmt;
use std::time::Duration;
use thiserror::Error;
//use futures::executor::block_on;

#[derive(Clone)]
pub struct Config {
    pub postgres_host: String,
    pub postgres_port: String,
    pub postgres_user: String,
    pub postgres_password: String,
    pub postgres_database: String,
    pub timeout_connection: Duration,
    pub max_connections: u32,
    pub database_url: String,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}

impl Config {
    pub fn database_url(&self) -> String {
        println!("{}", self.database_url != "");
        if self.database_url != "" {
            return self.database_url.clone();
        };

        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.postgres_user,
            self.postgres_password,
            self.postgres_host,
            self.postgres_port,
            self.postgres_database
        )
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            timeout_connection: Duration::from_secs(1),
            max_connections: 15,
            database_url: "postgres://admin:pass@localhost/dbname".to_string(),
            idle_timeout: Duration::from_secs(30),
            max_lifetime: Duration::from_secs(60),
            postgres_user: "".to_string(),
            postgres_password: "".to_string(),
            postgres_host: "".to_string(),
            postgres_port: "".to_string(),
            postgres_database: "".to_string(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConnectionError {
    // #[error("database Sqlx")]
    Sqlx(#[from] SQLxError),
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ConnectionError::Sqlx(ref err) => write!(f, "SQLX error: {}", err),
        }
    }
}

pub struct Connection {
    pub db: sqlx::Pool<sqlx::Postgres>,
}

impl Connection {
    pub async fn new(cfg: Config) -> Result<Connection, ConnectionError> {
        let conn = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(cfg.timeout_connection)
            .max_connections(cfg.max_connections)
            .idle_timeout(cfg.idle_timeout)
            .max_lifetime(cfg.max_lifetime)
            .connect(&cfg.database_url())
            .await?;

        Ok(Connection { db: conn })
    }
}

#[async_std::test]
#[should_panic]
async fn test_new_connection() {
    let cfg = Config::default();
    match Connection::new(cfg).await {
        Ok(_) => (),
        Err(e) => panic!("{}", e),
    }
}

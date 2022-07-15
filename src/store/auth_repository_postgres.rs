use super::auth_shema::*;
use super::database::*;
use super::auth_repository::{
    AuthRepository, AuthRepositoryError, User, VerificationData, VerificationDataType,
};
use async_trait::async_trait;
use chrono::prelude::*;
use uuid::Uuid;

struct AuthRepositoryPostgres {
    pub conn: Connection,
}

impl AuthRepositoryPostgres {
    fn new(conn: Connection) -> Self {
        Self { conn: conn }
    }

    async fn init(&self) -> Result<(), AuthRepositoryError> {
        // creation of user table.
        let mut conn = self.conn.db.begin().await?;
        sqlx::query(USER_SCHEMA).execute(&mut conn).await?;
        sqlx::query(VERIFICATION_SCHEMA).execute(&mut conn).await?;
        conn.commit().await?;
        Ok(())
    }
}

#[async_trait]
impl AuthRepository for AuthRepositoryPostgres {
    async fn create(&self, mut user: User) -> Result<(), AuthRepositoryError> {
        user.id = Uuid::new_v4().to_string();
        user.created_at = Utc::now().naive_utc();
        user.updated_at = Utc::now().naive_utc();

        //repo.logger.Info("creating user", hclog.Fmt("%#v", user))

        let mut conn = self.conn.db.begin().await?;
        let query = r#"
        insert into users (
            id,
            email, 
            username, 
            password, 
            token_hash, 
            created_at, 
            updated_at, 
            is_verified
        ) values ($1, $2, $3, $4, $5, $6, $7, $8);"#;
        sqlx::query(query)
            .bind(user.id)
            .bind(user.email)
            .bind(user.username)
            .bind(user.password)
            .bind(user.token_hash)
            .bind(user.created_at)
            .bind(user.updated_at)
            .bind(user.is_verified)
            .execute(&mut conn)
            .await?;
        conn.commit().await?;

        Ok(())
    }

    async fn user_by_email(&self, email: &str) -> Result<User, AuthRepositoryError> {
        let query = r#"select * from users where email = $1"#;
        let user: User = sqlx::query_as::<_, User>(query)
            .bind(email)
            .fetch_one(&self.conn.db)
            .await?;
        Ok(user)
    }

    async fn user_by_id(&self, user_id: &str) -> Result<User, AuthRepositoryError> {
        let query = r#"select * from users where id = $1"#;
        let user: User = sqlx::query_as::<_, User>(query)
            .bind(user_id)
            .fetch_one(&self.conn.db)
            .await?;
        Ok(user)
    }

    async fn update_username(&self, mut user: User) -> Result<(), AuthRepositoryError> {
        user.updated_at = Utc::now().naive_utc();

        let query = r#"update users set username = $1, updatedat = $2 where id = $3"#;
        sqlx::query(query)
            .bind(user.username)
            .bind(user.updated_at)
            .bind(user.id)
            .execute(&self.conn.db)
            .await?;

        Ok(())
    }

    async fn store_verification_data(
        &self,
        verification_data: VerificationData,
    ) -> Result<(), AuthRepositoryError> {
        let query = r#"insert into verifications(email, code, expires_at, verification_type) values($1, $2, $3, $4)"#;
        sqlx::query(query)
            .bind(verification_data.email)
            .bind(verification_data.code)
            .bind(verification_data.expires_at)
            .bind(verification_data.verification_type)
            .execute(&self.conn.db)
            .await?;
        Ok(())
    }

    async fn verification_data(
        &self,
        email: &str,
        verification_data_type: VerificationDataType,
    ) -> Result<VerificationData, AuthRepositoryError> {
        let query = r#"select * from verifications where email = $1 and type = $2"#;
        let verificationData: VerificationData = sqlx::query_as::<_, VerificationData>(query)
            .bind(email)
            .bind(verification_data_type)
            .fetch_one(&self.conn.db)
            .await?;
        Ok(verificationData)
    }

    async fn update_user_verification_status(
        &self,
        email: &str,
        status: bool,
    ) -> Result<(), AuthRepositoryError> {
        let query = r#"update users set is_verified = $1 where email = $2"#;
        sqlx::query(query)
            .bind(status)
            .bind(email)
            .execute(&self.conn.db)
            .await?;
        Ok(())
    }

    async fn delete_verification_data(
        &self,
        email: &str,
        verification_data_type: VerificationDataType,
    ) -> Result<(), AuthRepositoryError> {

        let query = r#"delete from verifications where email = $1 and type = $2"#;
        sqlx::query(query)
        .bind(email)
        .bind(verification_data_type)
        .execute(&self.conn.db)
        .await?;
        Ok(())
    }

    async fn update_password(
        &self,
        user_id: &str,
        password: &str,
        token_hash: &str,
    ) -> Result<(), AuthRepositoryError>{
        let query = r#"update users set password = $1, token_hash = $2 where id = $3"#;
        sqlx::query(query)
        .bind(password)
        .bind(token_hash)
        .bind(user_id)
        .execute(&self.conn.db)
        .await?;
        Ok(())
    }
}

#[async_std::test]
//#[should_panic]
async fn test_create() {
    let cfg = Config {
        database_url: "postgres://admin:password@localhost:5432/postgres".to_string(),
        ..Config::default()
    };
    let con: Connection = match Connection::new(cfg).await {
        Ok(c) => c,
        Err(e) => panic!("{}", e),
    };

    let auth = AuthRepositoryPostgres::new(con);
    match auth.init().await {
        Ok(_) => (),
        Err(e) => panic!("{}", e),
    }

    match auth
        .create(User {
            email: "test@sadsd.io".to_string(),
            username: "test".to_string(),
            password: "password".to_string(),
            token_hash: "Tfdttf".to_string(),
            is_verified: false,
            id: "".to_string(),
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        })
        .await
    {
        Ok(_) => (),
        Err(e) => panic!("{}", e),
    }
}

#[async_std::test]
async fn test_user_by_email() {
    let cfg = Config {
        database_url: "postgres://admin:password@localhost:5432/postgres".to_string(),
        ..Config::default()
    };
    let con: Connection = match Connection::new(cfg).await {
        Ok(c) => c,
        Err(e) => panic!("{}", e),
    };

    let auth = AuthRepositoryPostgres::new(con);
    match auth.init().await {
        Ok(_) => (),
        Err(e) => panic!("{}", e),
    }

    let usr = match auth.user_by_email("test@sadsd.io").await {
        Ok(u) => u,
        Err(e) => panic!("{}", e),
    };

    println!("{:#?}", usr);

    assert_eq!(usr.username, "test");
    assert_eq!(usr.password, "password");
}

// schema for user table
pub const USER_SCHEMA: &str = r#"
		create table if not exists users (
			id 		   Varchar(36) not null,
			email 	   Varchar(100) not null unique,
			username   Varchar(225),
			password   Varchar(225) not null,
			token_hash  Varchar(15) not null,
			is_verified Boolean default false,
			created_at  Timestamp not null,
			updated_at  Timestamp not null,
			Primary Key (id)
		);
"#;

pub const VERIFICATION_SCHEMA: &str = r#"
		create table if not exists verifications (
			email 		Varchar(100) not null,
			code  		Varchar(10) not null,
			expires_at 	Timestamp not null,
			verification_type        Varchar(10) not null,
			Primary Key (email),
			Constraint fk_user_email Foreign Key(email) References users(email)
				On Delete Cascade On Update Cascade
		)
"#;

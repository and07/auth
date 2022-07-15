
use crate::services::authorization::{Authentication};


use crate::store::auth_repository::{
    AuthRepository, AuthRepositoryError, User, VerificationData, VerificationDataType,
};



struct RefreshTokenRequest{}
struct ProfileRequest{}
struct GeneratePassResetCodeRequest{}

struct SignupRequest{}
struct LoginRequest{}
struct VerifyPasswordResetRequest{}
struct VerifyMailRequest{}

struct UpdateUsernameRequest{
    username: String, 
}



// GenericResponse is the format of our response
struct GenericResponse<T> {
	status : bool    ,
	message :String  ,
	data   : Option<T> ,
}


// TokenResponse below data types are used for encoding and decoding b/t go types and json
struct TokenResponse  {
	refresh_token: String ,
	access_token:  String ,
}

// AuthResponse ...
struct AuthResponse  {
	refresh_token : String ,
	access_token  : String ,
	username     : String ,
}


// ResetPasswordRequest ...
struct ResetPasswordRequest  {
	password  : String,
	password_re: String,
	code:       String,
}


struct Configurations{}


#[derive(Debug)]
enum AuthHandlerError {

}


struct Auth  {
	//logger   :   hclog.Logger,
	configs   :  Configurations,
	repo     :   dyn AuthRepository,
	authService: dyn Authentication,
}

impl Auth {
    fn new(configs   :  Configurations,
        repo     :   dyn AuthRepository,
        authService: dyn Authentication,) ->Self{

            Auth{
                configs:configs,
                repo:repo,
                authService:authService,
            }

    }
}

 trait AuthHandler {

    //get
    fn RefreshToken(&self,request :RefreshTokenRequest) -> Result<GenericResponse<T>, AuthHandlerError>;
    fn Profile(&self,request :ProfileRequest) -> Result<GenericResponse<T>, AuthHandlerError>;
    fn  GeneratePassResetCode(&self,request :GeneratePassResetCodeRequest)-> Result<GenericResponse<T>, AuthHandlerError>;

    //post
    fn Signup(&self,request :SignupRequest)-> Result<GenericResponse<T>, AuthHandlerError>;
    fn  Login(&self,request :LoginRequest)-> Result<GenericResponse<T>, AuthHandlerError>;
    fn VerifyPasswordReset(&self,request :VerifyPasswordResetRequest)-> Result<GenericResponse<T>, AuthHandlerError>;
    fn  VerifyMail(&self,request :VerifyMailRequest)-> Result<GenericResponse<T>, AuthHandlerError>;

    //put
    fn UpdateUsername(&self,request :UpdateUsernameRequest) -> Result<GenericResponse<T>, AuthHandlerError>;
    fn ResetPassword(&self, request :ResetPasswordRequest)-> Result<GenericResponse<T>, AuthHandlerError>;
}

impl AuthHandler for Auth{


        //get
        fn RefreshToken(&self,request :RefreshTokenRequest) -> Result<GenericResponse<T>, AuthHandlerError>{
            todo!()
        }
        fn Profile(&self,request :ProfileRequest) -> Result<GenericResponse, AuthHandlerError>{
            todo!()
        }
        fn  GeneratePassResetCode(&self,request :GeneratePassResetCodeRequest)-> Result<GenericResponse, AuthHandlerError>{
            todo!()
        }
    
        //post
        fn Signup(&self,request :SignupRequest)-> Result<GenericResponse, AuthHandlerError>{
            todo!()
        }
        fn  Login(&self,request :LoginRequest)-> Result<GenericResponse, AuthHandlerError>{
            todo!()
        }
        fn VerifyPasswordReset(&self,request :VerifyPasswordResetRequest)-> Result<GenericResponse, AuthHandlerError>{
            todo!()
        }
        fn  VerifyMail(&self,request :VerifyMailRequest)-> Result<GenericResponse, AuthHandlerError>{
            todo!()
        }
    
        //put
        fn UpdateUsername(&self,request :UpdateUsernameRequest) -> Result<GenericResponse, AuthHandlerError>{
            todo!()
        }
        fn ResetPassword(&self, request :ResetPasswordRequest)-> Result<GenericResponse, AuthHandlerError>{
            todo!()
        }
}

#[test]
fn test_y() {

}
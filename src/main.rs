#[macro_use]
extern crate diesel;
pub mod models;
pub mod schema;

use models::{Comment, LoginUser, NewComment, NewPost, NewUser, Post, User};

use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix_web::{middleware::Logger, post, web, App, HttpResponse, HttpServer, Responder};
use argonautica::Verifier;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;
type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;
use dotenv::dotenv;
use log;
use serde::Deserialize;
use tera::{Context, Tera};

#[derive(Debug)]
enum ServerError {
    ArgonauticError,
    DieselError,
    EnvironmentError,
    R2D2Error,
    UserError(String),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Test")
    }
}

impl actix_web::error::ResponseError for ServerError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ServerError::ArgonauticError => {
                HttpResponse::InternalServerError().json("Argonautic Error")
            }
            ServerError::DieselError => HttpResponse::InternalServerError().json("Diesel Error"),
            ServerError::EnvironmentError => {
                HttpResponse::InternalServerError().json("Environment Error")
            }
            ServerError::R2D2Error => HttpResponse::InternalServerError().json("R2D2 Error"),
            ServerError::UserError(data) => HttpResponse::InternalServerError().json(data),
        }
    }
}

impl From<std::env::VarError> for ServerError {
    fn from(err: std::env::VarError) -> ServerError {
        log::error!("{:?}", err);
        ServerError::EnvironmentError
    }
}

impl From<r2d2::Error> for ServerError {
    fn from(err: r2d2::Error) -> ServerError {
        log::error!("{:?}", err);
        ServerError::R2D2Error
    }
}

impl From<diesel::result::Error> for ServerError {
    fn from(err: diesel::result::Error) -> Self {
        match err {
            diesel::result::Error::NotFound => {
                log::error!("{:?}", err);
                ServerError::UserError("User not found".to_string())
            }
            _ => ServerError::DieselError,
        }
    }
}

impl From<argonautica::Error> for ServerError {
    fn from(err: argonautica::Error) -> Self {
        log::error!("{:?}", err);
        ServerError::ArgonauticError
    }
}

#[derive(Deserialize)]
pub struct PostForm {
    pub title: String,
    pub link: String,
}

//#[derive(Debug, Deserialize)]
//struct User {
//    username: String,
//    email: String,
//    password: String,
//}

#[derive(Deserialize)]
struct CommentForm {
    comment: String,
}

//fn establish_connection() -> PgConnection {
//    dotenv().ok();
//
//    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
//
//    PgConnection::establish(&database_url).expect(&format!("Error connecting to {}", database_url))
//}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

async fn index(tera: web::Data<Tera>, pool: web::Data<Pool>) -> Result<HttpResponse, ServerError> {
    use schema::posts::dsl::posts;
    use schema::users::dsl::users;

    let connection = pool.get()?;
    let all_posts: Vec<(Post, User)> = posts.inner_join(users).load(&connection)?;

    let mut data = Context::new();
    data.insert("title", "Hacker Clone");
    data.insert("posts_users", &all_posts);

    let rendered = tera.render("index.html", &data).unwrap();
    Ok(HttpResponse::Ok().body(rendered))
}

async fn signup(tera: web::Data<Tera>) -> impl Responder {
    let mut data = Context::new();
    data.insert("title", "Sign Up");

    let rendered = tera.render("signup.html", &data).unwrap();
    HttpResponse::Ok().body(rendered)
}

async fn process_signup(
    data: web::Form<NewUser>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    use schema::users;

    let connection = pool.get()?;

    let new_user = NewUser::new(
        data.username.clone(),
        data.email.clone(),
        data.password.clone(),
    );

    diesel::insert_into(users::table)
        .values(&new_user)
        .get_result::<User>(&connection)?;
    println!("{:?}", data);

    Ok(HttpResponse::Ok().body(format!("Successfully saved user: {}", data.username)))
}

async fn login(tera: web::Data<Tera>, id: Identity) -> impl Responder {
    let mut data = Context::new();
    data.insert("title", "Login");

    if let Some(_) = id.identity() {
        return HttpResponse::Ok().body("Already logged in");
    }
    let rendered = tera.render("login.html", &data).unwrap();
    HttpResponse::Ok().body(rendered)
}

async fn process_login(
    data: web::Form<LoginUser>,
    id: Identity,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    use schema::users::dsl::{username, users};
    //use schema::users::dsl::*;

    let connection = pool.get()?;
    let user = users
        .filter(username.eq(&data.username))
        .first::<User>(&connection)?;

    dotenv().ok();
    let secret = std::env::var("SECRET_KEY")?;

    let valid = Verifier::default()
        .with_hash(user.password)
        .with_password(data.password.clone())
        .with_secret_key(secret)
        .verify()?;

    if valid {
        let session_token = String::from(user.username);
        id.remember(session_token);
        println!("{:?}", data);
        Ok(HttpResponse::Ok().body(format!("Logged in: {}", data.username)))
    } else {
        Ok(HttpResponse::Unauthorized().body(format!("Password is incorrect")))
    }
}

async fn submission(tera: web::Data<Tera>, id: Identity) -> impl Responder {
    let mut data = Context::new();
    data.insert("title", "Submit a Post");

    if let Some(_) = id.identity() {
        let rendered = tera.render("submission.html", &data).unwrap();
        HttpResponse::Ok().body(rendered)
    } else {
        HttpResponse::Unauthorized().body("User not logged in")
    }
}

async fn process_submission(
    data: web::Form<PostForm>,
    id: Identity,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    if let Some(id) = id.identity() {
        use schema::users::dsl::{username, users};

        let connection = pool.get()?;
        //let user: Result<User, diesel::result::Error> =
        //users.filter(username.eq(id)).first(&connection);
        let user: User = users.filter(username.eq(id)).first(&connection)?;

        let new_post = NewPost::from_post_form(data.into_inner(), user.id);

        use schema::posts;

        diesel::insert_into(posts::table)
            .values(&new_post)
            .get_result::<Post>(&connection)?;
        //.expect("Error saving post");
    }

    Ok(HttpResponse::Ok().body(format!("Posted submitted")))
}

async fn logout(id: Identity) -> impl Responder {
    id.forget();
    HttpResponse::Ok().body("Logged out")
}

async fn post_page(
    tera: web::Data<Tera>,
    id: Identity,
    web::Path(post_id): web::Path<i32>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    use schema::posts::dsl::posts;
    use schema::users::dsl::users;

    let connection = pool.get()?;

    let post: Post = posts.find(post_id).get_result(&connection)?;
    //.expect("Failed to find post");

    let comments: Vec<(Comment, User)> = Comment::belonging_to(&post)
        .inner_join(users)
        .load(&connection)?;
    //.expect("Failed to find comments");

    let user: User = users.find(post.author).get_result(&connection)?;
    //.expect("Failed to find user");

    let mut data = Context::new();
    data.insert("title", &format!("{} - HackerClone", post.title));
    data.insert("post", &post);
    data.insert("user", &user);
    data.insert("comments", &comments);

    if let Some(_id) = id.identity() {
        data.insert("logged_in", "true");
    } else {
        data.insert("logged_in", "false");
    }

    let rendered = tera.render("post.html", &data).unwrap();
    Ok(HttpResponse::Ok().body(rendered))
}

async fn comment(
    data: web::Form<CommentForm>,
    id: Identity,
    web::Path(post_id): web::Path<i32>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    if let Some(id) = id.identity() {
        use schema::posts::dsl::posts;
        use schema::users::dsl::{username, users};

        let connection = pool.get()?;

        let post: Post = posts.find(post_id).get_result(&connection)?;
        //.expect("Failed to find post");

        //let user: Result<User, diesel::result::Error> =
        //    users.filter(username.eq(id)).first(&connection);
        let user: User = users.filter(username.eq(id)).first(&connection)?;

        let parent_id = None;
        let new_comment = NewComment::new(data.comment.clone(), post.id, user.id, parent_id);

        use schema::comments;
        diesel::insert_into(comments::table)
            .values(&new_comment)
            .get_result::<Comment>(&connection)?;
        //.expect("Error saving comment");

        return Ok(HttpResponse::Ok().body("Commented"));
    }

    Ok(HttpResponse::Unauthorized().body("Not logged in"))
}

async fn user_profile(
    tera: web::Data<Tera>,
    web::Path(requested_user): web::Path<String>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    use schema::users::dsl::{username, users};

    let connection = pool.get()?;

    let user: User = users
        .filter(username.eq(requested_user))
        .get_result(&connection)?;
    //.expect("Failed to find user");

    let posts: Vec<Post> = Post::belonging_to(&user).load(&connection)?;
    //.expect("Failed to find posts");

    let comments: Vec<Comment> = Comment::belonging_to(&user).load(&connection)?;
    //.expect("Failed to find comments");

    let mut data = Context::new();
    data.insert("title", &format!("{} - Profile", user.username));
    data.insert("user", &user);
    data.insert("posts", &posts);
    data.insert("comments", &comments);

    let rendered = tera.render("profile.html", &data).unwrap();
    Ok(HttpResponse::Ok().body(rendered))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create postgres pool");

    env_logger::init();

    HttpServer::new(move || {
        let tera = Tera::new("templates/**/*").unwrap();
        App::new()
            .wrap(Logger::default())
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("auth-cookie")
                    .secure(false),
            ))
            .data(tera)
            .data(pool.clone())
            .route(
                "/hello",
                web::get().to(|| HttpResponse::Ok().body("Namastey Duniyaa!")),
            )
            .route("/", web::get().to(index))
            .route("/signup", web::get().to(signup))
            .route("/signup", web::post().to(process_signup))
            .route("/login", web::get().to(login))
            .route("/login", web::post().to(process_login))
            .route("/submission", web::get().to(submission))
            .route("/submission", web::post().to(process_submission))
            .route("/logout", web::to(logout))
            .service(echo)
            .service(
                web::resource("/post/{post_id}")
                    .route(web::get().to(post_page))
                    .route(web::post().to(comment)),
            )
            .service(web::resource("/user/{username}").route(web::get().to(user_profile)))
    })
    .bind("127.0.0.1:8000")?
    .run()
    .await
}

#[macro_use]
extern crate diesel;
pub mod models;
pub mod schema;

use models::{Comment, LoginUser, NewComment, NewPost, NewUser, Post, User};

use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use dotenv::dotenv;
use serde::Deserialize;
use tera::{Context, Tera};

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

fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    PgConnection::establish(&database_url).expect(&format!("Error connecting to {}", database_url))
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

async fn index(tera: web::Data<Tera>) -> impl Responder {
    use schema::posts::dsl::posts;
    use schema::users::dsl::users;

    let connection = establish_connection();
    let all_posts: Vec<(Post, User)> = posts
        .inner_join(users)
        .load(&connection)
        .expect("Error retrieving all posts");

    let mut data = Context::new();
    data.insert("title", "Hacker Clone");
    data.insert("posts_users", &all_posts);

    let rendered = tera.render("index.html", &data).unwrap();
    HttpResponse::Ok().body(rendered)
}

async fn signup(tera: web::Data<Tera>) -> impl Responder {
    let mut data = Context::new();
    data.insert("title", "Sign Up");

    let rendered = tera.render("signup.html", &data).unwrap();
    HttpResponse::Ok().body(rendered)
}

async fn process_signup(data: web::Form<NewUser>) -> impl Responder {
    use schema::users;

    let connection = establish_connection();

    diesel::insert_into(users::table)
        .values(&*data)
        .get_result::<User>(&connection)
        .expect("Error registerting user");
    println!("{:?}", data);

    HttpResponse::Ok().body(format!("Successfully saved user: {}", data.username))
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

async fn process_login(data: web::Form<LoginUser>, id: Identity) -> impl Responder {
    use schema::users::dsl::{username, users};
    //use schema::users::dsl::*;

    let connection = establish_connection();
    let user = users
        .filter(username.eq(&data.username))
        .first::<User>(&connection);

    match user {
        Ok(u) => {
            if u.password == data.password {
                let session_token = String::from(u.username);
                id.remember(session_token);
                println!("{:?}", data);
                HttpResponse::Ok().body(format!("Logged in: {}", data.username))
            } else {
                HttpResponse::Unauthorized().body(format!("Password is incorrect"))
            }
        }
        Err(err) => {
            println!("{:?}", err);
            HttpResponse::Unauthorized().body(format!("User doesnt exist"))
        }
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

async fn process_submission(data: web::Form<PostForm>, id: Identity) -> impl Responder {
    if let Some(id) = id.identity() {
        use schema::users::dsl::{username, users};

        let connection = establish_connection();
        let user: Result<User, diesel::result::Error> =
            users.filter(username.eq(id)).first(&connection);

        match user {
            Ok(u) => {
                let new_post = NewPost::from_post_form(data.into_inner(), u.id);

                use schema::posts;

                diesel::insert_into(posts::table)
                    .values(&new_post)
                    .get_result::<Post>(&connection)
                    .expect("Error saving post");
            }
            Err(err) => {
                println!("{:?}", err);
                HttpResponse::NotFound().body("Failed to find user");
            }
        }
    }

    HttpResponse::Ok().body(format!("Posted submitted"))
}

async fn logout(id: Identity) -> impl Responder {
    id.forget();
    HttpResponse::Ok().body("Logged out")
}

async fn post_page(
    tera: web::Data<Tera>,
    id: Identity,
    web::Path(post_id): web::Path<i32>,
) -> impl Responder {
    use schema::posts::dsl::posts;
    use schema::users::dsl::users;

    let connection = establish_connection();

    let post: Post = posts
        .find(post_id)
        .get_result(&connection)
        .expect("Failed to find post");

    let comments: Vec<(Comment, User)> = Comment::belonging_to(&post)
        .inner_join(users)
        .load(&connection)
        .expect("Failed to find comments");

    let user: User = users
        .find(post.author)
        .get_result(&connection)
        .expect("Failed to find user");

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
    HttpResponse::Ok().body(rendered)
}

async fn comment(
    data: web::Form<CommentForm>,
    id: Identity,
    web::Path(post_id): web::Path<i32>,
) -> impl Responder {
    if let Some(id) = id.identity() {
        use schema::posts::dsl::posts;
        use schema::users::dsl::{username, users};

        let connection = establish_connection();

        let post: Post = posts
            .find(post_id)
            .get_result(&connection)
            .expect("Failed to find post");

        let user: Result<User, diesel::result::Error> =
            users.filter(username.eq(id)).first(&connection);

        match user {
            Ok(u) => {
                let parent_id = None;
                let new_comment = NewComment::new(data.comment.clone(), post.id, u.id, parent_id);

                use schema::comments;
                diesel::insert_into(comments::table)
                    .values(&new_comment)
                    .get_result::<Comment>(&connection)
                    .expect("Error saving comment");

                return HttpResponse::Ok().body("Commented");
            }
            Err(err) => {
                println!("{}", err);
                return HttpResponse::NoContent().body("User not found");
            }
        }
    }

    HttpResponse::Unauthorized().body("Not logged in")
}

async fn user_profile(
    tera: web::Data<Tera>,
    web::Path(requested_user): web::Path<String>,
) -> impl Responder {
    use schema::users::dsl::{username, users};

    let connection = establish_connection();

    let user: User = users
        .filter(username.eq(requested_user))
        .get_result(&connection)
        .expect("Failed to find user");

    let posts: Vec<Post> = Post::belonging_to(&user)
        .load(&connection)
        .expect("Failed to find posts");

    let comments: Vec<Comment> = Comment::belonging_to(&user)
        .load(&connection)
        .expect("Failed to find comments");

    let mut data = Context::new();
    data.insert("title", &format!("{} - Profile", user.username));
    data.insert("user", &user);
    data.insert("posts", &posts);
    data.insert("comments", &comments);

    let rendered = tera.render("profile.html", &data).unwrap();
    HttpResponse::Ok().body(rendered)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(move || {
        let tera = Tera::new("templates/**/*").unwrap();
        App::new()
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("auth-cookie")
                    .secure(false),
            ))
            .data(tera)
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

use anyhow::{Context, Result};
use log::Level::Info;
use openapiv3::OpenAPI;
use url::Url;

use crate::header;

fn send_request(
    client: reqwest::blocking::Client,
    url: &str,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    // Send the GET request
    let t_response = match client.get(url).send() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Request error: {}", e);
            return Err(e);
        }
    };
    Ok(t_response)
}

fn print_response(mode: &str, response: &str) {
    println!("Response from authenticator:");
    println!("\t{:<24}{}", "Authentication mode:", mode);
    println!("\t{:<24}{}", "Response:", response);
}

pub fn verify_auth(api: OpenAPI) -> Result<()> {
    println!("\n=============================================================================");
    println!("\n[*] Running authentication verification!\n\n");

    // Initialize authentication
    let mut authentication = super::initialize().context("Could not initialize authentication")?;

    // Get the API server from the OpenAPI spec
    let server = api
        .servers
        .first()
        .ok_or_else(|| anyhow!("No servers found in the OpenAPI specification."))?;

    // Setup cookie store to save the authentication token. This token is added to all HTTP headers.
    let cookie_store = std::sync::Arc::new(reqwest_cookie_store::CookieStoreMutex::new(
        authentication.cookie_store(&Url::parse(&server.url).unwrap()),
    ));
    let client_builder =
        reqwest::blocking::Client::builder().cookie_provider(std::sync::Arc::clone(&cookie_store));

    let mut default_headers = authentication.generate_headers();
    default_headers.extend(header::get_default_headers()?);

    let client = client_builder.default_headers(default_headers).build()?;

    // Print the response from the authentication
    match authentication {
        super::Authentication::None => print_response("None", "None"),
        super::Authentication::Raw(contents) => print_response("Raw", &contents),
        super::Authentication::Basic(config) => print_response("Basic", &config),
        super::Authentication::Bearer(token) => print_response("Bearer", &token),
        super::Authentication::Cookie(mut cookie_vector) => {
            let mut cookies = String::new();
            for cookie_item in cookie_vector.iter_mut() {
                let s = format!(
                    "\n\t{:<24}{}={}",
                    " ",
                    cookie_item.name(),
                    cookie_item.value()
                );
                cookies.push_str(&s);
            }
            print_response("Cookie", cookies.as_str());
        }
        super::Authentication::OAuth(mut tokens) => {
            if let Ok(token) = tokens.access_token() {
                print_response("OAuth", token);
            } else {
                print_response("OAuth", "Token");
            }
        }
    };

    // Check all paths for a "401 Unauthorized" error, which means authentication has failed
    for (path, _path_item) in api.paths.iter() {
        let url = server.url.clone() + path;
        let t_response = send_request(client.clone(), &url);
        if log::log_enabled!(Info) {
            println!("Path: {}", path);
        }
        match t_response {
            Ok(r) => {
                if r.status() == reqwest::StatusCode::UNAUTHORIZED {
                    println!("\n\nAuthentication verification:");
                    println!("\tResult:   failed");
                    println!("\tReason:   received status code: 401 Unauthorized");
                    println!("\tEndpoint: {url}\n");
                    println!(
                        "\n\nTip: for less verbose logging, set the flag \"--log-level=warn\""
                    );
                    println!("=============================================================================");
                    bail!("Could not authenticate: 401 Unauthorized");
                }
                // println!("\tResponse: {:?}", r.status());
                if log::log_enabled!(Info) {
                    println!("\tResponse: {:?}", r.text().unwrap());
                }
            }
            Err(e) => {
                println!("\n\nAuthentication verification:");
                println!("\tResult:   failed");
                println!("\tError in sending request: {e}");
                println!("\tIs the API up and running?");
                return Err(e).context("Error sending request to the API");
            }
        };
    }

    // No authorization errors found: success!
    println!("\n\nAuthentication verification:");
    println!("\tResult: success!\n");
    println!("\n\nTip: for less verbose logging, set the flag \"--log-level=warn\"");
    println!("=============================================================================");
    Ok(())
}

use std::path::Path;
#[cfg(windows)]
use std::ptr::write_volatile;

use anyhow::Result;
use libafl::inputs::Input;
#[allow(unused_imports)]
use libafl::Fuzzer; // This may be marked unused, but will make the compiler give you crucial error messages
use log::{error, info, warn};

use crate::{
    authentication::build_http_client,
    configuration::Configuration,
    input::OpenApiInput,
    openapi::{
        build_request::build_request_from_input,
        curl_request::CurlRequest,
        validate_response::{validate_response, Response},
    },
    parameter_feedback::ParameterFeedback,
};

/// Reproduces a given input file generated by the fuzzer (as a crash file or a corpus entry).
pub fn reproduce(input_file: &Path) -> Result<()> {
    let config = Configuration::get().map_err(anyhow::Error::msg)?;
    crate::setup_logging(config);
    let api = crate::get_api_spec(
        config
            .openapi_spec
            .as_ref()
            .ok_or_else(|| anyhow!("No OpenAPI specification given"))?,
    )?;
    let inputs = OpenApiInput::from_file(input_file)?;

    let (authentication, cookie_store, client) = build_http_client()?;

    println!(
        "Input file {:?} contains {} inputs",
        input_file,
        inputs.0.len()
    );

    let mut parameter_feedback = ParameterFeedback::new(inputs.0.len());

    for (request_index, request) in inputs.0.iter().enumerate() {
        info!("\n-----\nSending request: \n{}", request);

        let mut request = request.clone();
        if let Err(error) = request.resolve_parameter_references(&parameter_feedback) {
            error!(
                "Cannot instantiate request: missing value for backreferenced parameter: {}",
                error
            );
            continue;
        };

        let request_built = match build_request_from_input(&client, &cookie_store, &api, &request)
            .map(|builder| builder.build())
        {
            None => {
                warn!("Could not generate a HTTP request from this input. Skipping ...");
                continue;
            }
            Some(Err(message)) => {
                error!("Error building the request: {}", message);
                break;
            }
            Some(Ok(request)) => {
                info!(
                    "Converted to CURL command:\n{}",
                    CurlRequest(&request, &authentication)
                );
                request
            }
        };

        match client.execute(request_built) {
            Ok(response) => {
                let response: Response = response.into();
                if response.status().is_server_error() {
                    warn!("Crash reported by server: {}", response.status());
                    if let Ok(text) = response.text() {
                        info!("Response contents printed below: \n{}", text)
                    }
                    break;
                } else {
                    info!("Request successful ({})", response.status());
                    match validate_response(&api, &request, &response) {
                        Ok(()) => info!("Response matches specification"),
                        Err(e) => warn!("Validation error: {}", e),
                    }
                    if let Ok(text) = response.text() {
                        info!("Response contents printed below: \n{}", text)
                    }
                    if response.status().is_success() {
                        parameter_feedback.process_response(request_index, response);
                    }
                }
            }
            Err(e) => {
                error!("Error sending the request: {}", e);
                break;
            }
        }
        parameter_feedback.process_post_request(request_index, request);
    }
    Ok(())
}

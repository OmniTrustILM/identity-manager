//! The one HTTP client for ILM and the identity providers.

use std::time::Duration;

use reqwest::{Client, ClientBuilder, redirect};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn builder() -> ClientBuilder {
    Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(redirect::Policy::none())
        .user_agent(concat!("Identity Manager/", env!("CARGO_PKG_VERSION")))
}

/// HTTPS only, checked against the certificate store of the system; redirects are not followed.
pub fn client() -> Client {
    build(builder().https_only(true))
}

/// Like [`client`] but also reaches plain `http` servers, for stand-ins on 127.0.0.1.
#[cfg(test)]
pub fn client_for_tests() -> Client {
    build(builder())
}

fn build(builder: ClientBuilder) -> Client {
    builder.build().expect("the HTTP client settings are valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn serve(response: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0; 2048];
            let read = stream.read(&mut buffer).unwrap();
            let request = String::from_utf8_lossy(&buffer[..read]).to_lowercase();
            let body = if request.contains(&format!(
                "user-agent: identity manager/{}",
                env!("CARGO_PKG_VERSION")
            )) {
                "agent"
            } else {
                "no agent"
            };
            let response = response.replace("{body}", body);
            stream.write_all(response.as_bytes()).unwrap();
        });
        format!("http://{address}/")
    }

    #[tokio::test]
    async fn the_test_client_reaches_a_local_http_server_and_names_itself() {
        let url = serve("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n{body}");
        let body = client_for_tests()
            .get(url)
            .send()
            .await
            .unwrap()
            .text()
            .await;
        assert_eq!(body.unwrap(), "agent");
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let url = serve(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let response = client_for_tests().get(url).send().await.unwrap();
        assert_eq!(response.status(), 302);
    }

    #[tokio::test]
    async fn the_real_client_refuses_plain_http() {
        let url = serve("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        assert!(client().get(url).send().await.is_err());
    }
}

use crate::{
    CryptoError, Entry, IndexedStorer, IndexedTypeStorer, StorableType, Storer, TypeStorer,
};
use async_trait::async_trait;
use mongodb::bson::Document;
use once_cell::sync::Lazy;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    fs::File,
    io::Read,
    sync::{Arc, RwLock},
};

static CLIENT_TLS_CONFIG: Lazy<RwLock<Arc<Option<ClientTlsConfig>>>> =
    Lazy::new(|| RwLock::new(Default::default()));

#[derive(Debug)]
pub enum RedactStorerError {
    /// Represents an error which occurred in some internal system
    InternalError {
        source: Box<dyn Error + Send + Sync>,
    },

    /// Requested document was not found
    NotFound,

    /// PKCS12 file could not be read at the given path
    Pkcs12FileNotReadable { source: std::io::Error },

    /// Server CA cert file could not be read at the given path
    ServerCaCertFileNotReadable { source: std::io::Error },

    /// Bytes in PKCS12 file are not valid PKCS12 bytes
    HttpClientNotBuildable { source: reqwest::Error },
}

impl Error for RedactStorerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            RedactStorerError::InternalError { ref source } => Some(source.as_ref()),
            RedactStorerError::NotFound => None,
            RedactStorerError::Pkcs12FileNotReadable { ref source } => Some(source),
            RedactStorerError::HttpClientNotBuildable { ref source } => Some(source),
            RedactStorerError::ServerCaCertFileNotReadable { ref source } => Some(source),
        }
    }
}

impl Display for RedactStorerError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            RedactStorerError::InternalError { .. } => {
                write!(f, "Internal error occurred")
            }
            RedactStorerError::NotFound => {
                write!(f, "Requested document not found")
            }
            RedactStorerError::Pkcs12FileNotReadable { .. } => {
                write!(f, "Could not open PKCS12 client TLS file")
            }
            RedactStorerError::HttpClientNotBuildable { .. } => {
                write!(f, "Could not build HTTP request client")
            }
            RedactStorerError::ServerCaCertFileNotReadable { .. } => {
                write!(f, "Could not read server CA certificate")
            }
        }
    }
}

impl From<RedactStorerError> for CryptoError {
    fn from(rse: RedactStorerError) -> Self {
        match rse {
            RedactStorerError::InternalError { .. } => CryptoError::InternalError {
                source: Box::new(rse),
            },
            RedactStorerError::NotFound => CryptoError::NotFound {
                source: Box::new(rse),
            },
            RedactStorerError::Pkcs12FileNotReadable { .. } => CryptoError::InternalError {
                source: Box::new(rse),
            },
            RedactStorerError::HttpClientNotBuildable { .. } => CryptoError::InternalError {
                source: Box::new(rse),
            },
            RedactStorerError::ServerCaCertFileNotReadable { .. } => CryptoError::InternalError {
                source: Box::new(rse),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ClientTlsConfig {
    pub pkcs12_path: String,
    pub server_ca_path: Option<String>,
}

impl ClientTlsConfig {
    pub fn current() -> Arc<Option<ClientTlsConfig>> {
        CLIENT_TLS_CONFIG.read().unwrap().clone()
    }

    pub fn make_current(self) {
        *CLIENT_TLS_CONFIG.write().unwrap() = Arc::new(Some(self))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RedactStorer {
    url: String,
}

/// Stores an instance of a redact-backed key storer.
/// The redact-store server is an example implementation of a redact storage backing.
impl RedactStorer {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
        }
    }
}

impl From<RedactStorer> for IndexedTypeStorer {
    fn from(rs: RedactStorer) -> Self {
        IndexedTypeStorer::Redact(rs)
    }
}

impl From<RedactStorer> for TypeStorer {
    fn from(rs: RedactStorer) -> Self {
        TypeStorer::Indexed(IndexedTypeStorer::Redact(rs))
    }
}

impl RedactStorer {
    fn get_http_client() -> Result<reqwest::Client, RedactStorerError> {
        match *ClientTlsConfig::current() {
            Some(ref ctc) => {
                let mut pkcs12_vec: Vec<u8> = vec![];
                File::open(&ctc.pkcs12_path)
                    .map_err(|source| RedactStorerError::Pkcs12FileNotReadable { source })?
                    .read_to_end(&mut pkcs12_vec)
                    .map_err(|source| RedactStorerError::Pkcs12FileNotReadable { source })?;
                let pkcs12 = reqwest::Identity::from_pem(&pkcs12_vec)
                    .map_err(|source| RedactStorerError::HttpClientNotBuildable { source })?;
                match &ctc.server_ca_path {
                    Some(path) => {
                        let mut ca_cert_vec: Vec<u8> = vec![];
                        File::open(path)
                            .map_err(|source| RedactStorerError::ServerCaCertFileNotReadable {
                                source,
                            })?
                            .read_to_end(&mut ca_cert_vec)
                            .map_err(|source| RedactStorerError::ServerCaCertFileNotReadable {
                                source,
                            })?;
                        let ca_cert =
                            reqwest::Certificate::from_pem(&ca_cert_vec).map_err(|source| {
                                RedactStorerError::HttpClientNotBuildable { source }
                            })?;
                        Ok::<_, RedactStorerError>(
                            reqwest::Client::builder()
                                .identity(pkcs12)
                                .add_root_certificate(ca_cert)
                                .tls_built_in_root_certs(false)
                                .use_rustls_tls()
                                .pool_max_idle_per_host(10)
                                .build()
                                .map_err(|source| RedactStorerError::HttpClientNotBuildable {
                                    source,
                                })?,
                        )
                    }
                    None => Ok::<_, RedactStorerError>(
                        reqwest::Client::builder()
                            .identity(pkcs12)
                            .use_rustls_tls()
                            .pool_max_idle_per_host(10)
                            .build()
                            .map_err(|source| RedactStorerError::HttpClientNotBuildable {
                                source,
                            })?,
                    ),
                }
            }
            None => Ok(reqwest::Client::builder()
                .use_rustls_tls()
                .build()
                .map_err(|source| RedactStorerError::HttpClientNotBuildable { source })?),
        }
    }
}

#[async_trait]
impl IndexedStorer for RedactStorer {
    async fn get_indexed<T: StorableType>(
        &self,
        path: &str,
        index: &Option<Document>,
    ) -> Result<Entry<T>, CryptoError> {
        let mut req_url = format!("{}/{}?", &self.url, path);
        if let Some(i) = index {
            req_url.push_str(format!("index={}", i).as_ref());
        }
        let http_client = RedactStorer::get_http_client()?;

        match http_client.get(&req_url).send().await {
            Ok(r) => Ok(r
                .error_for_status()
                .map_err(|source| -> CryptoError {
                    if source.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                        RedactStorerError::NotFound.into()
                    } else {
                        RedactStorerError::InternalError {
                            source: Box::new(source),
                        }
                        .into()
                    }
                })?
                .json::<Entry<T>>()
                .await
                .map_err(|source| -> CryptoError {
                    RedactStorerError::InternalError {
                        source: Box::new(source),
                    }
                    .into()
                })?),
            Err(source) => Err(RedactStorerError::InternalError {
                source: Box::new(source),
            }
            .into()),
        }
    }

    async fn list_indexed<T: StorableType>(
        &self,
        path: &str,
        skip: u64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry<T>>, CryptoError> {
        let mut req_url = format!(
            "{}/{}?skip={}&page_size={}",
            &self.url, path, skip, page_size
        );
        if let Some(i) = index {
            req_url.push_str(format!("&index={}", i).as_ref());
        }
        let http_client = RedactStorer::get_http_client()?;

        match http_client.get(&req_url).send().await {
            Ok(r) => Ok(r
                .error_for_status()
                .map_err(|source| -> CryptoError {
                    if source.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                        RedactStorerError::NotFound.into()
                    } else {
                        RedactStorerError::InternalError {
                            source: Box::new(source),
                        }
                        .into()
                    }
                })?
                .json::<Vec<Entry<T>>>()
                .await
                .map_err(|source| -> CryptoError {
                    RedactStorerError::InternalError {
                        source: Box::new(source),
                    }
                    .into()
                })?),
            Err(source) => Err(RedactStorerError::InternalError {
                source: Box::new(source),
            }
            .into()),
        }
    }
}

#[async_trait]
impl Storer for RedactStorer {
    async fn get<T: StorableType>(&self, path: &str) -> Result<Entry<T>, CryptoError> {
        self.get_indexed::<T>(path, &T::get_index()).await
    }

    async fn create<T: StorableType>(&self, entry: Entry<T>) -> Result<Entry<T>, CryptoError> {
        let value = serde_json::to_value(&entry).map_err(|e| RedactStorerError::InternalError {
            source: Box::new(e),
        })?;
        let http_client = RedactStorer::get_http_client()?;

        http_client
            .post(&format!("{}/", self.url))
            .json(&value)
            .send()
            .await
            .and_then(|res| res.error_for_status().map(|_| entry))
            .map_err(|e| {
                if let Some(status) = e.status() {
                    if status == StatusCode::NOT_FOUND {
                        RedactStorerError::NotFound.into()
                    } else {
                        RedactStorerError::InternalError {
                            source: Box::new(e),
                        }
                        .into()
                    }
                } else {
                    RedactStorerError::InternalError {
                        source: Box::new(e),
                    }
                    .into()
                }
            })
    }
}

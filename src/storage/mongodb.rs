use crate::{CryptoError, Entry, StorableType, Storer, TypeStorer};
use async_trait::async_trait;
use futures::StreamExt;
use mongodb::{
    bson::{self, Bson, Document},
    options::ClientOptions,
    options::{FindOneOptions, FindOptions},
    Client,
};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

#[derive(Debug)]
pub enum MongoStorerError {
    /// Represents an error which occurred in some internal system
    InternalError {
        source: Box<dyn Error + Send + Sync>,
    },

    /// Requested document was not found
    NotFound,
}

impl Error for MongoStorerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            MongoStorerError::InternalError { ref source } => Some(source.as_ref()),
            MongoStorerError::NotFound => None,
        }
    }
}

impl Display for MongoStorerError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            MongoStorerError::InternalError { .. } => {
                write!(f, "Internal error occurred")
            }
            MongoStorerError::NotFound => {
                write!(f, "Requested document not found")
            }
        }
    }
}

impl From<MongoStorerError> for CryptoError {
    fn from(mse: MongoStorerError) -> Self {
        match mse {
            MongoStorerError::InternalError { .. } => CryptoError::InternalError {
                source: Box::new(mse),
            },
            MongoStorerError::NotFound => CryptoError::NotFound {
                source: Box::new(mse),
            },
        }
    }
}

/// Stores an instance of a mongodb-backed key storer
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(into = "MongoDbInfo", from = "MongoDbInfo")]
pub struct MongoStorer {
    db_info: MongoDbInfo,
    client: OnceCell<Client>,
}

impl From<MongoStorer> for TypeStorer {
    fn from(ms: MongoStorer) -> Self {
        TypeStorer::Mongo(ms)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MongoDbInfo {
    url: String,
    db_name: String,
}

impl From<MongoStorer> for MongoDbInfo {
    fn from(storer: MongoStorer) -> Self {
        storer.db_info
    }
}

impl From<MongoDbInfo> for MongoStorer {
    fn from(db_info: MongoDbInfo) -> Self {
        MongoStorer {
            db_info,
            client: OnceCell::new(),
        }
    }
}

impl MongoStorer {
    /// Instantiates a mongo-backed key storer using a URL to the mongo cluster and the
    /// name of the DB to connect to.
    pub fn new(url: &str, db_name: &str) -> Self {
        let db_info = MongoDbInfo {
            url: url.to_owned(),
            db_name: db_name.to_owned(),
        };
        MongoStorer {
            db_info,
            client: OnceCell::new(),
        }
    }
}

impl MongoStorer {
    async fn get_client(&self) -> Result<&Client, MongoStorerError> {
        match self.client.get() {
            Some(c) => Ok(c),
            None => {
                let db_client_options = ClientOptions::parse_with_resolver_config(
                    &self.db_info.url,
                    mongodb::options::ResolverConfig::cloudflare(),
                )
                .await
                .map_err(|e| MongoStorerError::InternalError {
                    source: Box::new(e),
                })?;
                self.client.get_or_try_init(|| {
                    Client::with_options(db_client_options).map_err(|e| {
                        MongoStorerError::InternalError {
                            source: Box::new(e),
                        }
                    })
                })
            }
        }
    }
}

#[async_trait]
impl Storer for MongoStorer {
    async fn get_indexed<T: StorableType>(
        &self,
        path: &str,
        index: &Option<Document>,
    ) -> Result<Entry<T>, CryptoError> {
        let mut filter = bson::doc! { "path": path };
        if let Some(i) = index {
            filter.insert("value", i);
        }

        let filter_options = FindOneOptions::builder().build();
        let client = self.get_client().await?;

        client
            .database(&self.db_info.db_name)
            .collection("entries")
            .find_one(filter, filter_options)
            .await
            .map_err(|e| -> CryptoError {
                MongoStorerError::InternalError {
                    source: Box::new(e),
                }
                .into()
            })
            .and_then(|doc| match doc {
                Some(doc) => bson::from_bson(Bson::Document(doc)).map_err(|e| {
                    MongoStorerError::InternalError {
                        source: Box::new(e),
                    }
                    .into()
                }),
                None => Err(MongoStorerError::NotFound.into()),
            })
    }

    async fn list_indexed<T: StorableType>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry<T>>, CryptoError> {
        let mut filter = bson::doc! { "path": path };
        if let Some(i) = index {
            filter.insert("value", i);
        }
        let filter_options = FindOptions::builder().skip(skip).limit(page_size).build();

        let cursor = self
            .get_client()
            .await?
            .database(&self.db_info.db_name)
            .collection("entries")
            .find(filter, filter_options)
            .await
            .map_err(|e| -> CryptoError {
                MongoStorerError::InternalError {
                    source: Box::new(e),
                }
                .into()
            })?;

        Ok(cursor
            .filter_map(|doc| async move {
                match doc {
                    Ok(doc) => Some(doc),
                    Err(_) => None,
                }
            })
            .collect::<Vec<Document>>()
            .await
            .into_iter()
            .filter_map(|doc| -> Option<Entry<T>> {
                match bson::from_bson(Bson::Document(doc)) {
                    Ok(entry) => Some(entry),
                    Err(_) => None,
                }
            })
            .collect::<Vec<Entry<T>>>())
    }

    async fn create<T: StorableType>(&self, entry: Entry<T>) -> Result<bool, CryptoError> {
        let filter = bson::doc! { "path": &entry.path };
        let filter_options = mongodb::options::ReplaceOptions::builder()
            .upsert(true)
            .build();
        let doc = bson::to_document(&entry).map_err(|e| MongoStorerError::InternalError {
            source: Box::new(e),
        })?;

        match self
            .get_client()
            .await?
            .database(&self.db_info.db_name)
            .collection("entries")
            .replace_one(filter, doc.clone(), filter_options)
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => Err(MongoStorerError::InternalError {
                source: Box::new(e),
            }
            .into()),
        }
    }
}

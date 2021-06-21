use crate::{Buildable, Builder, Entry, EntryPath, States, StorageError, Storer, Unsealer};
use async_trait::async_trait;
use futures::StreamExt;
use mongodb::{
    bson,
    options::ClientOptions,
    options::{FindOneOptions, FindOptions},
    Client, Database,
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// Stores an instance of a mongodb-backed key storer
#[derive(Clone)]
pub struct MongoStorer {
    db_info: MongoDbInfo,
    client: Client,
    db: Database,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MongoDbInfo {
    url: String,
    db_name: String,
}

impl MongoStorer {
    /// Instantiates a mongo-backed key storer using a URL to the mongo cluster and the
    /// name of the DB to connect to.
    pub async fn new(url: &str, db_name: &str) -> Self {
        let db_info = MongoDbInfo {
            url: url.to_owned(),
            db_name: db_name.to_owned(),
        };
        let db_client_options = ClientOptions::parse_with_resolver_config(
            url,
            mongodb::options::ResolverConfig::cloudflare(),
        )
        .await
        .unwrap();
        let client = Client::with_options(db_client_options).unwrap();
        let db = client.database(db_name);
        MongoStorer {
            db_info,
            client,
            db,
        }
    }
}

#[async_trait]
impl Storer for MongoStorer {
    async fn get<T: Buildable>(&self, name: &str) -> Result<T, StorageError> {
        let filter = bson::doc! { "name": name };
        let filter_options = FindOneOptions::builder().build();

        match self
            .db
            .collection_with_type::<Entry>("data")
            .find_one(filter, filter_options)
            .await
        {
            Ok(Some(entry)) => match entry.value {
                States::Referenced { path: name } => Ok(self.get::<T>(&name).await?),
                States::Sealed {
                    builder,
                    unsealer: unsealable,
                } => {
                    let bytes = unsealable
                        .unseal(self.clone())
                        .await
                        .map_err(|_| StorageError::NotFound)?;
                    let builder = <T as Buildable>::Builder::try_from(builder)
                        .map_err(|_| StorageError::NotFound)?;
                    let output = builder
                        .build(bytes.as_ref())
                        .map_err(|_| StorageError::NotFound)?;
                    Ok(output)
                }
                States::Unsealed { builder, bytes } => {
                    let builder = <T as Buildable>::Builder::try_from(builder)
                        .map_err(|_| StorageError::NotFound)?;
                    let output = builder
                        .build(bytes.as_ref())
                        .map_err(|_| StorageError::NotFound)?;
                    Ok(output)
                }
            },
            Ok(None) => Err(StorageError::NotFound),
            Err(e) => Err(StorageError::InternalError {
                source: Box::new(e),
            }),
        }
    }

    async fn list<T: Buildable + Send>(
        &self,
        name: &EntryPath,
        skip: i64,
        page_size: i64,
    ) -> Result<Vec<T>, StorageError> {
        let filter_options = FindOptions::builder().skip(skip).limit(page_size).build();
        let filter = bson::doc! { "path": name };

        match self
            .db
            .collection_with_type::<Entry>("data")
            .find(filter, filter_options)
            .await
        {
            Ok(cursor) => Ok(cursor
                .filter_map(|result| async move {
                    match result {
                        Ok(entry) => match entry.value {
                            States::Referenced { path: name } => match self.get::<T>(&name).await {
                                Ok(output) => Some(output),
                                Err(_) => None,
                            },
                            States::Sealed {
                                builder,
                                unsealer: unsealable,
                            } => {
                                let bytes = match unsealable.unseal(self.clone()).await {
                                    Ok(v) => v,
                                    Err(_) => return None,
                                };
                                let builder = match <T as Buildable>::Builder::try_from(builder) {
                                    Ok(b) => b,
                                    Err(_) => return None,
                                };
                                match builder.build(bytes.as_ref()) {
                                    Ok(output) => Some(output),
                                    Err(_) => None,
                                }
                            }
                            States::Unsealed { builder, bytes } => {
                                let builder = match <T as Buildable>::Builder::try_from(builder) {
                                    Ok(b) => b,
                                    Err(_) => return None,
                                };
                                match builder.build(bytes.as_ref()) {
                                    Ok(output) => Some(output),
                                    Err(_) => None,
                                }
                            }
                        },
                        Err(_) => None,
                    }
                })
                .collect::<Vec<T>>()
                .await),
            Err(e) => Err(StorageError::InternalError {
                source: Box::new(e),
            }),
        }
    }

    async fn create(&self, name: EntryPath, value: States) -> Result<bool, StorageError> {
        let filter = bson::doc! { "name": &name };
        let entry = Entry { path: name, value };
        let filter_options = mongodb::options::ReplaceOptions::builder()
            .upsert(true)
            .build();

        match self
            .db
            .collection_with_type::<Entry>("data")
            .replace_one(filter, entry, filter_options)
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => Err(StorageError::InternalError {
                source: Box::new(e),
            }),
        }
    }
}

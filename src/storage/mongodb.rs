use crate::{Buildable, Entry, EntryPath, States, StorageError, Storer};
use async_trait::async_trait;
use futures::StreamExt;
use mongodb::{
    bson::{self, Document},
    options::ClientOptions,
    options::{FindOneOptions, FindOptions},
    Client, Database,
};
use serde::{Deserialize, Serialize};

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
    async fn get_indexed<T: Buildable>(
        &self,
        path: &str,
        index: &Document,
    ) -> Result<Entry, StorageError> {
        let filter = bson::doc! { "path": path, "value": index };
        let filter_options = FindOneOptions::builder().build();

        match self
            .db
            .collection_with_type::<Entry>("entries")
            .find_one(filter, filter_options)
            .await
        {
            Ok(Some(entry)) => Ok(entry),
            Ok(None) => Err(StorageError::NotFound),
            Err(e) => Err(StorageError::InternalError {
                source: Box::new(e),
            }),
        }
    }

    async fn list_indexed<T: Buildable + Send>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
        index: &Document,
    ) -> Result<Vec<Entry>, StorageError> {
        let filter = bson::doc! { "path": path, "value": index };
        let filter_options = FindOptions::builder().skip(skip).limit(page_size).build();

        match self
            .db
            .collection_with_type::<Entry>("entries")
            .find(filter, filter_options)
            .await
        {
            Ok(cursor) => Ok(cursor
                .filter_map(|result| async move {
                    match result {
                        Ok(entry) => Some(entry),
                        Err(_) => None,
                    }
                })
                .collect::<Vec<Entry>>()
                .await),
            Err(e) => Err(StorageError::InternalError {
                source: Box::new(e),
            }),
        }
    }

    async fn create(&self, path: EntryPath, value: States) -> Result<bool, StorageError> {
        let filter = bson::doc! { "path": &path };
        let entry = Entry { path, value };
        let filter_options = mongodb::options::ReplaceOptions::builder()
            .upsert(true)
            .build();

        println!("test");
        println!("{:?}", &entry);
        match self
            .db
            .collection_with_type::<Entry>("entries")
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

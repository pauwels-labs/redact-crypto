use crate::{Entry, KeyName, Stateful, StorageError, Storer, TypeStates, Types};
use async_trait::async_trait;
use futures::StreamExt;
use mongodb::{bson, options::ClientOptions, options::FindOneOptions, Client, Database};
use serde::Serialize;
use std::convert::TryFrom;

/// Stores an instance of a mongodb-backed key storer
#[derive(Clone)]
pub struct MongoStorer {
    url: String,
    db_name: String,
    client: Client,
    db: Database,
}

impl MongoStorer {
    /// Instantiates a mongo-backed key storer using a URL to the mongo cluster and the
    /// name of the DB to connect to.
    pub async fn new(url: &str, db_name: &str) -> Self {
        let db_client_options = ClientOptions::parse_with_resolver_config(
            url,
            mongodb::options::ResolverConfig::cloudflare(),
        )
        .await
        .unwrap();
        let client = Client::with_options(db_client_options).unwrap();
        let db = client.database(db_name);
        MongoStorer {
            url: url.to_owned(),
            db_name: db_name.to_owned(),
            client,
            db,
        }
    }
}

#[async_trait]
impl Storer for MongoStorer {
    async fn get<T: Stateful>(&self, name: &str) -> Result<TypeStates<T>, StorageError>
    where
        T: Stateful,
    {
        let filter_options = FindOneOptions::builder().build();
        let filter = bson::doc! { "name": name };

        match self
            .db
            .collection_with_type::<Entry<Types>>("keys")
            .find_one(filter, filter_options)
            .await
        {
            Ok(Some(data)) => {
                let ts = data.value;
                match ts {
                    TypeStates::Reference(rt) => Ok(TypeStates::Reference(
                        T::ReferenceType::try_from(rt).map_err(|_| StorageError::NotFound)?,
                    )),
                    TypeStates::Sealed(st) => Ok(TypeStates::Sealed(
                        T::SealedType::try_from(st).map_err(|_| StorageError::NotFound)?,
                    )),
                    TypeStates::Unsealed(t) => Ok(TypeStates::Unsealed(
                        T::UnsealedType::try_from(t).map_err(|_| StorageError::NotFound)?,
                    )),
                }
            }
            Ok(None) => Err(StorageError::NotFound),
            Err(e) => Err(StorageError::InternalError {
                source: Box::new(e),
            }),
        }
    }

    async fn list<T>(&self) -> Result<Vec<TypeStates<T>>, StorageError>
    where
        T: Stateful,
    {
        match self
            .db
            .collection_with_type::<Entry<Types>>("keys")
            .find(None, None)
            .await
        {
            Ok(cursor) => {
                let results = cursor
                    .filter_map(|entry| async move {
                        match entry {
                            Ok(e) => {
                                let ts = e.value;
                                match ts {
                                    TypeStates::Reference(rt) => T::ReferenceType::try_from(rt)
                                        .map_or_else(
                                            |_| None,
                                            |value| Some(TypeStates::Reference(value)),
                                        ),
                                    TypeStates::Sealed(st) => T::SealedType::try_from(st)
                                        .map_or_else(
                                            |_| None,
                                            |value| Some(TypeStates::Sealed(value)),
                                        ),
                                    TypeStates::Unsealed(t) => T::UnsealedType::try_from(t)
                                        .map_or_else(
                                            |_| None,
                                            |value| Some(TypeStates::Unsealed(value)),
                                        ),
                                }
                            }
                            Err(_) => None,
                        }
                    })
                    .collect::<Vec<TypeStates<T>>>()
                    .await;
                Ok(results)
            }
            Err(e) => Err(StorageError::InternalError {
                source: Box::new(e),
            }),
        }
    }

    async fn create<T>(&self, name: KeyName, value: T) -> Result<bool, StorageError>
    where
        T: Into<TypeStates<Types>> + Send + Sync + Serialize,
    {
        let filter_options = mongodb::options::ReplaceOptions::builder()
            .upsert(true)
            .build();
        let filter = bson::doc! { "name": &name };
        let value = value.into();

        match self
            .db
            .collection_with_type::<Entry<Types>>("keys")
            .replace_one(filter, Entry { name, value }, filter_options)
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => Err(StorageError::InternalError {
                source: Box::new(e),
            }),
        }
    }

    // fn with_type<T, U>(&self) -> U
    // where
    //     U: StorerWithType<T>,
    // {
    //     MongoStorerWithType {
    //         storer: self.clone(),
    //     }
    // }
}

// #[async_trait]
// impl<T> StorerWithType<T> for MongoStorerWithType {
//     async fn get(&self, name: &str) -> Result<T, StorageError>
//     where
//         T: TryFrom<Types, Error = CryptoError>,
//     {
//         self.storer.get(name).await
//     }

//     async fn list(&self) -> Result<Vec<T>, StorageError>
//     where
//         T: TryFrom<Types, Error = CryptoError> + Send,
//     {
//         self.storer.list().await
//     }

//     async fn create(&self, name: KeyName, value: T) -> Result<bool, StorageError>
//     where
//         T: Into<Types> + Send + Sync + Serialize,
//     {
//         self.create(name, value).await
//     }
// }

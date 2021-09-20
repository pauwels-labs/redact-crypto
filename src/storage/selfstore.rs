use crate::{CryptoError, Entry, NonIndexedTypeStorer, StorableType, Storer, TypeStorer};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt::Display,
    sync::{Arc, RwLock},
};

static SELF_STORER: Lazy<RwLock<Arc<SelfStorer>>> = Lazy::new(|| RwLock::new(Default::default()));

#[derive(Debug)]
pub enum SelfStorerError {
    /// No self storer was defined for use, self store operations are not supported
    NoSelfStorerProvided,
}

impl Error for SelfStorerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            SelfStorerError::NoSelfStorerProvided => None,
        }
    }
}

impl Display for SelfStorerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            SelfStorerError::NoSelfStorerProvided => write!(f, "No self storer was defined"),
        }
    }
}

impl From<SelfStorerError> for CryptoError {
    fn from(sse: SelfStorerError) -> Self {
        match sse {
            SelfStorerError::NoSelfStorerProvided => CryptoError::InternalError {
                source: Box::new(sse),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SelfStorer {
    #[serde(skip)]
    internal_storer: Option<Box<TypeStorer>>,
}

impl From<SelfStorer> for NonIndexedTypeStorer {
    fn from(ss: SelfStorer) -> Self {
        NonIndexedTypeStorer::SelfStore(ss)
    }
}

impl SelfStorer {
    pub fn current() -> Arc<SelfStorer> {
        SELF_STORER.read().unwrap().clone()
    }

    pub fn make_current(self) {
        *SELF_STORER.write().unwrap() = Arc::new(self)
    }
}

#[async_trait]
impl Storer for SelfStorer {
    async fn get<T: StorableType>(&self, path: &str) -> Result<Entry<T>, CryptoError> {
        match SelfStorer::current().internal_storer {
            Some(ref storer) => storer.get(path).await,
            None => Err(SelfStorerError::NoSelfStorerProvided.into()),
        }
    }

    async fn create<T: StorableType>(&self, value: Entry<T>) -> Result<Entry<T>, CryptoError> {
        match SelfStorer::current().internal_storer {
            Some(ref storer) => storer.create(value).await,
            None => Err(SelfStorerError::NoSelfStorerProvided.into()),
        }
    }
}

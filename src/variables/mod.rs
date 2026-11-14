//! Variable system for ModSecurity.
//!
//! This module handles variable resolution and collection management.

mod collection;
mod json;
mod request;
mod resolver;
mod response;
mod tx;

pub use collection::{Collection, HashMapCollection, MutableCollection};
pub use request::RequestData;
pub(crate) use resolver::is_excluded;
pub use resolver::VariableResolver;
pub use response::ResponseData;
pub use tx::TxCollection;

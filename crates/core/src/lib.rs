#![forbid(unsafe_code)]

mod app_info;
pub mod attributes;
pub mod http;
pub mod identity;
pub mod ilm;
pub mod inventory;
pub mod lock;
pub mod oauth;
pub mod policy;
pub mod session;
pub mod settings;
pub mod token;

pub use app_info::{AppInfo, Platform};

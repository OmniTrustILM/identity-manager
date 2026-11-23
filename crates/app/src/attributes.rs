//! The commands of the attribute forms: callbacks and checks of an open form, closing it, and the way to ILM's
//! web interface for what this application cannot show. Values come from the interface only as typed by the
//! person; everything else is resolved from the core's copy of the definitions.

use im_core::attributes::{CallbackResult, FormCheck};
use im_core::ilm::attributes::WebTarget;
use serde::Deserialize;
use tauri::{AppHandle, Runtime, State};

use crate::certificates::ilm;
use crate::session::SignIn;

/// The page of ILM's web interface the interface asks to open; the address is the core's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, rename_all = "camelCase"))]
pub enum IlmTarget {
    AddToIlm,
}

impl IlmTarget {
    pub(crate) fn web(self) -> WebTarget<'static> {
        match self {
            Self::AddToIlm => WebTarget::AddToIlm,
        }
    }
}

#[tauri::command]
pub async fn attribute_callback<R: Runtime>(
    app: AppHandle<R>,
    id: String,
    field: String,
    values: serde_json::Value,
    seq: u64,
) -> Result<CallbackResult, String> {
    let ilm = ilm(&app);
    ilm.unlocked()?;
    let result = ilm.session().run_callback(&id, &field, &values, seq).await;
    ilm.unlocked()?;
    result.map_err(|error| error.to_string())
}

#[tauri::command]
pub fn check_attributes<R: Runtime>(
    app: AppHandle<R>,
    id: String,
    values: serde_json::Value,
) -> Result<FormCheck, String> {
    let ilm = ilm(&app);
    ilm.unlocked()?;
    ilm.session()
        .check_form(&id, &values)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn close_form<R: Runtime>(app: AppHandle<R>, id: String) -> Result<(), String> {
    let ilm = ilm(&app);
    ilm.unlocked()?;
    ilm.session().close_form(&id);
    Ok(())
}

#[tauri::command]
pub fn open_in_ilm(sign_in: State<'_, SignIn>, target: IlmTarget) -> Result<(), String> {
    sign_in.open_in_ilm(&target.web())
}

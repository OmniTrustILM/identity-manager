//! The forms ILM's attributes make: the core keeps the definitions of every open form and runs their callbacks, so
//! the interface only names a form, a field and the values the person gave.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use jiff::tz::TimeZone;
use serde_json::Value as Json;

use super::{CallError, Session, lock};
use crate::attributes::{
    CallbackResult, Definition, Definitions, FormCheck, FormContext, FormView, Resolution, Stamps,
    Value, Values, check, cleared_with, default_of, group_views, parse_values,
    required_unsupported, resolve,
};
use crate::ilm::attributes::{
    CallbackAnswer, CallbackError, WebTarget, callback_request, custom_attributes_request,
    issue_attributes_request, read_callback, read_custom_attributes, read_issue_attributes,
    web_url,
};
use crate::ilm::profile::IlmError;

/// How many forms stay open; the oldest makes room.
const MAX_FORMS: usize = 8;
const NOT_ALLOWED: &str = "ILM does not allow this.";
const NO_ANSWER: &str = "ILM did not answer.";

/// Why a form could not be opened or used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormError {
    SignedOut,
    Offline,
    Unexpected(u16),
    Malformed,
    /// The form is not open any more: it was closed, or the application locked or signed out meanwhile.
    Gone,
    /// The values are not of the kinds the form asks for.
    BadValues,
}

impl std::fmt::Display for FormError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignedOut => CallError::SignedOut.fmt(f),
            Self::Offline => f.write_str("ILM cannot be reached."),
            Self::Unexpected(status) => write!(f, "ILM answered with an error ({status})."),
            Self::Malformed => {
                f.write_str("ILM answered in a way this application does not understand.")
            }
            Self::Gone => {
                f.write_str("This form is not open any more. Close it and open it again.")
            }
            Self::BadValues => f.write_str("The values of this form cannot be read."),
        }
    }
}

impl std::error::Error for FormError {}

impl From<CallError> for FormError {
    fn from(error: CallError) -> Self {
        match error {
            CallError::SignedOut => Self::SignedOut,
            CallError::Unreachable | CallError::Withdrawn => Self::Offline,
        }
    }
}

impl From<super::ChangeError> for FormError {
    fn from(_: super::ChangeError) -> Self {
        Self::SignedOut
    }
}

impl From<IlmError> for FormError {
    fn from(error: IlmError) -> Self {
        match error {
            IlmError::Unauthorized => Self::SignedOut,
            IlmError::Unreachable => Self::Offline,
            IlmError::Unexpected(status) => Self::Unexpected(status),
            IlmError::Malformed => Self::Malformed,
        }
    }
}

/// How a committed change touches a field's stamp.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    /// Its options or content changed.
    Changed,
    /// ILM set or cleared its value.
    ValueSet,
    /// ILM set or cleared its value again, to what it was: the interface takes it anew, nothing depends on it.
    Restamp,
    /// What it depends on cleared it, or its group replaced or installed it.
    Reset,
}

/// An open form: what ILM defined, what callbacks added, when each field last changed, and the newest callback run
/// per field. Never values.
struct Form {
    id: String,
    context: FormContext,
    web: Option<String>,
    base: Definitions,
    /// The fields each group attribute's callback added, by group name.
    added: Vec<(String, Definitions)>,
    stamps: Stamps,
    latest: HashMap<String, u64>,
    /// Per field, the newest run a clear has invalidated: that run and every older one are dropped.
    fenced: HashMap<String, u64>,
    /// Advances with every change of the form, so the interface can tell which of two snapshots is the newer.
    revision: u64,
}

impl Form {
    fn new(id: String, context: FormContext, web: Option<String>, base: Definitions) -> Self {
        Self {
            id,
            context,
            web,
            base,
            added: Vec::new(),
            stamps: Stamps::new(),
            latest: HashMap::new(),
            fenced: HashMap::new(),
            revision: 0,
        }
    }

    fn definitions(&self) -> Definitions {
        let mut all = self.base.clone();
        for (_, more) in &self.added {
            all.fields.extend(more.fields.iter().cloned());
            all.groups.extend(more.groups.iter().cloned());
            all.unsupported.extend(more.unsupported.iter().cloned());
        }
        all
    }

    /// Everything the interface draws the form from, as of now.
    fn view(&self) -> FormView {
        let definitions = self.definitions();
        let mut blockers = required_unsupported(&definitions);
        blockers.extend(definitions.unshowable());
        FormView {
            id: self.id.clone(),
            revision: self.revision,
            groups: group_views(&self.base, &self.added, &self.stamps),
            unsupported: blockers,
            web: self.web.clone(),
        }
    }

    fn result(&self, seq: u64, field: &str, problem: Option<&str>) -> CallbackResult {
        CallbackResult {
            seq,
            field: field.to_owned(),
            form: self.view(),
            problem: problem.map(str::to_owned),
        }
    }

    fn field_mut(&mut self, name: &str) -> Option<&mut Definition> {
        let added = self
            .added
            .iter_mut()
            .flat_map(|(_, more)| more.fields.iter_mut());
        self.base
            .fields
            .iter_mut()
            .chain(added)
            .find(|field| field.name == name)
    }

    fn is_group(&self, name: &str) -> bool {
        self.definitions()
            .groups
            .iter()
            .any(|group| group.name == name)
    }

    /// Whether a run of `field` numbered `seq` is still the newest, and no clear has invalidated it.
    fn is_current(&self, field: &str, seq: u64) -> bool {
        seq >= self.latest.get(field).copied().unwrap_or(0)
            && seq > self.fenced.get(field).copied().unwrap_or(0)
    }

    /// `names` and everything that goes with them: the fields a group among them added, and every dependant, in
    /// turn.
    fn closure(&self, names: Vec<String>) -> Vec<String> {
        let definitions = self.definitions();
        let mut all = names;
        let mut index = 0;
        while let Some(name) = all.get(index).cloned() {
            let owned = self
                .added
                .iter()
                .filter(|(group, _)| *group == name)
                .flat_map(|(_, more)| {
                    let groups = more.groups.iter().map(|group| &group.name);
                    more.fields.iter().map(|field| &field.name).chain(groups)
                })
                .cloned();
            let dependants = cleared_with(&definitions, &name);
            for next in owned.chain(dependants) {
                if !all.contains(&next) {
                    all.push(next);
                }
            }
            index += 1;
        }
        all
    }

    /// The one way the form changes: when `changes` names fields, the revision rises and each field is stamped with
    /// it, as the moment ILM set or cleared its value (with that value) or the field was reset, as the mark says.
    /// Returns whether anything changed.
    fn commit(&mut self, changes: Vec<(String, Mark)>) -> bool {
        if changes.is_empty() {
            return false;
        }
        self.revision += 1;
        for (name, mark) in changes {
            let value = self.field_mut(&name).and_then(|field| default_of(field));
            let stamp = self.stamps.entry(name).or_default();
            if mark != Mark::Restamp {
                stamp.changed_at = self.revision;
            }
            if mark != Mark::Changed {
                stamp.value_set_at = self.revision;
                stamp.value = value;
            }
            if mark == Mark::Reset {
                stamp.reset_at = self.revision;
            }
        }
        true
    }

    /// Empties `all`, drops their outstanding runs (all but `current`, the run being applied) and removes the fields
    /// the groups among them added. Returns what changed.
    fn invalidate(
        &mut self,
        all: &[String],
        current: &str,
        typed: &dyn Fn(&str, Option<&Value>) -> bool,
    ) -> Vec<(String, Mark)> {
        let mut changes = Vec::new();
        for name in all {
            // The run being applied is not reset by its own clear, or it would start again.
            let mark = if name == current {
                Mark::ValueSet
            } else {
                Mark::Reset
            };
            if let Some(field) = self.field_mut(name) {
                // What the person typed into the field goes with its content; what the clear leaves is no edit.
                let had_content = !field.content.is_empty();
                field.content.clear();
                let reset = default_of(field);
                let had = had_content || (field.is_editable() && typed(name, reset.as_ref()));
                if had {
                    changes.push((name.clone(), mark));
                }
            }
            if self.added.iter().any(|(group, _)| group == name) {
                changes.push((name.clone(), mark));
            }
            if name != current {
                let newest = self.latest.get(name).copied().unwrap_or(0);
                self.fenced.insert(name.clone(), newest);
            }
        }
        self.added.retain(|(group, _)| !all.contains(group));
        changes
    }

    /// Clears what run `seq` of `field` lost, with everything that goes with it, unless that run has been
    /// superseded; the check and the clear are one step, so a newer run or a fence cannot slip in between.
    fn clear_current(&mut self, field: &str, seq: u64, lost: Vec<String>, given: &Values) -> bool {
        if !self.is_current(field, seq) {
            return false;
        }
        let all = self.closure(lost);
        let typed = |name: &str, reset: Option<&Value>| {
            given
                .get(name)
                .is_some_and(|value| !value.is_empty() && Some(value) != reset)
        };
        let changes = self.invalidate(&all, field, &typed);
        self.commit(changes);
        true
    }

    /// Applies an answer to the callback of `field`; false when the answer does not fit the attribute. An empty
    /// answer is read by what owns the callback: no fields for a group, no options for a field.
    fn apply(&mut self, field: &str, answer: CallbackAnswer) -> bool {
        match answer {
            CallbackAnswer::Content(items) if items.is_empty() && self.is_group(field) => {
                self.replace_fields(field, Definitions::default());
                true
            }
            CallbackAnswer::Content(items) => self.set_content(field, items),
            CallbackAnswer::Definitions(items) if self.is_group(field) => {
                self.replace_fields(field, Definitions::read(&items));
                true
            }
            CallbackAnswer::Definitions(_) => false,
        }
    }

    /// Makes `items` the options or content of `field`. ILM sets the value of a field unless it is a list the person
    /// chooses from, where the choice is theirs.
    fn set_content(&mut self, field: &str, items: Vec<Json>) -> bool {
        let Some(definition) = self.field_mut(field) else {
            return false;
        };
        let changed = definition.content != items || !definition.answered;
        definition.content = items;
        definition.answered = true;
        let value_set =
            !definition.is_list() || definition.read_only || default_of(definition).is_some();
        if value_set || changed {
            let mark = match (value_set, changed) {
                (true, true) => Mark::ValueSet,
                (true, false) => Mark::Restamp,
                (false, _) => Mark::Changed,
            };
            self.commit(vec![(field.to_owned(), mark)]);
        }
        true
    }

    /// Makes `more` the fields the group `group` added, in place of what it added before. The old fields and the
    /// new names are cleared like a group's children, with everything that depends on them; the new fields start
    /// with the values ILM defined.
    fn replace_fields(&mut self, group: &str, more: Definitions) {
        let old = self.added.iter().find(|(added, _)| added == group);
        if old.map_or(more.is_empty(), |(_, old)| *old == more) {
            return;
        }
        let names = |definitions: &Definitions| -> Vec<String> {
            let groups = definitions.groups.iter().map(|group| &group.name);
            let fields = definitions.fields.iter().map(|field| &field.name);
            fields.chain(groups).cloned().collect()
        };
        let mut seeds = old.map(|(_, old)| names(old)).unwrap_or_default();
        let installed = names(&more);
        for name in &installed {
            if !seeds.contains(name) {
                seeds.push(name.clone());
            }
        }
        let all = self.closure(seeds);
        let mut changes = self.invalidate(&all, group, &|_, _| true);
        self.added.retain(|(added, _)| added != group);
        self.added.push((group.to_owned(), more));
        changes.push((group.to_owned(), Mark::Changed));
        changes.extend(installed.into_iter().map(|name| (name, Mark::Reset)));
        self.commit(changes);
    }
}

/// The forms open now, the oldest first.
#[derive(Default)]
pub(super) struct Forms {
    open: Mutex<Vec<Form>>,
    /// Advances whenever every form is closed, so an opening that began before cannot register its form.
    generation: AtomicU64,
}

impl Forms {
    pub(super) fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Registers the form unless every form was closed since `generation` was read; whether it was.
    fn add(&self, form: Form, generation: u64) -> bool {
        let mut open = lock(&self.open);
        if self.generation() != generation {
            return false;
        }
        open.push(form);
        if open.len() > MAX_FORMS {
            open.remove(0);
        }
        true
    }

    fn with<T>(&self, id: &str, work: impl FnOnce(&mut Form) -> T) -> Result<T, FormError> {
        let mut open = lock(&self.open);
        let form = open
            .iter_mut()
            .find(|form| form.id == id)
            .ok_or(FormError::Gone)?;
        Ok(work(form))
    }

    pub(super) fn clear(&self) {
        let mut open = lock(&self.open);
        self.generation.fetch_add(1, Ordering::SeqCst);
        open.clear();
    }
}

#[cfg(test)]
mod form_tests;

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the system provides random bytes");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Session {
    /// Reads the definitions of `context` as the person and opens a form for them. None when the person may not
    /// read them, or ILM does not have them (403, 404).
    pub async fn open_form(&self, context: FormContext) -> Result<Option<FormView>, FormError> {
        self.open_form_since(context, self.forms.generation()).await
    }

    /// Like `open_form`, for an operation that began when forms had `generation`: the form is not registered when
    /// every form was closed since.
    pub(super) async fn open_form_since(
        &self,
        context: FormContext,
        generation: u64,
    ) -> Result<Option<FormView>, FormError> {
        let id = self.departing()?.id;
        let who = self.signed_in_as().ok_or(FormError::SignedOut)?;
        let raw = match &context {
            FormContext::Custom => {
                let response = self
                    .call_ilm_as(Some(&id), None, custom_attributes_request)
                    .await?;
                match read_custom_attributes(response).await? {
                    Some(raw) => raw,
                    None => return Ok(None),
                }
            }
            FormContext::Issue {
                authority,
                ra_profile,
            } => {
                let response = self
                    .call_ilm_as(Some(&id), None, |client, ilm| {
                        issue_attributes_request(client, ilm, authority, ra_profile)
                    })
                    .await?;
                read_issue_attributes(response).await?
            }
        };
        let definitions = Definitions::read(&raw);
        for unsupported in &definitions.unsupported {
            log::warn!("the attribute {} cannot be shown", unsupported.name);
        }
        let form_id = random_id();
        let target = match &context {
            FormContext::Custom => WebTarget::AddToIlm,
            FormContext::Issue {
                authority,
                ra_profile,
            } => WebTarget::RaProfile {
                authority,
                ra_profile,
            },
        };
        let web = Some(web_url(&who.ilm, &target));
        log::info!(
            "a form of {} was opened: {} fields, {} that cannot be shown",
            context.kind(),
            definitions.fields.len(),
            definitions.unsupported.len()
        );
        if !self.is_sign_in(&id) {
            return Err(FormError::SignedOut);
        }
        let form = Form::new(form_id, context, web, definitions);
        let view = form.view();
        if !self.forms.add(form, generation) {
            return Err(FormError::Gone);
        }
        Ok(Some(view))
    }

    /// Runs the callback of `field` (a field or a group attribute) of form `form`, resolved from the core's own copy
    /// of the definitions and the values given. `seq` numbers the runs per field: an answer a newer run has replaced
    /// changes nothing. Returns the form as it is afterwards.
    pub async fn run_callback(
        &self,
        form: &str,
        field: &str,
        values: &Json,
        seq: u64,
    ) -> Result<CallbackResult, FormError> {
        let id = self.departing()?.id;
        let started = self.forms.with(form, |open| {
            if !open.is_current(field, seq) {
                return None;
            }
            open.latest.insert(field.to_owned(), seq);
            Some((open.context.clone(), open.definitions()))
        })?;
        let Some((context, definitions)) = started else {
            return self.settled(form, field, seq, None);
        };
        let parsed = parse_values(&definitions.fields, values).map_err(|_| FormError::BadValues)?;
        match resolve(&context, &definitions, field, &parsed) {
            Resolution::Skip => self.settled(form, field, seq, None),
            Resolution::Cleared => {
                let lost = cleared_with(&definitions, field);
                self.forms.with(form, |open| {
                    if open.clear_current(field, seq, lost, &parsed) {
                        log::info!("callback run for {field}: cleared, no dependency value");
                    } else {
                        log::info!("callback run for {field}: replaced by a newer run");
                    }
                    open.result(seq, field, None)
                })
            }
            Resolution::Call(route, body) => {
                let response = match self
                    .call_ilm_as(Some(&id), None, |client, ilm| {
                        callback_request(client, ilm, &route, &body)
                    })
                    .await
                {
                    Ok(response) => response,
                    Err(CallError::SignedOut) => return Err(FormError::SignedOut),
                    Err(_) => {
                        log::info!("callback run for {field}: no answer");
                        return self.settled(form, field, seq, Some(NO_ANSWER));
                    }
                };
                let status = response.status().as_u16();
                let answer = match read_callback(response).await {
                    Ok(answer) => answer,
                    Err(CallbackError::NotAllowed) => {
                        log::info!("callback run for {field}: not allowed ({status})");
                        return self.settled(form, field, seq, Some(NOT_ALLOWED));
                    }
                    Err(CallbackError::Failed(_)) => {
                        log::info!("callback run for {field}: failed ({status})");
                        return self.settled(form, field, seq, Some(NO_ANSWER));
                    }
                };
                self.forms.with(form, |open| {
                    if !open.is_current(field, seq) {
                        log::info!("callback run for {field}: replaced by a newer run");
                        return open.result(seq, field, None);
                    }
                    if open.apply(field, answer) {
                        log::info!("callback run for {field}: answered ({status})");
                        open.result(seq, field, None)
                    } else {
                        log::warn!(
                            "callback run for {field}: an answer that does not fit ({status})"
                        );
                        open.result(seq, field, Some(NO_ANSWER))
                    }
                })
            }
        }
    }

    /// The result of a run that changed nothing: the form as it is.
    fn settled(
        &self,
        form: &str,
        field: &str,
        seq: u64,
        problem: Option<&str>,
    ) -> Result<CallbackResult, FormError> {
        self.forms
            .with(form, |open| open.result(seq, field, problem))
    }

    /// The problem of every field of the form that has one, for the values the person has given, and the revision of
    /// the form they were checked against.
    pub fn check_form(&self, form: &str, values: &Json) -> Result<FormCheck, FormError> {
        let (revision, definitions) = self
            .forms
            .with(form, |open| (open.revision, open.definitions()))?;
        let parsed = parse_values(&definitions.fields, values).map_err(|_| FormError::BadValues)?;
        Ok(FormCheck {
            revision,
            problems: check(&definitions.fields, &parsed, &TimeZone::system()),
        })
    }

    /// The definitions of the open form, which stays open.
    pub(super) fn form_definitions(&self, form: &str) -> Result<Definitions, FormError> {
        self.forms.with(form, |open| open.definitions())
    }

    /// Closes the form; one that is not open is no error.
    pub fn close_form(&self, form: &str) {
        lock(&self.forms.open).retain(|open| open.id != form);
    }

    /// Closes the form and gives out what the core knows of it.
    #[cfg(test)]
    pub(crate) fn take_form(&self, form: &str) -> Option<(FormContext, Definitions)> {
        let mut open = lock(&self.forms.open);
        let at = open.iter().position(|open| open.id == form)?;
        let taken = open.remove(at);
        let definitions = taken.definitions();
        Some((taken.context, definitions))
    }

    /// Closes the form and gives out its definitions, for the request that sends it, when `verify` accepts them.
    /// Verifying and closing happen under one lock, so no callback can change the form in between; when `verify`
    /// refuses, or the form is not open (`gone`), the form stays as it is.
    pub(crate) fn take_form_if<T, E>(
        &self,
        form: &str,
        gone: E,
        verify: impl FnOnce(&Definitions) -> Result<T, E>,
    ) -> Result<(Definitions, T), E> {
        let mut open = lock(&self.forms.open);
        let at = open.iter().position(|open| open.id == form).ok_or(gone)?;
        let definitions = open[at].definitions();
        let verified = verify(&definitions)?;
        open.remove(at);
        Ok((definitions, verified))
    }

    /// Closes every form, as when the application locks.
    pub fn close_forms(&self) {
        self.forms.clear();
    }
}

//! Cursor-paged reads: every page of a list, in order, from the first page (no cursor) to the one
//! whose `next_cursor` is `null`. A [`Pager`] keeps a read bounded: it stops with
//! [`Error::Paging`] after `max_pages` pages (`too_many_pages`), on a cursor the platform handed
//! out before (`cursor_repeated`, the list would not end) and on an answer that is not a page
//! (`malformed_page`), so a caller that acts on what a whole list leaves out (a membership resync
//! removing people) never acts on part of one.

use std::collections::HashSet;

use serde_json::Value;

use super::error::Error;

/// The most pages a paged read takes unless told otherwise (100,000 items at 100 a page).
pub const DEFAULT_MAX_PAGES: usize = 1000;

/// The largest page the platform's cursor-paged lists answer.
pub const MAX_PAGE_SIZE: u32 = 100;

/// The state of one cursor-paged read.
///
/// ```
/// # use ever_connect_sdk::client::{Error, Pager};
/// # use serde_json::json;
/// # fn main() -> Result<(), Error> {
/// let mut pager = Pager::new(10);
/// let mut cursor: Option<String> = None;
/// let mut items = Vec::new();
/// loop {
///     pager.before_page()?;
///     // Read the page after `cursor` here; two pages stand in for the platform's answers.
///     let page = match cursor.as_deref() {
///         None => json!({"items": [1, 2], "next_cursor": "c1"}),
///         Some(_) => json!({"items": [3], "next_cursor": null}),
///     };
///     let (page_items, next) = pager.accept(page)?;
///     items.extend(page_items);
///     match next {
///         Some(next) => cursor = Some(next),
///         None => break,
///     }
/// }
/// assert_eq!(items, vec![json!(1), json!(2), json!(3)]);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Pager {
    max_pages: usize,
    pages: usize,
    seen: HashSet<String>,
}

impl Pager {
    /// A read of at most `max_pages` pages (0 reads none).
    #[must_use]
    pub fn new(max_pages: usize) -> Self {
        Self {
            max_pages,
            pages: 0,
            seen: HashSet::new(),
        }
    }

    /// The pages accepted so far.
    #[must_use]
    pub const fn pages(&self) -> usize {
        self.pages
    }

    /// Call before reading a page.
    ///
    /// # Errors
    /// [`Error::Paging`] `too_many_pages` once `max_pages` pages were read.
    pub fn before_page(&self) -> Result<(), Error> {
        if self.pages >= self.max_pages {
            return Err(Error::Paging {
                code: "too_many_pages",
                pages: self.pages,
            });
        }
        Ok(())
    }

    /// Takes one page: its items, and the cursor of the next page (`None` on the last page; an
    /// empty `next_cursor` ends the list like `null`).
    ///
    /// # Errors
    /// [`Error::Paging`]: `malformed_page` for an answer without an `items` list or with a
    /// `next_cursor` that is not a string or `null`; `cursor_repeated` for a cursor handed out
    /// before.
    pub fn accept(&mut self, page: Value) -> Result<(Vec<Value>, Option<String>), Error> {
        self.pages += 1;
        let malformed = Error::Paging {
            code: "malformed_page",
            pages: self.pages,
        };
        let Value::Object(mut page) = page else {
            return Err(malformed);
        };
        let next = match page.remove("next_cursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.is_empty() => None,
            Some(Value::String(s)) => Some(s),
            Some(_) => return Err(malformed),
        };
        let Some(Value::Array(items)) = page.remove("items") else {
            return Err(malformed);
        };
        if let Some(next) = &next
            && !self.seen.insert(next.clone())
        {
            return Err(Error::Paging {
                code: "cursor_repeated",
                pages: self.pages,
            });
        }
        Ok((items, next))
    }
}

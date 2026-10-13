//! Inert HTML script and base-href extraction (REA `htmlArtifactReferences.ts`, which uses
//! parse5).
//!
//! The document is parsed with html5ever's spec tree builder (scripting enabled, as parse5's
//! default), so template contents, foreign (SVG/MathML) content, raw-text elements, comments and
//! duplicate attributes behave as in parse5. parse5 also reports the exact source range of every
//! start tag; html5ever does not, so the text is fed in chunks that end at every `>`, which pins
//! the end offset of the tag being created, and the start offset is found by validating
//! candidate `<` positions backwards from that end.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use html5ever::driver::ParseOpts;
use html5ever::tendril::{StrTendril, TendrilSink};
use html5ever::tree_builder::{ElementFlags, NodeOrText, QuirksMode, TreeBuilderOpts, TreeSink};
use html5ever::{local_name, ns, parse_document, Attribute, ExpandedName, QualName};
use markup5ever_rcdom::{Handle, NodeData, RcDom};

/// One `<script src>` start tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtmlScriptReference {
    pub script_path: String,
    /// UTF-16 offsets of the opening tag, as parse5 reports them.
    pub start_offset: usize,
    pub end_offset: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HtmlReferences {
    pub base_href: Option<String>,
    pub scripts: Vec<HtmlScriptReference>,
}

/// Records the end offset (bytes) at which each `script` element was created.
struct Recorder {
    dom: RcDom,
    fed_bytes: Rc<Cell<usize>>,
    created: Rc<RefCell<Vec<(Handle, usize)>>>,
}

impl TreeSink for Recorder {
    type Handle = Handle;
    type Output = RcDom;
    type ElemName<'a> = ExpandedName<'a>;

    fn finish(self) -> RcDom {
        self.dom
    }

    fn parse_error(&self, msg: Cow<'static, str>) {
        self.dom.parse_error(msg)
    }

    fn get_document(&self) -> Handle {
        self.dom.get_document()
    }

    fn elem_name<'a>(&'a self, target: &'a Handle) -> ExpandedName<'a> {
        match &target.data {
            NodeData::Element { name, .. } => name.expanded(),
            _ => panic!("not an element"),
        }
    }

    fn create_element(&self, name: QualName, attrs: Vec<Attribute>, flags: ElementFlags) -> Handle {
        let is_script = name.ns == ns!(html) && name.local == local_name!("script");
        let is_base = name.ns == ns!(html) && name.local == local_name!("base");
        let handle = self.dom.create_element(name, attrs, flags);
        if is_script || is_base {
            self.created.borrow_mut().push((handle.clone(), self.fed_bytes.get()));
        }
        handle
    }

    fn create_comment(&self, text: StrTendril) -> Handle {
        self.dom.create_comment(text)
    }

    fn create_pi(&self, target: StrTendril, data: StrTendril) -> Handle {
        self.dom.create_pi(target, data)
    }

    fn append(&self, parent: &Handle, child: NodeOrText<Handle>) {
        self.dom.append(parent, child)
    }

    fn append_based_on_parent_node(&self, element: &Handle, prev_element: &Handle, child: NodeOrText<Handle>) {
        self.dom.append_based_on_parent_node(element, prev_element, child)
    }

    fn append_doctype_to_document(&self, name: StrTendril, public_id: StrTendril, system_id: StrTendril) {
        self.dom.append_doctype_to_document(name, public_id, system_id)
    }

    fn mark_script_already_started(&self, node: &Handle) {
        self.dom.mark_script_already_started(node)
    }

    fn pop(&self, node: &Handle) {
        self.dom.pop(node)
    }

    fn get_template_contents(&self, target: &Handle) -> Handle {
        self.dom.get_template_contents(target)
    }

    fn same_node(&self, x: &Handle, y: &Handle) -> bool {
        self.dom.same_node(x, y)
    }

    fn set_quirks_mode(&self, mode: QuirksMode) {
        self.dom.set_quirks_mode(mode)
    }

    fn append_before_sibling(&self, sibling: &Handle, new_node: NodeOrText<Handle>) {
        self.dom.append_before_sibling(sibling, new_node)
    }

    fn add_attrs_if_missing(&self, target: &Handle, attrs: Vec<Attribute>) {
        self.dom.add_attrs_if_missing(target, attrs)
    }

    fn associate_with_form(&self, target: &Handle, form: &Handle, nodes: (&Handle, Option<&Handle>)) {
        self.dom.associate_with_form(target, form, nodes)
    }

    fn remove_from_parent(&self, target: &Handle) {
        self.dom.remove_from_parent(target)
    }

    fn reparent_children(&self, node: &Handle, new_parent: &Handle) {
        self.dom.reparent_children(node, new_parent)
    }

    fn is_mathml_annotation_xml_integration_point(&self, handle: &Handle) -> bool {
        self.dom.is_mathml_annotation_xml_integration_point(handle)
    }

    fn set_current_line(&self, line_number: u64) {
        self.dom.set_current_line(line_number)
    }

    fn allow_declarative_shadow_roots(&self, intended_parent: &Handle) -> bool {
        self.dom.allow_declarative_shadow_roots(intended_parent)
    }

    fn attach_declarative_shadow(&self, location: &Handle, template: &Handle, attrs: &[Attribute]) -> bool {
        self.dom.attach_declarative_shadow(location, template, attrs)
    }

    fn maybe_clone_an_option_into_selectedcontent(&self, option: &Handle) {
        self.dom.maybe_clone_an_option_into_selectedcontent(option)
    }
}

/// Extract inert HTML script references and the first document base href.
pub fn html_artifact_references(text: &str) -> HtmlReferences {
    let fed_bytes = Rc::new(Cell::new(0usize));
    let created: Rc<RefCell<Vec<(Handle, usize)>>> = Rc::new(RefCell::new(Vec::new()));
    let sink = Recorder { dom: RcDom::default(), fed_bytes: fed_bytes.clone(), created: created.clone() };
    let mut parser = parse_document(
        sink,
        ParseOpts {
            tree_builder: TreeBuilderOpts { scripting_enabled: true, ..TreeBuilderOpts::default() },
            ..ParseOpts::default()
        },
    );
    let mut start = 0usize;
    while start < text.len() {
        let end = match text[start..].find('>') {
            Some(index) => start + index + 1,
            None => text.len(),
        };
        fed_bytes.set(end);
        parser.process(StrTendril::from_slice(&text[start..end]));
        start = end;
    }
    let dom = parser.finish();

    // Source ranges of the start tags that created `script` elements.
    let mut tag_ranges: Vec<(Handle, usize, usize)> = Vec::new();
    for (handle, end) in created.borrow().iter() {
        if let Some(begin) = find_start_tag(text, *end) {
            tag_ranges.push((handle.clone(), begin, *end));
        }
    }

    let utf16_of = Utf16Offsets::new(text);
    let mut base_href: Option<String> = None;
    let mut scripts = Vec::new();
    let mut pending: Vec<Handle> = vec![dom.document.clone()];
    while let Some(node) = pending.pop() {
        if let NodeData::Element { name, attrs, .. } = &node.data {
            if name.ns == ns!(html) {
                let attrs = attrs.borrow();
                if name.local == local_name!("base") && base_href.is_none() {
                    if let Some(href) = attrs.iter().find(|a| a.name.local.as_ref() == "href") {
                        base_href = Some(href.value.to_string());
                    }
                }
                if name.local == local_name!("script") {
                    if let Some(src) = attrs.iter().find(|a| a.name.local.as_ref() == "src") {
                        let location = tag_ranges.iter().find(|(h, _, _)| Rc::ptr_eq(h, &node));
                        if let (false, Some((_, begin, end))) = (src.value.is_empty(), location) {
                            scripts.push(HtmlScriptReference {
                                script_path: src.value.to_string(),
                                start_offset: utf16_of.offset(*begin),
                                end_offset: utf16_of.offset(*end),
                            });
                        }
                    }
                }
            }
        }
        // Template content lives outside `children`, so it is never visited (as in parse5).
        for child in node.children.borrow().iter().rev() {
            pending.push(child.clone());
        }
    }
    HtmlReferences { base_href, scripts }
}

/// Byte offset -> UTF-16 offset.
struct Utf16Offsets<'a> {
    text: &'a str,
    ascii: bool,
}

impl<'a> Utf16Offsets<'a> {
    fn new(text: &'a str) -> Self {
        Utf16Offsets { text, ascii: text.is_ascii() }
    }

    fn offset(&self, byte: usize) -> usize {
        if self.ascii {
            byte
        } else {
            self.text[..byte].encode_utf16().count()
        }
    }
}

/// Find the `<` that opens the start tag ending exactly at `end` (bytes, exclusive).
fn find_start_tag(text: &str, end: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if end == 0 || bytes.get(end - 1) != Some(&b'>') {
        return None;
    }
    let mut search_end = end;
    let mut attempts = 0;
    while let Some(index) = text[..search_end].rfind('<') {
        attempts += 1;
        if attempts > 100_000 {
            return None;
        }
        if scan_start_tag(bytes, index) == Some(end) {
            return Some(index);
        }
        search_end = index;
    }
    None
}

/// Tokenize one start tag (`<` + ASCII letter) per the HTML tokenizer and return its end.
fn scan_start_tag(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    if !bytes.get(i)?.is_ascii_alphabetic() {
        return None;
    }
    let is_space = |b: u8| matches!(b, b'\t' | b'\n' | 0x0c | b' ' | b'\r');
    while i < bytes.len() && !is_space(bytes[i]) && bytes[i] != b'/' && bytes[i] != b'>' {
        i += 1;
    }
    loop {
        // before attribute name
        while i < bytes.len() && is_space(bytes[i]) {
            i += 1;
        }
        match bytes.get(i)? {
            b'>' => return Some(i + 1),
            b'/' => {
                i += 1;
                if bytes.get(i) == Some(&b'>') {
                    return Some(i + 1);
                }
                continue;
            }
            _ => {}
        }
        // attribute name (a leading `=` belongs to the name)
        i += 1;
        while i < bytes.len() && !is_space(bytes[i]) && !matches!(bytes[i], b'/' | b'>' | b'=') {
            i += 1;
        }
        // after attribute name
        while i < bytes.len() && is_space(bytes[i]) {
            i += 1;
        }
        match bytes.get(i)? {
            b'/' => continue,
            b'>' => return Some(i + 1),
            b'=' => {
                i += 1;
                while i < bytes.len() && is_space(bytes[i]) {
                    i += 1;
                }
                match bytes.get(i)? {
                    quote @ (b'"' | b'\'') => {
                        let quote = *quote;
                        i += 1;
                        while *bytes.get(i)? != quote {
                            i += 1;
                        }
                        i += 1;
                    }
                    b'>' => return Some(i + 1),
                    _ => {
                        while i < bytes.len() && !is_space(bytes[i]) && bytes[i] != b'>' {
                            i += 1;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scripts(text: &str) -> Vec<String> {
        html_artifact_references(text).scripts.into_iter().map(|s| s.script_path).collect()
    }

    #[test]
    fn script_extraction_matches_the_rea_cases() {
        assert!(scripts(r#"<script data-src="decoy.js"></script>"#).is_empty());
        assert_eq!(scripts("<script src=actual.js></script>"), ["actual.js"]);
        assert_eq!(scripts(r#"<script title=">" src="actual.js"></script>"#), ["actual.js"]);
        assert_eq!(scripts(r#"<SCRIPT SRC="actual.js"></SCRIPT>"#), ["actual.js"]);
        assert_eq!(scripts(r#"<script src="actual.js" src="decoy.js"></script>"#), ["actual.js"]);
        assert!(scripts(r#"<script src="" src="decoy.js"></script>"#).is_empty());
        assert_eq!(scripts(r#"<script src="actual&#46;js"></script>"#), ["actual.js"]);
        assert!(scripts(r#"<!-- <script src="decoy.js"></script> -->"#).is_empty());
        assert!(scripts(r#"<textarea><script src="decoy.js"></script></textarea>"#).is_empty());
        assert!(scripts(r#"<style><script src="decoy.js"></script></style>"#).is_empty());
        assert!(scripts(r#"<script>const text = '<script src="decoy.js">';</script>"#).is_empty());
        assert!(scripts(r#"<template><base href="decoy/"><script src="decoy.js"></script></template>"#).is_empty());
        assert!(scripts(r#"<svg><script src="decoy.js"></script></svg>"#).is_empty());
        assert_eq!(
            scripts(r#"<svg><foreignObject><script src="actual.js"></script></foreignObject></svg>"#),
            ["actual.js"]
        );
    }

    #[test]
    fn offsets_cover_the_opening_tag_only() {
        let opening = "<script\n title=\">\" src=actual.js>";
        let prefix = "<!doctype html>\n\n";
        let text = format!("{prefix}{opening}ignored body</script>");
        let found = html_artifact_references(&text);
        assert_eq!(found.base_href, None);
        assert_eq!(
            found.scripts,
            vec![HtmlScriptReference {
                script_path: "actual.js".into(),
                start_offset: prefix.len(),
                end_offset: prefix.len() + opening.len(),
            }]
        );
    }

    #[test]
    fn base_href_is_the_first_real_one() {
        let href = |text: &str| html_artifact_references(text).base_href;
        assert_eq!(href(r#"<base data-href="decoy/"><base href=actual/>"#).as_deref(), Some("actual/"));
        assert_eq!(href(r#"<base href="actual&#47;" href="decoy/"><base href="later/">"#).as_deref(), Some("actual/"));
        assert_eq!(href(r#"<base href=""><base href="decoy/">"#).as_deref(), Some(""));
        assert_eq!(
            href(r#"<template><base href="decoy/"></template><base href="actual/">"#).as_deref(),
            Some("actual/")
        );
    }

    #[test]
    fn deep_documents_do_not_overflow() {
        let depth = 12_000;
        let text = format!("{}<script src=actual.js></script>{}", "<div>".repeat(depth), "</div>".repeat(depth));
        assert_eq!(scripts(&text), ["actual.js"]);
    }
}

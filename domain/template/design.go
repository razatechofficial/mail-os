package template

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// The design is the designer's node tree, in the shape of Desk's designer:
// an email node holding blocks (header, text, button, image, divider,
// spacer, columns, footer), text blocks holding paragraphs, headings and
// lists of inline text, variables and line breaks. The console compiles it
// to HTML and plain text; the server stores it and validates it, and never
// renders it.

// Limits on a design.
const (
	MaxDesignBytes = 512 << 10
	// MaxDesignDepth bounds nesting: email, columns, column, text, lists
	// and inline content need far fewer levels.
	MaxDesignDepth = 32
	// maxDesignErrors caps the details of one refusal.
	maxDesignErrors = 50
)

// Node types.
const (
	NodeEmail       = "email"
	NodeHeader      = "header"
	NodeText        = "text" // a text block at block level, a run of text inline
	NodeButton      = "button"
	NodeImage       = "image"
	NodeDivider     = "divider"
	NodeSpacer      = "spacer"
	NodeColumns     = "columns"
	NodeColumn      = "column"
	NodeFooter      = "footer"
	NodeParagraph   = "paragraph"
	NodeHeading     = "heading"
	NodeBulletList  = "bulletList"
	NodeOrderedList = "orderedList"
	NodeListItem    = "listItem"
	NodeHardBreak   = "hardBreak"
	NodeVariable    = "variable"
	// NodeHTML is a raw HTML block (attrs.html). Only an administrator may
	// save one, and only where the feature is on; the HTML it compiles to
	// is sanitised like the rest of the body (contract §6).
	NodeHTML = "html"
)

// Mark types on inline text.
const (
	MarkBold      = "bold"
	MarkItalic    = "italic"
	MarkUnderline = "underline"
	MarkStrike    = "strike"
	MarkLink      = "link"
)

// Node is one node of the design tree.
type Node struct {
	Type    string         `json:"type"`
	Attrs   map[string]any `json:"attrs,omitempty"`
	Content []Node         `json:"content,omitempty"`
	Text    string         `json:"text,omitempty"`
	Marks   []Mark         `json:"marks,omitempty"`
}

// Mark is a format on inline content; a link carries attrs.href.
type Mark struct {
	Type  string         `json:"type"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

// DesignOptions are what the caller may save.
type DesignOptions struct {
	// AllowRawHTML admits html nodes: the caller is a MailOS administrator
	// and raw HTML blocks are switched on.
	AllowRawHTML bool
}

// context is where a node sits, which decides what it may be.
type context int

const (
	ctxRoot context = iota
	ctxEmail
	ctxColumns
	ctxColumn
	ctxTextBlock
	ctxInline
	ctxList
	ctxListItem
	ctxLeaf
)

var (
	blockTypes  = []string{NodeHeader, NodeText, NodeButton, NodeImage, NodeDivider, NodeSpacer, NodeColumns, NodeFooter, NodeHTML}
	columnTypes = []string{NodeText, NodeButton, NodeImage, NodeDivider, NodeSpacer, NodeHTML}
	textTypes   = []string{NodeParagraph, NodeHeading, NodeBulletList, NodeOrderedList}
	inlineTypes = []string{NodeText, NodeVariable, NodeHardBreak}
	itemTypes   = []string{NodeParagraph, NodeBulletList, NodeOrderedList}
	knownTypes  = map[string]bool{}
	knownMarks  = map[string]bool{MarkBold: true, MarkItalic: true, MarkUnderline: true, MarkStrike: true, MarkLink: true}
)

func init() {
	for _, list := range [][]string{{NodeEmail, NodeColumn, NodeListItem}, blockTypes, textTypes, inlineTypes} {
		for _, t := range list {
			knownTypes[t] = true
		}
	}
}

// allowed is what each context holds.
func (c context) allowed() []string {
	switch c {
	case ctxRoot:
		return []string{NodeEmail}
	case ctxEmail:
		return blockTypes
	case ctxColumns:
		return []string{NodeColumn}
	case ctxColumn:
		return columnTypes
	case ctxTextBlock:
		return textTypes
	case ctxInline:
		return inlineTypes
	case ctxList:
		return []string{NodeListItem}
	case ctxListItem:
		return itemTypes
	}
	return nil
}

// childContext is where a node's children sit.
func childContext(nodeType string, in context) context {
	switch nodeType {
	case NodeEmail:
		return ctxEmail
	case NodeColumns:
		return ctxColumns
	case NodeColumn:
		return ctxColumn
	case NodeText:
		if in == ctxInline {
			return ctxLeaf
		}
		return ctxTextBlock
	case NodeParagraph, NodeHeading:
		return ctxInline
	case NodeBulletList, NodeOrderedList:
		return ctxList
	case NodeListItem:
		return ctxListItem
	}
	return ctxLeaf
}

// ParseDesign decodes a design. It refuses fields a node does not have and
// anything after the tree. Use ValidateDesign to check the tree's rules.
func ParseDesign(raw []byte) (*Node, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var n Node
	if err := dec.Decode(&n); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("unexpected data after the design")
	}
	return &n, nil
}

// IsNullDesign reports a design that was not given: empty or JSON null. A
// draft may have none, such as one seeded from a version or written as
// HTML only.
func IsNullDesign(raw []byte) bool {
	s := bytes.TrimSpace(raw)
	return len(s) == 0 || string(s) == "null"
}

// ValidateDesign checks a design against the template API's rules: the
// root is an email node; only known node types and marks, each where it
// may sit; columns hold two or three columns; at most MaxDesignBytes; and
// image.src https, button, image and link hrefs https, mailto: or a single
// placeholder. Field paths point at the failing part, such as
// "design.content[2].attrs.href".
func ValidateDesign(raw []byte, opts DesignOptions) []apperrors.FieldError {
	if len(raw) > MaxDesignBytes {
		return []apperrors.FieldError{tooLarge("design", MaxDesignBytes)}
	}
	root, err := ParseDesign(raw)
	if err != nil {
		return []apperrors.FieldError{{Field: "design", Code: CodeInvalid, Message: "design is not a valid node tree"}}
	}
	v := designValidator{opts: opts}
	v.node(*root, "design", ctxRoot, 1)
	return v.errs
}

type designValidator struct {
	opts DesignOptions
	errs []apperrors.FieldError
}

func (v *designValidator) add(field, code, msg string) {
	if len(v.errs) < maxDesignErrors {
		v.errs = append(v.errs, apperrors.FieldError{Field: field, Code: code, Message: msg})
	}
}

func (v *designValidator) node(n Node, path string, in context, depth int) {
	if depth > MaxDesignDepth {
		v.add(path, CodeInvalidNesting, fmt.Sprintf("design is nested more than %d levels deep", MaxDesignDepth))
		return
	}
	if !knownTypes[n.Type] {
		v.add(path+".type", CodeUnknownNode, fmt.Sprintf("node type %q is not allowed", n.Type))
		return
	}
	if !slices.Contains(in.allowed(), n.Type) {
		v.add(path+".type", CodeInvalidNesting, fmt.Sprintf("%s may not be placed here", n.Type))
		return
	}
	inline := in == ctxInline
	if n.Text != "" && !(inline && n.Type == NodeText) {
		v.add(path+".text", CodeInvalid, "only inline text nodes carry text")
	}
	if len(n.Marks) > 0 && !(inline && (n.Type == NodeText || n.Type == NodeVariable)) {
		v.add(path+".marks", CodeInvalid, "only inline text and variables carry marks")
	}
	for i, m := range n.Marks {
		v.mark(m, fmt.Sprintf("%s.marks[%d]", path, i))
	}
	v.attrs(n, path)

	child := childContext(n.Type, in)
	if child == ctxLeaf && len(n.Content) > 0 {
		v.add(path+".content", CodeInvalidNesting, fmt.Sprintf("%s holds no content", n.Type))
		return
	}
	if n.Type == NodeColumns && (len(n.Content) < 2 || len(n.Content) > 3) {
		v.add(path+".content", CodeInvalidNesting, "columns holds 2 or 3 column nodes")
	}
	for i, c := range n.Content {
		v.node(c, fmt.Sprintf("%s.content[%d]", path, i), child, depth+1)
	}
}

func (v *designValidator) mark(m Mark, path string) {
	if !knownMarks[m.Type] {
		v.add(path+".type", CodeUnknownMark, fmt.Sprintf("mark %q is not allowed", m.Type))
		return
	}
	if m.Type == MarkLink {
		v.linkURL(m.Attrs, "href", path, true)
	}
}

func (v *designValidator) attrs(n Node, path string) {
	switch n.Type {
	case NodeButton:
		v.linkURL(n.Attrs, "href", path, false)
	case NodeImage:
		v.imageURL(n.Attrs, "src", path)
		v.linkURL(n.Attrs, "href", path, false)
	case NodeHeader:
		v.imageURL(n.Attrs, "logo_url", path)
	case NodeVariable:
		key, ok := n.Attrs["key"].(string)
		if !ok || !ValidKey(key) {
			v.add(path+".attrs.key", CodeInvalidVariable, "variable key must match ^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)*$")
		}
	case NodeHTML:
		if !v.opts.AllowRawHTML {
			v.add(path, CodeRawHTML, "raw HTML blocks are for administrators, where the feature is on")
			return
		}
		if _, ok := n.Attrs["html"].(string); !ok {
			v.add(path+".attrs.html", CodeInvalidType, "html must be a string")
		}
	}
}

// stringAttr reads an optional string attribute; ok is false when it is
// present with another type.
func (v *designValidator) stringAttr(attrs map[string]any, name, path string) (string, bool) {
	raw, present := attrs[name]
	if !present || raw == nil {
		return "", true
	}
	s, ok := raw.(string)
	if !ok {
		v.add(path+".attrs."+name, CodeInvalidType, name+" must be a string")
	}
	return s, ok
}

// linkURL checks a link target: https, mailto: or a single placeholder.
func (v *designValidator) linkURL(attrs map[string]any, name, path string, need bool) {
	s, ok := v.stringAttr(attrs, name, path)
	if !ok {
		return
	}
	switch {
	case strings.TrimSpace(s) == "":
		if need {
			v.add(path+".attrs."+name, CodeRequired, name+" is required")
		}
	case !LinkURL(s):
		v.add(path+".attrs."+name, CodeInvalidURL, name+" must be https://, mailto: or a single placeholder such as {{link}}")
	}
}

// imageURL checks an image source: https only.
func (v *designValidator) imageURL(attrs map[string]any, name, path string) {
	s, ok := v.stringAttr(attrs, name, path)
	if !ok || strings.TrimSpace(s) == "" {
		return
	}
	if !HTTPSURL(s) {
		v.add(path+".attrs."+name, CodeInvalidURL, name+" must be an https:// URL")
	}
}

// HTTPSURL reports an absolute https URL with a host and no spaces or
// control characters.
func HTTPSURL(s string) bool {
	if strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// LinkURL reports a link target a design may use: an https URL, a mailto:
// address, or a single placeholder such as {{link}} that the event fills.
func LinkURL(s string) bool {
	if _, ok := SinglePlaceholder(s); ok {
		return true
	}
	if len(s) > len("mailto:") && strings.EqualFold(s[:len("mailto:")], "mailto:") {
		return !strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f })
	}
	return HTTPSURL(s)
}

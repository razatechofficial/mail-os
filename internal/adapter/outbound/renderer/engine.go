package renderer

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"sync"
	texttemplate "text/template"

	"github.com/razatechofficial/mail-os/internal/port"
)

type engine struct {
	htmlPool sync.Pool
	textPool sync.Pool
}

func New() port.TemplateRenderer {
	return &engine{
		htmlPool: sync.Pool{New: func() any { return new(bytes.Buffer) }},
		textPool: sync.Pool{New: func() any { return new(bytes.Buffer) }},
	}
}

func (e *engine) Render(ctx context.Context, templateContent string, variables map[string]any) (string, string, error) {
	htmlBuf := e.htmlPool.Get().(*bytes.Buffer)
	defer func() { htmlBuf.Reset(); e.htmlPool.Put(htmlBuf) }()

	htmlTmpl, err := template.New("email").Parse(templateContent)
	if err != nil {
		return "", "", fmt.Errorf("renderer.Render: parse html: %w", err)
	}
	if err := htmlTmpl.Execute(htmlBuf, variables); err != nil {
		return "", "", fmt.Errorf("renderer.Render: execute html: %w", err)
	}

	textBuf := e.textPool.Get().(*bytes.Buffer)
	defer func() { textBuf.Reset(); e.textPool.Put(textBuf) }()

	textTmpl, err := texttemplate.New("email").Parse(templateContent)
	if err != nil {
		return htmlBuf.String(), "", nil
	}
	_ = textTmpl.Execute(textBuf, variables)

	return htmlBuf.String(), textBuf.String(), nil
}

var _ port.TemplateRenderer = (*engine)(nil)

package port

import "context"

type TemplateRenderer interface {
	Render(ctx context.Context, templateContent string, variables map[string]any) (html string, text string, err error)
}

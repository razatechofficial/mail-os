// Package openapi embeds the OpenAPI 3.1 document of the REST API, served
// unauthenticated at /api/v1/openapi.json and checked against the router by
// TestOpenAPISpec.
package openapi

import _ "embed"

//go:embed openapi.json
var spec []byte

// Spec returns the document.
func Spec() []byte { return spec }

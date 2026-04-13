package authzx

// Subject represents the entity performing the action.
type Subject struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	Roles      []string               `json:"roles,omitempty"`
}

// Resource represents the target of the action.
type Resource struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// AuthorizeRequest is the input for an authorization check.
type AuthorizeRequest struct {
	Subject  Subject                `json:"subject"`
	Resource Resource               `json:"resource"`
	Action   string                 `json:"action"`
	Context  map[string]interface{} `json:"context,omitempty"`
}

// AuthorizeResponse is the result of an authorization check.
type AuthorizeResponse struct {
	Allowed    bool   `json:"allowed"`
	Reason     string `json:"reason"`
	PolicyID   string `json:"policy_id,omitempty"`
	AccessPath string `json:"access_path,omitempty"`
}

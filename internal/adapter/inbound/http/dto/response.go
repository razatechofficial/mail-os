package dto

import "time"

type OrganizationResponse struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Slug          string         `json:"slug"`
	WebhookURL    string         `json:"webhook_url"`
	IsActive      bool           `json:"is_active"`
	Settings      map[string]any `json:"settings,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

type APIKeyResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	IsActive   bool       `json:"is_active"`
	CreatedAt  time.Time  `json:"created_at"`
}

type APIKeyCreateResponse struct {
	APIKeyResponse
	Key string `json:"key"`
}

type SendingDomainResponse struct {
	ID         string     `json:"id"`
	Domain     string     `json:"domain"`
	Status     string     `json:"status"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type ProviderResponse struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Type          string         `json:"type"`
	Configuration map[string]any `json:"configuration,omitempty"`
	Priority      int            `json:"priority"`
	Weight        int            `json:"weight"`
	DailyLimit    int            `json:"daily_limit"`
	IsActive      bool           `json:"is_active"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

type TemplateResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Slug        string     `json:"slug"`
	Category    string     `json:"category"`
	Description string     `json:"description"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type TemplateVersionResponse struct {
	ID         string   `json:"id"`
	TemplateID string   `json:"template_id"`
	Version    int      `json:"version"`
	Subject    string   `json:"subject"`
	Variables  []string `json:"variables"`
	IsActive   bool     `json:"is_active"`
	CreatedAt  time.Time `json:"created_at"`
}

type ContactResponse struct {
	ID        string         `json:"id"`
	Email     string         `json:"email"`
	FirstName string         `json:"first_name"`
	LastName  string         `json:"last_name"`
	Status    string         `json:"status"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type ContactListResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Type        string     `json:"type"`
	Query       string     `json:"query"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type CampaignResponse struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Subject         string     `json:"subject"`
	FromName        string     `json:"from_name"`
	FromEmail       string     `json:"from_email"`
	TemplateID      string     `json:"template_id"`
	ContactListID   string     `json:"contact_list_id"`
	Type            string     `json:"type"`
	Status          string     `json:"status"`
	ScheduledAt     *time.Time `json:"scheduled_at,omitempty"`
	TotalRecipients int        `json:"total_recipients"`
	SentCount       int        `json:"sent_count"`
	FailedCount     int        `json:"failed_count"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type MessageResponse struct {
	ID             string         `json:"id"`
	CampaignID     string         `json:"campaign_id,omitempty"`
	FromName       string         `json:"from_name"`
	FromEmail      string         `json:"from_email"`
	ToEmail        string         `json:"to_email"`
	ToName         string         `json:"to_name"`
	Subject        string         `json:"subject"`
	Type           string         `json:"type"`
	Status         string         `json:"status"`
	Tags           []string       `json:"tags,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	SentAt         *time.Time     `json:"sent_at,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type SendEmailResponse struct {
	MessageID string `json:"message_id"`
	Status    string `json:"status"`
}

type BatchSendEmailResponse struct {
	Results      []SendEmailResponse `json:"results"`
	SuccessCount int                 `json:"success_count"`
	FailCount    int                 `json:"fail_count"`
}

type SuppressionResponse struct {
	ID        string     `json:"id"`
	Email     string     `json:"email"`
	Type      string     `json:"type"`
	Reason    string     `json:"reason"`
	Source    string     `json:"source"`
	CreatedAt time.Time  `json:"created_at"`
}

type WebhookResponse struct {
	ID        string   `json:"id"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	IsActive  bool     `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type StatsResponse struct {
	PeriodType  string    `json:"period_type"`
	PeriodStart time.Time `json:"period_start"`
	Sent        int       `json:"sent"`
	Delivered   int       `json:"delivered"`
	Bounced     int       `json:"bounced"`
	Complained  int       `json:"complained"`
	Opened      int       `json:"opened"`
	Clicked     int       `json:"clicked"`
	Failed      int       `json:"failed"`
}

type AuditLogResponse struct {
	ID          string         `json:"id"`
	ActorType   string         `json:"actor_type"`
	ActorID     string         `json:"actor_id"`
	Action      string         `json:"action"`
	Resource    string         `json:"resource"`
	ResourceID  string         `json:"resource_id"`
	Changes     map[string]any `json:"changes,omitempty"`
	IPAddress   string         `json:"ip_address"`
	UserAgent   string         `json:"user_agent"`
	CreatedAt   time.Time      `json:"created_at"`
}

type HealthResponse struct {
	Status string `json:"status"`
}

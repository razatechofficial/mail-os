package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type scheduledJobRepo struct {
	pool *pgxpool.Pool
}

func NewScheduledJobRepo(pool *pgxpool.Pool) *scheduledJobRepo {
	return &scheduledJobRepo{pool: pool}
}

func (r *scheduledJobRepo) Create(ctx context.Context, job *domain.ScheduledJob) error {
	q := QuerierFromContext(ctx, r.pool)
	payload, _ := json.Marshal(job.Payload)
	_, err := q.Exec(ctx, `
		INSERT INTO scheduled_jobs (id, org_id, type, payload, status, run_at, started_at, completed_at, attempts, max_attempts, last_error, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`, job.ID, string(job.OrgID), job.Type, payload, string(job.Status), job.RunAt, nullTime(job.StartedAt), nullTime(job.CompletedAt),
		job.Attempts, job.MaxAttempts, nullStr(job.LastError), job.CreatedAt, job.UpdatedAt)
	return err
}

func (r *scheduledJobRepo) FindPending(ctx context.Context, limit int) ([]*domain.ScheduledJob, error) {
	q := QuerierFromContext(ctx, r.pool)
	if limit <= 0 {
		limit = 100
	}
	rows, err := q.Query(ctx, `
		SELECT id, org_id, type, payload, status, run_at, started_at, completed_at, attempts, max_attempts, last_error, created_at, updated_at
		FROM scheduled_jobs
		WHERE status = 'pending' AND run_at <= NOW()
		ORDER BY run_at ASC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*domain.ScheduledJob
	for rows.Next() {
		j, err := scanScheduledJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

func (r *scheduledJobRepo) UpdateStatus(ctx context.Context, id string, status domain.JobStatus, lastError string) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		UPDATE scheduled_jobs SET status = $2, last_error = $3, updated_at = NOW()
		WHERE id = $1
	`, id, string(status), nullStr(lastError))
	return err
}

func scanScheduledJob(row pgx.Row) (*domain.ScheduledJob, error) {
	var id, orgID, jobType, status, lastError string
	var payload []byte
	var runAt, createdAt, updatedAt time.Time
	var startedAt, completedAt *time.Time
	var attempts, maxAttempts int
	err := row.Scan(&id, &orgID, &jobType, &payload, &status, &runAt, &startedAt, &completedAt, &attempts, &maxAttempts, &lastError, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	var payloadMap map[string]any
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &payloadMap)
	}
	if payloadMap == nil {
		payloadMap = map[string]any{}
	}
	return &domain.ScheduledJob{
		ID:          id,
		OrgID:       domain.OrganizationID(orgID),
		Type:        jobType,
		Payload:     payloadMap,
		Status:      domain.JobStatus(status),
		RunAt:       runAt,
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Attempts:    attempts,
		MaxAttempts: maxAttempts,
		LastError:   lastError,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}, nil
}

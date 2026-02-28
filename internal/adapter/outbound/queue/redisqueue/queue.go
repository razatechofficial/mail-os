package redisqueue

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

var (
	_ port.Publisher = (*publisher)(nil)
	_ port.Consumer  = (*consumer)(nil)
)

const (
	consumerGroup = "mailos-workers"
	delayedPrefix = "delayed:"
	pollInterval  = 500 * time.Millisecond
	delayPoll     = 1 * time.Second
	blockTimeout  = 2 * time.Second
	claimIdle     = 30 * time.Second
)

// publisher writes messages to Redis Streams via XADD.
// Delayed messages are staged in a sorted set and promoted
// to the stream by the consumer's background goroutine.
type publisher struct {
	rdb *redis.Client
}

type consumer struct {
	rdb        *redis.Client
	consumerID string
}

func newClient(addr, password string, db int) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
}

func NewPublisher(addr, password string, db int) port.Publisher {
	return &publisher{rdb: newClient(addr, password, db)}
}

func NewConsumer(addr, password string, db int) port.Consumer {
	return &consumer{
		rdb:        newClient(addr, password, db),
		consumerID: "worker-" + uuid.New().String()[:8],
	}
}

func (p *publisher) Publish(ctx context.Context, topic string, payload []byte, opts ...port.PublishOption) error {
	o := port.ApplyPublishOptions(opts...)

	if o.Delay > 0 {
		score := float64(time.Now().Add(o.Delay).UnixMilli())
		member := redis.Z{Score: score, Member: string(payload)}
		return p.rdb.ZAdd(ctx, delayedPrefix+topic, member).Err()
	}

	return p.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: topic,
		Values: map[string]any{"payload": payload},
	}).Err()
}

func (p *publisher) Close() error {
	return p.rdb.Close()
}

func (c *consumer) Subscribe(ctx context.Context, topic string, handler port.JobHandler) error {
	if err := c.ensureGroup(ctx, topic); err != nil {
		return fmt.Errorf("redisqueue: create consumer group: %w", err)
	}

	// Main consumer loop
	go c.readLoop(ctx, topic, handler)

	// Promote delayed messages that are now ready
	go c.delayLoop(ctx, topic)

	// Reclaim stale pending messages from crashed consumers
	go c.claimLoop(ctx, topic, handler)

	return nil
}

func (c *consumer) ensureGroup(ctx context.Context, topic string) error {
	err := c.rdb.XGroupCreateMkStream(ctx, topic, consumerGroup, "0").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		return err
	}
	return nil
}

func (c *consumer) readLoop(ctx context.Context, topic string, handler port.JobHandler) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		streams, err := c.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    consumerGroup,
			Consumer: c.consumerID,
			Streams:  []string{topic, ">"},
			Count:    10,
			Block:    blockTimeout,
		}).Result()
		if err != nil {
			if err == redis.Nil || ctx.Err() != nil {
				continue
			}
			logger.Warn("redisqueue: xreadgroup error", logger.Err(err))
			time.Sleep(pollInterval)
			continue
		}

		for _, stream := range streams {
			for _, msg := range stream.Messages {
				c.processMessage(ctx, topic, msg, handler)
			}
		}
	}
}

func (c *consumer) processMessage(ctx context.Context, topic string, msg redis.XMessage, handler port.JobHandler) {
	payload, ok := msg.Values["payload"].(string)
	if !ok {
		logger.Warn("redisqueue: invalid payload type, acking", logger.String("id", msg.ID))
		c.rdb.XAck(ctx, topic, consumerGroup, msg.ID)
		return
	}

	if err := handler(ctx, []byte(payload)); err != nil {
		logger.Warn("redisqueue: handler failed, message stays pending",
			logger.String("id", msg.ID), logger.Err(err))
		return
	}

	c.rdb.XAck(ctx, topic, consumerGroup, msg.ID)
	c.rdb.XDel(ctx, topic, msg.ID)
}

// delayLoop polls the sorted set for delayed messages whose
// scheduled time has passed, then promotes them into the stream.
func (c *consumer) delayLoop(ctx context.Context, topic string) {
	key := delayedPrefix + topic
	ticker := time.NewTicker(delayPoll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		now := strconv.FormatInt(time.Now().UnixMilli(), 10)
		results, err := c.rdb.ZRangeByScore(ctx, key, &redis.ZRangeBy{
			Min:   "-inf",
			Max:   now,
			Count: 50,
		}).Result()
		if err != nil || len(results) == 0 {
			continue
		}

		for _, payload := range results {
			if err := c.rdb.XAdd(ctx, &redis.XAddArgs{
				Stream: topic,
				Values: map[string]any{"payload": []byte(payload)},
			}).Err(); err != nil {
				logger.Warn("redisqueue: failed to promote delayed message", logger.Err(err))
				continue
			}
			c.rdb.ZRem(ctx, key, payload)
		}
	}
}

// claimLoop reclaims messages from consumers that have been
// idle for too long (crashed or stuck), ensuring no message is lost.
func (c *consumer) claimLoop(ctx context.Context, topic string, handler port.JobHandler) {
	ticker := time.NewTicker(claimIdle)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		pending, err := c.rdb.XPendingExt(ctx, &redis.XPendingExtArgs{
			Stream: topic,
			Group:  consumerGroup,
			Start:  "-",
			End:    "+",
			Count:  20,
			Idle:   claimIdle,
		}).Result()
		if err != nil || len(pending) == 0 {
			continue
		}

		ids := make([]string, len(pending))
		for i, p := range pending {
			ids[i] = p.ID
		}

		claimed, err := c.rdb.XClaim(ctx, &redis.XClaimArgs{
			Stream:   topic,
			Group:    consumerGroup,
			Consumer: c.consumerID,
			MinIdle:  claimIdle,
			Messages: ids,
		}).Result()
		if err != nil {
			continue
		}

		for _, msg := range claimed {
			c.processMessage(ctx, topic, msg, handler)
		}
	}
}

func (c *consumer) Close() error {
	return c.rdb.Close()
}

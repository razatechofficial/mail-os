package queue

import (
	"fmt"

	"github.com/razatechofficial/mail-os/internal/adapter/outbound/queue/kafkaqueue"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/queue/natsqueue"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/queue/pgqueue"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/queue/rabbitmq"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/queue/redisqueue"
	"github.com/razatechofficial/mail-os/internal/port"
)

func NewFromConfig(backend string, opts map[string]any) (port.Publisher, port.Consumer, error) {
	switch backend {
	case "pgqueue":
		dsn, _ := opts["dsn"].(string)
		pub := pgqueue.NewPublisher(dsn)
		con := pgqueue.NewConsumer(dsn)
		return pub, con, nil
	case "redis":
		addr, _ := opts["addr"].(string)
		pub := redisqueue.NewPublisher(addr)
		con := redisqueue.NewConsumer(addr)
		return pub, con, nil
	case "rabbitmq":
		url, _ := opts["url"].(string)
		pub := rabbitmq.NewPublisher(url)
		con := rabbitmq.NewConsumer(url)
		return pub, con, nil
	case "nats":
		url, _ := opts["url"].(string)
		pub := natsqueue.NewPublisher(url)
		con := natsqueue.NewConsumer(url)
		return pub, con, nil
	case "kafka":
		brokers, _ := opts["brokers"].(string)
		pub := kafkaqueue.NewPublisher(brokers)
		con := kafkaqueue.NewConsumer(brokers)
		return pub, con, nil
	default:
		return nil, nil, fmt.Errorf("unsupported queue backend: %s", backend)
	}
}

package container

type Workers struct{}

func (c *Container) buildWorkers() *Workers {
	return &Workers{}
}

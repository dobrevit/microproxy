package main

import "sync"

type ProxyHealth struct {
	sync.Mutex
	Healthy      bool
	FailureCount int
	FailureLimit int // Threshold of failures to consider the proxy as unhealthy
}

func (p *ProxyHealth) RecordFailure() {
	p.Lock()
	defer p.Unlock()
	p.FailureCount++
	if p.FailureCount >= p.FailureLimit {
		p.Healthy = false
	}
}

func (p *ProxyHealth) RecordSuccess() {
	p.Lock()
	defer p.Unlock()
	p.Healthy = true
	p.FailureCount = 0 // reset failure count on a successful request
}

func (p *ProxyHealth) IsHealthy() bool {
	p.Lock()
	defer p.Unlock()
	return p.Healthy
}

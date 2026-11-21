package main

import (
	"fmt"
	"os"
	"sync"
)

func runTunnelPool(workers int, run protoRun, n int, fn func(tn tunnel, i int)) error {
	if workers < 1 {
		workers = 1
	}
	if workers > n {
		workers = n
	}

	var tunnels []tunnel
	for len(tunnels) < workers {
		tn, err := newTunnel(run)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tunnel setup failed: %v\n", err)
			break
		}
		tunnels = append(tunnels, tn)
	}
	if len(tunnels) == 0 {
		return fmt.Errorf("no tunnels could be created")
	}
	defer func() {
		for _, tn := range tunnels {
			tn.Close()
		}
	}()

	jobs := make(chan int)
	var wg sync.WaitGroup
	for _, tn := range tunnels {
		wg.Add(1)
		go func(tn tunnel) {
			defer wg.Done()
			for i := range jobs {
				fn(tn, i)
			}
		}(tn)
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return nil
}

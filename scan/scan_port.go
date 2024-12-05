package scan

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type PortScanner struct {
	timeout     time.Duration
	maxRoutines int
	jobChan     chan portJob
	ti          *TargetIterator
}

func NewPortScanner(ti *TargetIterator, timeout time.Duration, paralellism int) *PortScanner {
	return &PortScanner{
		timeout:     timeout,
		maxRoutines: paralellism,
		jobChan:     make(chan portJob, paralellism),
		ti:          ti,
	}
}

func (s *PortScanner) Start() error {

	for i := 0; i < s.maxRoutines; i++ {
		go func() {
			for {
				job := <-s.jobChan
				if job.port == 0 {
					break
				}

				select {
				case <-job.ctx.Done():
					close(job.done)
					return
				default:
				}

				if state, err := s.scanPort(job.ip, job.port); err == nil {
					switch state {
					case PortOpen:
						job.open <- job.port
					case PortClosed:
						job.closed <- job.port
					case PortFiltered:
						job.filtered <- job.port
					}
				}
				close(job.done)
			}
		}()
	}

	return nil
}

func (s *PortScanner) Stop() {

}

func (s *PortScanner) Scan(ctx context.Context, ports []int) ([]Result, error) {

	wg := &sync.WaitGroup{}

	if len(ports) == 0 {
		ports = make([]int, 65535)
		for i := 1; i <= 65535; i++ {
			ports[i-1] = i
		}
	}

	resultChan := make(chan *Result)
	results := []Result{}
	doneChan := make(chan struct{})

	go func() {
		for {
			result := <-resultChan
			if result == nil {
				close(doneChan)
				break
			}
			results = append(results, *result)
		}
	}()

	for {
		ip, err := s.ti.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		wg.Add(1)
		tIP := make([]byte, len(ip))
		copy(tIP, ip)
		go func(ip net.IP, ports []int, wg *sync.WaitGroup) {
			r := s.scanHost(ctx, ip, ports)
			resultChan <- &r
			wg.Done()
		}(tIP, ports, wg)

		_ = ip
	}

	wg.Wait()
	close(resultChan)
	close(s.jobChan)
	<-doneChan

	return results, nil
}

func (s *PortScanner) scanHost(ctx context.Context, host net.IP, ports []int) Result {

	wg := &sync.WaitGroup{}

	result := NewResult(host)

	openChan := make(chan int)
	closedChan := make(chan int)
	filteredChan := make(chan int)
	doneChan := make(chan struct{})

	startTime := time.Now()

	go func() {
		for {
			select {
			case open := <-openChan:
				if open == 0 {
					close(doneChan)
					return
				}
				if result.Latency < 0 {
					result.Latency = time.Since(startTime)
				}
				result.Open = append(result.Open, open)
			case closed := <-closedChan:
				if result.Latency < 0 {
					result.Latency = time.Since(startTime)
				}
				result.Closed = append(result.Closed, closed)
			case filtered := <-filteredChan:
				if result.Latency < 0 {
					result.Latency = time.Since(startTime)
				}
				result.Filtered = append(result.Filtered, filtered)
			}
		}
	}()

	for _, port := range ports {
		wg.Add(1)
		go func(p int, wg *sync.WaitGroup) {

			done := make(chan struct{})

			s.jobChan <- portJob{
				open:     openChan,
				closed:   closedChan,
				filtered: filteredChan,
				ip:       host,
				port:     p,
				done:     done,
				ctx:      ctx,
			}

			<-done
			wg.Done()

		}(port, wg)
	}

	wg.Wait()
	close(openChan)
	<-doneChan

	return result
}

func (s *PortScanner) scanPort(target net.IP, port int) (PortState, error) {

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.String(), port), s.timeout)
	if err != nil {
		if strings.Contains(err.Error(), "refused") {
			return PortClosed, nil
		}
		return PortUnknown, err
	}
	conn.Close()
	return PortOpen, err
}

func (s *PortScanner) OutputResult(result Result) {
	fmt.Println(result.String())
}

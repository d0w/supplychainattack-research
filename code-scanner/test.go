package main

import (
    "fmt"
    "sync"
    "time"
	"runtime"
)

// computeIntensive simulates a CPU-bound task by performing calculations
func computeIntensive(id int, result chan<- string, wg *sync.WaitGroup) {
    defer wg.Done()
    
    start := time.Now()
    
    // Simulate CPU-intensive computation
    var sum float64
    for i := 0; i < 1_000_000_000; i++ {
        sum += float64(i) * 0.0001
        // Occasionally check if sum is within some arbitrary bounds to prevent
        // compiler optimizations from skipping the work
        if i%10_000_000 == 0 && sum > 1e12 {
            sum = 0
        }
    }
    
    elapsed := time.Since(start)
    result <- fmt.Sprintf("Task %d completed with result: %.2f (took %v)", id, sum, elapsed)
}

// fetchData simulates fetching data from a remote source
func fetchData(id int, ch chan<- string, wg *sync.WaitGroup) {
    // Defer the WaitGroup's Done call so it happens even if the function panics
    defer wg.Done()
    
    // Simulate work with different durations
    duration := time.Duration(id*300) * time.Millisecond
    time.Sleep(duration)
    
    // Send the result to the channel
    ch <- fmt.Sprintf("Data from source %d (took %v)", id, duration)
}

func main() {
	// I/O BOUND
    fmt.Println("Starting concurrent operations...")

	fmt.Printf("Using %d CPUs\n", runtime.NumCPU())
    
    // Create a channel to receive results
    resultChannel := make(chan string, 5)
    
    // Create a WaitGroup to wait for all goroutines to finish
    var wg sync.WaitGroup
    
    // Start multiple concurrent operations
    for i := 1; i <= 5; i++ {
        wg.Add(1)
        go fetchData(i, resultChannel, &wg)
    }
    
    // Start a goroutine to close the channel once all fetchData goroutines are done
    go func() {
        wg.Wait()
        close(resultChannel)
    }()
    
    // Process results as they arrive
    for result := range resultChannel {
        fmt.Println("Received:", result)
    }



	// // CPU bound 
	// numCPUs := runtime.NumCPU()
	// runtime.GOMAXPROCS(numCPUs)

	// fmt.Printf("Using %d CPU cores for computation.\n", numCPUs)

	// resultChannel := make(chan string, numCPUs)

	// var wg sync.WaitGroup
	
	// for i := 1; i <= numCPUs; i++ {
	// 	wg.Add(1)
	// 	go computeIntensive(i, resultChannel, &wg) // Start CPU-intensive tasks
	// }

	// go func() {
	// 	// Wait for all computeIntensive goroutines to finish and close the channel
	// 	wg.Wait()
	// 	close(resultChannel)
	// }()

	// for result := range resultChannel {
	// 	fmt.Println("Received:", result) // Process results as they arrive
	// }
    
    // fmt.Println("All operations completed!")
}
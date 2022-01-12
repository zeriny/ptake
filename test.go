package main

import (
    "bufio"
    "bytes"
    "fmt"
    "io"
    "os"
    "ptake/ptake_pkg"
    "strings"
    "sync"
    "time"
)

func testIsAvailable() {
    file, err := os.Open("temp/available_fr_domain_0110.txt")
    if err != nil {
        fmt.Println(err)
    }

    defer file.Close()
    scanner := bufio.NewScanner(file)
    // Hint: The default MaxScanTokenSize is set with 64 * 1024 (65536). If exceeded, ErrTooLong will be thrown.
    scanner.Buffer([]byte{}, bufio.MaxScanTokenSize*10)
    for scanner.Scan() {
        line:=scanner.Text()
        domain:=strings.TrimRight(line, ".")
        fmt.Println(domain, ptake_pkg.IsAvailable(domain))
        time.Sleep(time.Duration(10)*time.Second)
    }
    if scanner.Err() != nil {
        fmt.Println(scanner.Err())
    }

    return
}

func testSingleIsAvailable(domain string){
    flag := ptake_pkg.IsAvailable(domain)
    fmt.Println(flag)
}

func checkContentFingerprint(domain string) {
    _, body := ptake_pkg.Get(domain, 3, false)
    if body == nil {
        _, body = ptake_pkg.Get(domain, 3, true)
    }
    match := false
    fps := [3]string{"This page isn’t working", "We’re having trouble finding that site.", "Not Found"}

    for i := range fps{
        fp := fps[i]
        if bytes.Contains(body, []byte(fp)){
            match = true
            if match{
                break
            }
        }
    }
    fmt.Println(domain, match)
}

func testFingerprintChecking(domainPath string) {
    chanStream := make(chan string, 100)
    wg := new(sync.WaitGroup)

    // Consumer
    for i := 0; i < 100; i++ {
        wg.Add(1)
        go func() {
            for domain := range chanStream {
                checkContentFingerprint(domain)
            }
            wg.Done()
        }()
    }

    // Producer: Load CNAME chains to be checked.
    file, err := os.Open(domainPath)
    if err != nil {
        fmt.Println(err)
        return
    }
    defer file.Close()
    reader := bufio.NewReader(file)
    for {
        lineBytes, err := reader.ReadBytes('\n')
        if err == io.EOF {
            break
        }
        if err != nil {
            fmt.Println("Error: %s\n", err.Error())
        }
        lineBytes = bytes.TrimRight(lineBytes, "\n")

        chanStream <- string(lineBytes)
    }

    close(chanStream)
    wg.Wait()
}
func main(){

    //testIsAvailable()
    //testSingleIsAvailable("www.14septembre.fr")
    testFingerprintChecking(os.Args[1])
}
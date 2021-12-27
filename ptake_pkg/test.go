package ptake_pkg

import
(
    "os"
    log "github.com/sirupsen/logrus"
    "bufio"
    "strings"
    "fmt"
)

func testIsAvailable() {
    file, err := os.Open("temp/1222_expired_fqdn.txt")
    if err != nil {
        log.Fatalln(err)
    }

    defer file.Close()
    scanner := bufio.NewScanner(file)
    // Hint: The default MaxScanTokenSize is set with 64 * 1024 (65536). If exceeded, ErrTooLong will be thrown.
    scanner.Buffer([]byte{}, bufio.MaxScanTokenSize*10)
    for scanner.Scan() {
        line:=scanner.Text()
        domain:=strings.TrimRight(line, ".")
        fmt.Println(domain, isAvailable(domain))
    }
    if scanner.Err() != nil {
        log.Fatalln(scanner.Err())
    }

    return
}

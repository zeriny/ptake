package ptake_pkg

import (
    "bufio"
    "encoding/json"
    "fmt"
    "gopkg.in/yaml.v2"
    "io/ioutil"
    "log"
    "os"
    "path"
)

func loadConfig(confFile string) (c Conf) {
    yamlConfig, err := ioutil.ReadFile(confFile)
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    err = yaml.Unmarshal(yamlConfig, &c)
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    return c
}

func loadServiceList(file string) (serviceList []Service) {
    config, err := ioutil.ReadFile(file)
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    err = json.Unmarshal(config, &serviceList)
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    return serviceList
}

func splitInputFile(inputPath string, outputPath string, l int){
    var lines []string
    file, err := os.Open(inputPath)
    if err != nil {
        log.Fatalln(err)
    }
    defer file.Close()
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        lines = append(lines, scanner.Text())
    }
    if scanner.Err() != nil {
        log.Fatalln(err)
    }

    for i := range lines {
        outputBase := fmt.Sprintf("%salexa_%dk", outputPath, (i/l+1))
        err := os.MkdirAll(outputBase,os.ModePerm)
        if err!=nil {
            fmt.Println(err)
            os.Exit(1)
        }
        outputPath := path.Join(outputBase, "sld.txt")
        fmt.Println(outputPath)
        f, err := os.OpenFile(outputPath, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
        if err != nil {
            log.Fatalln(err)
        }
        defer f.Close()
        _, err = f.WriteString(lines[i] + "\n")
        if err != nil {
            log.Fatalln(err)
        }
    }

}

func Initialize(o *Options) (){
    fmt.Println("[+] Initializing...")
    defaultDataPath := "./data/"
    defaultOutputPath := "./results/"

    // Data Path
    if o.InputPath == ""{
        o.InputPath = path.Join(defaultDataPath, o.Dataset)
        fmt.Printf("[+] Input data path: %s\n", o.InputPath)
    }
    _, err := os.Stat(o.InputPath)
    if os.IsNotExist(err) {
        fmt.Println(err)
        os.Exit(1)
    }

    // Result Path
    if o.OutputPath == ""{
        o.OutputPath = path.Join(defaultOutputPath, o.Dataset)
        fmt.Printf("[+] Output results path: %s\n", o.OutputPath)
        err := os.MkdirAll(o.OutputPath,os.ModePerm)
        if err!=nil {
            fmt.Println(err)
            os.Exit(1)
        }
    }

    // Cache Path
    o.CachePath = path.Join(o.InputPath, "cache")
    err1 := os.MkdirAll(o.CachePath,os.ModePerm)
    if err1!=nil {
        fmt.Println(err1)
        os.Exit(1)
    }

    if o.Fresh{
        fmt.Println("[!] A fresh scan will be start. It's going to remove cache files...")
        dir, _ := ioutil.ReadDir(o.CachePath)
        for _, d := range dir {
            os.RemoveAll(path.Join([]string{o.CachePath, d.Name()}...))
        }
        fmt.Printf("[!] Cache files in %s are removed!\n", o.CachePath)
        os.Remove(o.LogPath)
        fmt.Printf("[!] Log file is removed (%s)\n", o.LogPath)
    }

    // Log Path
    logPath := path.Join(o.InputPath, "ptake.log")
    if o.LogPath != ""{
        logPath = o.LogPath
    }
    logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        return
    }
    log.SetOutput(logFile)
    log.SetFlags(log.Lshortfile | log.Lmicroseconds | log.Ldate)

    // Configurations
    o.Config = loadConfig(o.ConfigPath)
    o.ServiceList = loadServiceList(o.ServicePath)
    fmt.Printf("[+] Load %d services.\n", len(o.ServiceList))
    fmt.Println("[+] Initialize over.")
}
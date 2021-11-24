package ptake_pkg

import (
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
        fmt.Printf("[!] Cache files in %s are removed!", o.CachePath)
        os.Remove(o.LogPath)
        fmt.Printf("[!] Log file is removed (%s)", o.CachePath)
    }

    // Log Path
    logFile, err := os.OpenFile(o.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        return
    }
    log.SetOutput(logFile)
    log.SetFlags(log.Llongfile | log.Lmicroseconds | log.Ldate)

    // Configurations
    o.Config = loadConfig(o.ConfigPath)
    o.ServiceList = loadServiceList(o.ServicePath)
    fmt.Printf("[+] Load %d services.\n", len(o.ServiceList))
    fmt.Println("[+] Initialize over.")
}
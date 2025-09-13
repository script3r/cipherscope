package main

import (
    "fmt"
    "golang.org/x/crypto/bcrypt"
)

func main() {
    _, _ = bcrypt.GenerateFromPassword([]byte("pw"), 10)
    fmt.Println("ok")
}


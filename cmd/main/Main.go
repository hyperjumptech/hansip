package main

import (
	"fmt"
	"github.com/hyperjumptech/hansip/internal/server"
)

func main() {
	fmt.Println(
		` __ __   ____  ____   _____ ____  ____  
|  |  | /    ||    \ / ___/|    ||    \ 
|  |  ||  o  ||  _  (   \_  |  | |  o  )
|  _  ||     ||  |  |\__  | |  | |   _/ 
|  |  ||  _  ||  |  |/  \ | |  | |  |   
|  |  ||  |  ||  |  |\    | |  | |  |   
|__|__||__|__||__|__| \___||____||__|   
Access Authentication & Authorization (AAA) server.`)
	server.Start()
}

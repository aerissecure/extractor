package main

import (
	"fmt"
	"os"

	"github.com/aerissecure/extractor"
)

func main() {
	for _, file := range []string{"x2.tar", "x.bz2", "x.gz", "x.lz4", "x.rar", "x.tar", "x.txt", "x.xz", "x.zip"} {
		fmt.Println("__", file, "__")
		f, _ := os.Open(file)
		e := extractor.New(f, file)
		for {
			r, fname, err, more := e.NextWithError()
			if !more {
				break
			}
			fmt.Println("name:", fname, "err:", err)
			if err == nil {
				b := make([]byte, 128)
				r.Read(b)
				fmt.Println("io.Reader:", string(b))
				fmt.Println()
			}
			// if err != nil {
			// 	fmt.Println("reader == nil?:", r == nil)
			// }
		}
		fmt.Println("-----------------")
	}
	// time.Sleep(time.Second * 20)
}

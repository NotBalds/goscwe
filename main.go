package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
)

func exists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	return false
}

func main() {
	if !exists(os.Getenv("HOME") + "/.local/share/gocwe") {
		id := uuid.NewString()
		key, _ := rsa.GenerateKey(rand.Reader, 1024)
		os.MkdirAll(os.Getenv("HOME")+"/.local/share/gocwe", fs.ModePerm)
		os.Chdir(os.Getenv("HOME") + "/.local/share/gocwe")
		os.WriteFile("uuid", []byte(id), fs.ModePerm)
		os.WriteFile("key", x509.MarshalPKCS1PrivateKey(key), fs.ModePerm)
	}
	os.Chdir(os.Getenv("HOME") + "/.local/share/gocwe")
	var keys = make(map[string]string)
	for {
		fmt.Println("If you want to receive messages, enter 0, if you want to send message, enter 1, to view your uuid and publickey, enter 2")
		var n int
		fmt.Scan(&n)
		if n < 0 || n > 2 {
			log.Fatalln("Unsupported operation!")
		}
		if n == 0 {
			bts, _ := os.ReadFile("uuid")
			id := string(bts)
			bts, _ = os.ReadFile("key")
			key, _ := x509.ParsePKCS1PrivateKey(bts)
			data, _ := json.Marshal(User{id})
			res, _ := http.Post("http://bald.su:1337/get", "application/json", bytes.NewReader(data))
			body, _ := io.ReadAll(res.Body)
			var msgs []Message
			_ = json.Unmarshal(body, &msgs)
			var by_sender = make(map[string][]Message)
			for _, v := range msgs {
				by_sender[v.Sender] = append(by_sender[v.Sender], v)
			}
			for k := range by_sender {
				fmt.Println("From " + k + ":")
				for _, v := range by_sender[k] {
					bts, _ := base64.StdEncoding.DecodeString(v.Content)
					decr, _ := rsa.DecryptPKCS1v15(rand.Reader, key, bts)
					fmt.Println(string(decr))
				}
			}
		}
		if n == 1 {
			bts, _ := os.ReadFile("uuid")
			id := string(bts)
			bts, _ = os.ReadFile("key")
			var content, pubkey, receiver string
			fmt.Println("Enter receiver:")
			fmt.Scan(&receiver)
			if keys[receiver] == "" {
				fmt.Println("Enter his publickey")
				fmt.Scan(&pubkey)
				keys[receiver] = pubkey
			} else {
				pubkey = keys[receiver]
			}
			fmt.Println("Enter content:")
			io := bufio.NewReader(os.Stdin)
			content, _ = io.ReadString('\n')
			btskey, _ := base64.StdEncoding.DecodeString(pubkey)

			cpubkey, _ := x509.ParsePKCS1PublicKey(btskey)

			ccontent, _ := rsa.EncryptPKCS1v15(rand.Reader, cpubkey, []byte(content))

			basecontent := base64.StdEncoding.EncodeToString(ccontent)

			data, _ := json.Marshal(Send{Receiver: receiver, Message: Message{Sender: id, Content: basecontent, SendTime: strconv.FormatInt(time.Now().Unix(), 10)}})
			_, _ = http.Post("http://bald.su:1337/send", "application/json", bytes.NewReader(data))
		}
		if n == 2 {
			bts, _ := os.ReadFile("uuid")
			id := string(bts)
			bts, _ = os.ReadFile("key")
			fmt.Println("uuid:", id)
			ckey, _ := x509.ParsePKCS1PrivateKey(bts)
			btskey := x509.MarshalPKCS1PublicKey(&ckey.PublicKey)

			strkey := base64.StdEncoding.EncodeToString(btskey)
			fmt.Println("publickey:", strkey)
		}
	}
}

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
)

func main() {

	//Parse the command line arguments for l, p flags.
	listenPort := flag.String("l", "", "a string")
	pwdFile := flag.String("p", "", "a string")

	destIP := ""
	destPort := ""
	passPhrase := ""

	flag.Parse()

	destArgs := flag.Args()

	if len(destArgs) > 1 {
		destIP = destArgs[0]
		destPort = destArgs[1]
	}

	// Open file to read passphrase from
	if *pwdFile != "" {
		dat, err := ioutil.ReadFile(*pwdFile)
		if err != nil {
			fmt.Println(err)
		}
		passPhrase = string(dat)
	}

	if *listenPort != "" {
		startServer(passPhrase, *listenPort, destIP, destPort)
	} else {
		startClient(passPhrase, destIP, destPort)
	}
}

func startClient(passPhrase string, destHost string, destPort string) {

	fmt.Println("Started client mode")

	conn, err := net.Dial("tcp", destHost+":"+destPort)

	if err != nil {
		fmt.Printf("Can't connect to server: %s\n", err)
		return
	}
	fmt.Println("Connected to ", destHost, " : ", destPort)

	go readFromStdin(conn, passPhrase)
	writeToStdout(conn, passPhrase)
}

func startServer(passPhrase string, listenPort string, destHost string, destPort string) {

	fmt.Println("Started reverse server proxy mode")

	listener, err := net.Listen("tcp", ":"+listenPort)

	if err != nil {
		panic(err)
	}
	defer listener.Close()

	fmt.Println("Reading from ", listener.Addr().String())

	for {

		conn, err := listener.Accept()

		proxy, err := net.Dial("tcp", destHost+":"+destPort)

		if err != nil {
			fmt.Println(err)
			return
		}
		go processClient(conn, proxy, passPhrase)
		go processReverseServer(conn, proxy, passPhrase)
	}

}

func processReverseServer(conn net.Conn, proxy net.Conn, passPhrase string) {
	for {
		if proxy == nil {
			return
		}

		buf := make([]byte, 1024)
		n, err := proxy.Read(buf)

		if err != nil {
			conn.Close()
			proxy.Close()
			conn = nil
			proxy = nil
			return
		}

		encryptedBuffer := getCipherText(passPhrase, buf[:n])
		sendInBlocks(encryptedBuffer, passPhrase, conn)
	}
}

func processClient(conn net.Conn, proxy net.Conn, passPhrase string) {

	log.Println("A client joined")
	for {

		if conn == nil || proxy == nil {
			return
		}
		buffreader := make([]byte, 1024)
		_, err := conn.Read(buffreader)
		if err != nil {
			log.Println("Client closed the connection")
			conn.Close()
			proxy.Close()
			return
		}

		var end_term int

		for end_term = 0; end_term < 1024; end_term++ {
			if buffreader[end_term] == 0 {
				break
			}
		}

		decrryptedBuf := getPlainText(passPhrase, (buffreader[:end_term]))
		finalBuf := recvInBlocks(decrryptedBuf, passPhrase, conn)
		proxy.Write(finalBuf)
	}
}

func readFromStdin(conn net.Conn, passPhrase string) {
	for {
		if conn == nil {
			return
		}
		buf := make([]byte, 1024)
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return
		}
		encryptedBuffer := getCipherText(passPhrase, buf[:n])
		sendInBlocks(encryptedBuffer, passPhrase, conn)

	}
}

func writeToStdout(conn net.Conn, passPhrase string) {

	for {
		buf := make([]byte, 1024)
		_, err := conn.Read(buf)

		if err != nil {

			return
		}

		var end_term int

		for end_term = 0; end_term < 1024; end_term++ {
			if buf[end_term] == 0 {
				break
			}
		}

		decryptedBuf := getPlainText(passPhrase, buf[:end_term])
		finalBuf := recvInBlocks(decryptedBuf, passPhrase, conn)
		os.Stdout.Write(finalBuf)

	}
}

func getCipherText(passPhrase string, plainText []byte) []byte {
	salt := make([]byte, 8)
	rand.Read(salt)

	key := pbkdf2.Key([]byte(passPhrase), salt, 1000, 32, sha256.New)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	data := aesgcm.Seal(nil, nonce, []byte(plainText), nil)

	return []byte(hex.EncodeToString(salt) + "-" + hex.EncodeToString(nonce) + "-" + hex.EncodeToString(data))
}

func getPlainText(passPhrase string, cipherText []byte) []byte {
	if cipherText != nil {
		arr := strings.Split(string(cipherText), "-")
		salt := make([]byte, 8)
		rand.Read(salt)
		nonce := make([]byte, 12)
		rand.Read(nonce)
		data := cipherText
		if len(arr) == 3 {
			salt, _ = hex.DecodeString(arr[0])
			nonce, _ = hex.DecodeString(arr[1])
			data, _ = hex.DecodeString(arr[2])
		}
		key := pbkdf2.Key([]byte(passPhrase), salt, 1000, 32, sha256.New)
		b, _ := aes.NewCipher(key)
		aesgcm, _ := cipher.NewGCM(b)
		data, _ = aesgcm.Open(nil, nonce, data, nil)
		return data
	}
	return []byte("")
}

func sendInBlocks(cipherText []byte, passPhrase string, conn net.Conn) {

	cipherLen := len(cipherText)
	var quotient int = cipherLen / 1024
	extraElement := false
	if cipherLen%1024 != 0 {
		extraElement = true
	}

	encBlock := getCipherText(passPhrase, []byte(strconv.Itoa(cipherLen)))
	tempBuf := make([]byte, 1024)

	tempBuf = []byte(encBlock[:])
	lenbuffer := make([]byte, 1024)
	lenbuffer = append(tempBuf, lenbuffer[len(tempBuf):]...)
	conn.Write(lenbuffer)

	for i := 0; i < quotient; i++ {
		encryptblock := cipherText[:1024]
		conn.Write(encryptblock)
		cipherText = cipherText[1024:]
	}

	if extraElement == true {
		temp := make([]byte, 1024)
		temp = append(cipherText, temp[len(cipherText):]...)
		conn.Write(temp)
	}
}

func recvInBlocks(plainText []byte, passPhrase string, conn net.Conn) []byte {

	if length, len_err := strconv.Atoi(string(plainText)); len_err == nil {

		var quotient int = length / 1024

		extraElement := false
		if length%1024 != 0 {
			extraElement = true
		}

		var buf []byte

		for i := 0; i < quotient; i++ {
			remBlock := make([]byte, 1024)
			n, err := conn.Read(remBlock)
			if err != nil {
				log.Println("Client closed the connection")
			}
			buf = append(buf, remBlock[:n]...)
		}

		if extraElement == true {

			extraBlock := make([]byte, 1024)
			nleft, errlen := conn.Read(extraBlock)
			if errlen != nil {
				conn.Close()
			}

			extraBlock = extraBlock[:nleft]
			buf = append(buf, extraBlock...)
		}
		return getPlainText(passPhrase, buf[:])
	} else {
		return plainText
	}
}

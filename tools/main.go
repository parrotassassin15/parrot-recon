package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"time"

	"github.com/bndr/gotabulate"
)

var (
	flagHelp   = flag.Bool("h", false, `Print the help menu and exit`)
	flagList   = flag.String("l", "", `Use a list for SQL Testing`)
	flagTor    = flag.String("p", "", `Use tor proxies to connect to host`)
	flagTarget = flag.String("t", "", `target URL`)
)

var Proxy string = "socks5://127.0.0.1:9050"

func online() {
	response, err := http.Get("https://www.google.com")
	ch(err)
	if response.StatusCode != 200 {
		fmt.Println("\033[31m[-] You seem to not be online.....")
		fmt.Println("\033[31m[-] Exiting.....")
		os.Exit(0)
	} else {
		fmt.Println("[*] Online test passed.....")
	}
}

//
//
//
//
func tabletest() {
	row_1 := []interface{}{"john", 20, "ready"}

	// Create an object from 2D interface array
	t := gotabulate.Create([][]interface{}{row_1})

	// Set the Headers (optional)
	t.SetHeaders([]string{*flagTarget})
	t.SetEmptyString("None")
	t.SetAlign("center")
	fmt.Println(t.Render("grid"))
}

func listed() {
	flag.Parse()
	//
	//
	//
	f, err := os.Open(*flagList)
	if err != nil {
		fmt.Println("[-] Sorry could not parse the list -> ", *flagList)
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	//
	for scan.Scan() {
		jector := []string{
			scan.Text(),
		}
		errors := []string{
			"SQL",
			"MySQL",
			"ORA-",
			"syntax", // better verticle
		}

		errRegexes := []*regexp.Regexp{}
		for _, e := range errors {
			re := regexp.MustCompile(fmt.Sprintf(".*%s.*", e))
			errRegexes = append(errRegexes, re)
		}

		for _, payload := range jector {

			client := new(http.Client)
			body := []byte(fmt.Sprintf("username=%s&password=p", payload))

			req, err := http.NewRequest(
				"POST",
				*flagTarget,
				bytes.NewReader(body),
			)

			if err != nil {
				log.Fatalf("\033[31m\t[!] Unable to generate request: %s\n", err)
			}

			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			resp, err := client.Do(req)
			if err != nil {
				log.Fatalf("[!] Unable to process response: %s\n", err)
			}

			body, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Fatalf("[!] Unable to read response body: %s\n", err)
			}

			resp.Body.Close() // close response

			for idx, re := range errRegexes {
				if re.MatchString(string(body)) {
					stringerror := "Server is vulnerable"
					errormsg := "An error | detected vulnerability"
					//				fmt.Printf("[+] SQL Error found [Server->%s] for payload: %s\n", errors[idx], payload)
					row_1 := []interface{}{errors[idx], payload}
					row_2 := []interface{}{errormsg}
					t := gotabulate.Create([][]interface{}{row_1, row_2})
					t.SetHeaders([]string{*flagTarget, stringerror})
					t.SetAlign("center")
					fmt.Println("\033[37m", t.Render("grid"))
					break
					//fmt.Printf("[+] SQL Error found [Server->%s] for payload: %s\n", errors[idx], payload)
					//break
				}
			}
		}
	}

}

func torhandel(err error) {
	if err != nil {
		fmt.Println("Error recived within this block | parsing -> ", Proxy)
		log.Fatal(err)
	}
}

func testproxy() {
	torProxyUrl, err := url.Parse(Proxy)

	if err != nil {
		fmt.Println("[-] Error when running proxy, is tor offline? or not being uses")
		os.Exit(0)
	}

	torTransport := &http.Transport{Proxy: http.ProxyURL(torProxyUrl)}
	client := &http.Client{Transport: torTransport, Timeout: time.Second * 5}
	resp, err := client.Get("https://www.google.com")

	if err != nil {
		fmt.Println("[-] Error when attempting connection using socket -> ", Proxy)
		fmt.Println("[-] Attempted to grab or make a GET request to server => https://www.google.com")
		log.Fatal(err)
	}
	defer resp.Body.Close()
}

func maintor() {
	flag.Parse()
	testproxy()
	torProxyUrl, err := url.Parse(Proxy)
	torhandel(err)
	torTransport := &http.Transport{Proxy: http.ProxyURL(torProxyUrl)}
	client := &http.Client{Transport: torTransport, Timeout: time.Second * 5}
	resp, err := client.Get(*flagTarget)
	ch(err)
	defer resp.Body.Close()
	fmt.Println("[*] Used Sock  : ", Proxy)
	fmt.Println("[*] Status Code: ", resp.StatusCode)
}

func ch(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func clear() {
	if runtime.GOOS == "windows" {
		cls, err := exec.Command("cls").Output()
		if err != nil {
			log.Fatal(err)
		}
		output := string(cls[:])
		fmt.Println(output)
	}
	if runtime.GOOS == "linux" {
		clear, err := exec.Command("clear").Output()
		ch(err)
		output := string(clear[:])
		fmt.Println(output)
	}
}

func main() {
	flag.Parse()
	online()
	if *flagHelp {
		fmt.Println("\033[32m[*] Usage    -> go run main.go -t <target> ")
		fmt.Println("\033[32m[X] Extra    -> -p true|false <tor> -l <injection-list>")
		fmt.Println("\033[32m[X] Advances -> go run main.go -t <target> -p -l <main.txt> | note it must be a main.txt")
		fmt.Println("---------------------------------------------------------------------------")
		flag.PrintDefaults()
	}
	if *flagTor == "true" {
		testproxy()
		maintor()
	}
	if *flagTor == "false" {
		fmt.Println("[*] Not using tor sockets")
	}
	if *flagList == "main.txt" {
		listed()
		os.Exit(1)
	}
	if *flagTarget == "true" {
		fmt.Println("[-] Please input a url")
		fmt.Println("[-] go run main.go -t http://testphp.vulnweb.com/listproducts.php?cat=1")
		os.Exit(1)
	}
	injections := []string{
		"baseline",
		")",
		"(",
		"\"",
		"'",
	}
	errors := []string{
		"SQL",
		"MySQL",
		"ORA-",
		"syntax",
	}

	errRegexes := []*regexp.Regexp{}
	for _, e := range errors {
		re := regexp.MustCompile(fmt.Sprintf(".*%s.*", e))
		errRegexes = append(errRegexes, re)
	}

	for _, payload := range injections {
		client := new(http.Client)
		body := []byte(fmt.Sprintf("username=%s&password=p", payload))

		res, err := http.NewRequest(
			"POST",
			*flagTarget,
			bytes.NewReader(body),
		)

		if err != nil {
			log.Fatalf("\033[31m\t[X] Unable to Create request -> %s\n", err)
		}

		res.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(res)
		if err != nil {
			log.Fatalf("\033[31m[X] Unable to process response: %s\n", err)
		}

		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("\033[31m[X] Unable to read response body: %s\n", err)
		}

		resp.Body.Close() // close response

		for idx, re := range errRegexes {
			if re.MatchString(string(body)) {
				stringerror := "Server is vulnerable"
				errormsg := "An error | detected vulnerability"
				//				fmt.Printf("[+] SQL Error found [Server->%s] for payload: %s\n", errors[idx], payload)
				row_1 := []interface{}{errors[idx], payload}
				row_2 := []interface{}{errormsg}
				t := gotabulate.Create([][]interface{}{row_1, row_2})
				t.SetHeaders([]string{*flagTarget, stringerror})
				t.SetAlign("center")
				fmt.Println("\033[37m", t.Render("grid"))
				break
			}
		}
	}
}

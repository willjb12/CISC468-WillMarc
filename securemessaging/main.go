package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/mdns"
)

type chatRequest struct {
	srcIP   net.IP
	dstIP   net.IP
	srcUser string
	dstUser string
}

type ControlWrite struct {
	Writer io.Writer
}

func (cw *ControlWrite) Write(p []byte) (n int, err error) {
	if strings.HasPrefix(string(p), "sm> ") || string(p) == "sm> " {
		return cw.Writer.Write(p)
	}
	return len(p), nil
}

func print_nice_columns(discovered []*mdns.ServiceEntry) {
	var userNum string
	var userName string

	fmt.Println("User Number     Username     IP Address")

	for ind, entry := range discovered {

		userNum = fmt.Sprintf("%d", ind+1) + strings.Repeat(" ", 16-len(fmt.Sprintf("%d", ind+1)))

		if len(entry.Host) < 13 {
			userName = entry.Host + strings.Repeat(" ", 13-len(entry.Host))
		} else {
			userName = entry.Host[0:11] + strings.Repeat(" ", 2)
		}

		fmt.Printf("%s%s%s\n", userNum, userName, entry.AddrV4)

	}
}

func announce_presence() *mdns.Server {
	host, _ := os.Hostname()
	info := []string{"Secure Messaging"}
	service, _ := mdns.NewMDNSService(host, "_securemessaging._udp", "", "", 8000, nil, info)

	// Create the mDNS server, defer shutdown
	server, _ := mdns.NewServer(&mdns.Config{Zone: service})

	return server
}

func default_interface() net.IP {
	defaultRoute, _ := net.InterfaceAddrs()

	var defaultIP net.IP
	for _, addr := range defaultRoute {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			defaultIP = ipNet.IP
			break
		}
	}

	return defaultIP
}

func peer_discovery() []*mdns.ServiceEntry {
	params := mdns.DefaultParams("_securemessaging._udp")

	entriesCh := make(chan *mdns.ServiceEntry, 10)

	params.DisableIPv6 = true
	params.Entries = entriesCh

	var mu sync.Mutex
	var discovered []*mdns.ServiceEntry

	go func() {
		for entry := range entriesCh {
			// fmt.Printf("sm> Got new entry: %v\n", entry)
			mu.Lock()
			discovered = append(discovered, entry)
			mu.Unlock()
		}
	}()

	fmt.Printf("Users to connect with: \n")
	mdns.Query(params)

	time.Sleep(5 * time.Second)

	print_nice_columns(discovered)

	return discovered
}

func initiate_chat() {
	incomingRequestChan := make(chan chatRequest)
	peerSelectionChan := make(chan chatRequest)
	quitChan := make(chan struct{})
	pauseDiscoveryChan := make(chan struct{})

	// look for users and take the users desired connection
	// send valid user input to the peerSelectionChan
	go func() {
		var input string

		for {
			discovered := peer_discovery()

			fmt.Println("\nEnter the user you would like to connect to, refresh to refresh, or back")

			fmt.Print("sm> ")
			fmt.Scanln(&input)

			if strings.ToLower(input) == "refresh" {
				fmt.Println("refreshing available users")
			} else if strings.ToLower(input) == "back" {
				fmt.Println("going back to main screen")
				quitChan <- struct{}{}
				<-pauseDiscoveryChan
			} else {
				var selectedEntry *mdns.ServiceEntry
				var found bool
				for _, entry := range discovered {
					if strings.HasPrefix(entry.Host, input) || entry.Host == input {
						selectedEntry = entry
						found = true
						break
					}
				}
				if !found {
					fmt.Println("\nHost not found. Check your typing.")
					continue
				} else {
					host, _ := os.Hostname()
					myIP := default_interface()
					selection := chatRequest{srcIP: myIP, dstIP: selectedEntry.AddrV4, srcUser: host, dstUser: selectedEntry.Host}

					peerSelectionChan <- selection
					<-pauseDiscoveryChan
				}
			}
		}
	}()

	// listen for connection requests
	// parse a received request and send it to the incoming requests chan
	go func() {
		addr, err := net.ResolveUDPAddr("udp", ":60001")
		if err != nil {
			fmt.Println("Could not resolve address")
			return
		}

		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			fmt.Println("Could not create connection")
			return
		}

		defer conn.Close()

		buffer := make([]byte, 1024)
		for {
			n, _, _ := conn.ReadFromUDP(buffer)

			request := string(buffer[:n])
			incomingRequestChan <- chatRequest{srcIP: net.ParseIP("0.0.0.0"), dstIP: net.ParseIP("0.0.0.0"), srcUser: request, dstUser: "me"}
		}
	}()

	for {
		select {
		case selection := <-peerSelectionChan:

			fmt.Println("\nYou have selected a user")

			destination := selection.dstIP.String() + ":" + "60001"
			serverAddr, err := net.ResolveUDPAddr("udp", destination)
			if err != nil {
				fmt.Println("Could not resolve address")
				continue
			}
			conn, err := net.DialUDP("udp", nil, serverAddr)
			if err != nil {
				fmt.Println("Could not create connection")
				continue
			}
			message := []byte("Hello")
			_, err = conn.Write(message)
			if err != nil {
				fmt.Println("could not send message")
				continue
			}

			conn.Close()
			pauseDiscoveryChan <- struct{}{}
		case request := <-incomingRequestChan:
			fmt.Println("\nA user is trying to connect to you.")
			fmt.Println(request.srcUser)
		case <-quitChan:

			return
		}

	}
}

// takes an ip address that you wish to chat with and attempts to initiate a connection
func chat_with(net.IP) string {
	return "quit"
}

// handle input on the main menu and allow the user to
// chat
// migrate key
// help
// quit
func handle_main_menu(input string) string {
	if input == "chat" || input == "1" {
		initiate_chat()
		return "good"
	} else if input == "quit" || input == "2" {
		return "quit"
	}

	fmt.Println("The input does not correspond to a valid command")
	return "not good"
}

func main() {
	// login

	// Announce presence on the network for duration of time with program open
	server := announce_presence()
	defer server.Shutdown()

	// take main menu input and store in input
	var input string

	for {
		fmt.Printf("Main Menu\nAvailable Options\n1. chat\n2. quit\n")
		fmt.Print("sm> ")
		fmt.Scanln(&input)

		res := handle_main_menu(input)

		if res == "quit" {
			break
		}
	}
}

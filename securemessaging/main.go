package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/mdns"
	"github.com/likexian/selfca"
)

type chatRequest struct {
	IP   net.IP
	User string
}

type HostID struct {
	Hostname string
	ID       string
}

// structure to hold open TLS connections
type TLSConnectionStore struct {
	connections  map[string]*ConnectionInfo
	TLStoreMutex sync.Mutex
}

// structure to hold the writer and request associated to a TLS connection
type ConnectionInfo struct {
	cert       *x509.Certificate
	conn       *tls.Conn
	active     bool
	InboxMutex sync.Mutex
}

// initialize the store
func NewTLSConnectionStore() *TLSConnectionStore {
	return &TLSConnectionStore{
		connections: make(map[string]*ConnectionInfo),
	}
}

// add a connection to the store
func (s *TLSConnectionStore) Add(id string, info *ConnectionInfo) {
	s.TLStoreMutex.Lock()
	defer s.TLStoreMutex.Unlock()
	s.connections[id] = info
}

// remove a connection from the store
func (s *TLSConnectionStore) Remove(id string) {
	s.TLStoreMutex.Lock()
	defer s.TLStoreMutex.Unlock()
	delete(s.connections, id)
}

// declare the store as global variable
var (
	store *TLSConnectionStore
)

// to add hostids to the hostids file
var (
	addHostIdMutex sync.Mutex
)

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

	fmt.Printf("\nUsers to connect with: \n")
	mdns.Query(params)

	time.Sleep(5 * time.Second)

	print_nice_columns(discovered)

	return discovered
}

func initiate_chat() {

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
				fmt.Println("\nrefreshing available users")
			} else if strings.ToLower(input) == "back" {
				fmt.Println("\ngoing back to main screen")
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
					host := selectedEntry.Host[:len(selectedEntry.Host)-1]
					selection := chatRequest{IP: selectedEntry.AddrV4, User: host}

					peerSelectionChan <- selection
					<-pauseDiscoveryChan
				}
			}
		}
	}()

	for {
		select {
		case selection := <-peerSelectionChan:

			fmt.Println("\nYou have selected a user")
			dstHostID, err := setup_chat_with(selection)
			if err != nil {
				fmt.Printf("could not complete initial setup with %s: %v", selection.User, err)
				pauseDiscoveryChan <- struct{}{}
				continue
			}

			fmt.Printf("You have completed the initial setup with %s!\n", dstHostID.Hostname)

			err = establish_tls_chat(dstHostID, selection.IP)
			if err != nil {
				fmt.Printf("error establishing secure connection: %v", err)
				pauseDiscoveryChan <- struct{}{}
				continue
			}

			pauseDiscoveryChan <- struct{}{}
		case <-quitChan:

			return
		}

	}
}

func setup_chat_with(selection chatRequest) (HostID, error) {
	// create HostID of destination user
	var dstHostID HostID

	destination := selection.IP.String() + ":" + "7777"
	serverAddr, err := net.ResolveTCPAddr("tcp", destination)
	if err != nil {
		return dstHostID, fmt.Errorf("could not resolve address: %v", err)
	}
	conn, err := net.DialTCP("tcp", nil, serverAddr)
	if err != nil {
		return dstHostID, fmt.Errorf("could not create connection: %v", err)
	}

	//fmt.Printf("The connection was successful\n")

	// get own id to send over connection
	myId, _ := get_id()

	// write own id to connection
	conn.Write([]byte(myId))

	//fmt.Printf("Successfully wrote id to connection\n")

	// read from connection
	buffer := make([]byte, 2048)
	n, _ := conn.Read(buffer)

	response := buffer[:n]

	// check if it is a certificate
	block, _ := pem.Decode(response)

	if block == nil { // if it is not a certificate then it is an id
		clientId := string(response)

		// check if it is a valid id (at least 4 digits long)
		if len(clientId) < 4 {
			return dstHostID, fmt.Errorf("the provided id is too short")
		}

		// double check whether the user is in your contacts
		// if found, match will be the HostID of the contact
		// selection.dstUser is the advertised hostname from mdns
		found, dstHostID, err := check_contact(clientId)
		if err != nil {
			return dstHostID, fmt.Errorf("error while checking for contact existence: %v", err)
		}

		if found && dstHostID.Hostname == selection.User { // we found the id in our contacts and they have the correct host name
			// return the dstHostID, no errors occurred
			return dstHostID, nil

		} else if found && dstHostID.Hostname != selection.User { // we found the id in our contacts and they have a different host name
			fmt.Printf("dstUser: %s\nmatch.Hostname: %s\n", selection.IP, dstHostID.Hostname)
			return dstHostID, fmt.Errorf("the id provided belongs to a different user")

		} else { // we did not find the id in our contacts, yet the dest user already has our id
			return dstHostID, fmt.Errorf("the id was not found in your contacts, another user may be using your id")
		}

	} else { // if it is a certificate then add the user to contacts and send back own certificate
		// add the user to contacts
		dstHostID, err := add_new_contact(block)
		if err != nil {
			return dstHostID, fmt.Errorf("error adding new contact: %v", err)
		}

		// send own certificate over the connection
		// get own certificate
		cert, err := os.ReadFile("my.crt")
		if err != nil {
			return dstHostID, fmt.Errorf("error occurred while reading own cert from file: %v", err)
		}

		// write own certificate to connection
		_, err = conn.Write([]byte(cert))
		if err != nil {
			return dstHostID, fmt.Errorf("error occurred while writing own cert to connection: %v", err)
		}

		// return the dstHostID, no errors occurred
		return dstHostID, nil
	}
}

func tcp_connection_handler(conn net.Conn) {

	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		conn.Close()
		return
	}

	message := buffer[:n]

	yourId := string(message)

	if len(yourId) < 4 {
		fmt.Printf("Invalid id")
		conn.Close()
		return
	}

	//fmt.Printf("receieved request from id %s\n", yourId)

	// check whether the user is in your contacts
	found, _, err := check_contact(yourId)
	if err != nil {
		fmt.Printf("error occurred while checking for contact existenct: %v", err)
		conn.Close()
		return
	}

	if found { // if so then send your own id
		myId, err := get_id()
		if err != nil {
			conn.Close()
			return
		}

		// send my id over the connection
		_, err = conn.Write([]byte(myId))
		if err != nil {
			fmt.Printf("error occurred while writing own id to connection: %v", myId)
			conn.Close()
			return
		}
	} else { // otherwise exchange certificates with user
		// get own certificate
		cert, err := os.ReadFile("my.crt")
		if err != nil {
			fmt.Printf("error occurred while reading own cert from file: %v", err)
			conn.Close()
			return
		}

		// write own certificate to connection
		_, err = conn.Write([]byte(cert))
		if err != nil {
			fmt.Printf("error occurred while writing own cert to connection: %v", err)
			conn.Close()
			return
		}

		// read clients certificate from connection
		buffer := make([]byte, 2048)
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Printf("error occurred while reading client certificate from buffer")
			conn.Close()
			return
		}

		clientCert := buffer[:n]
		// check if it is a certificate
		block, _ := pem.Decode(clientCert)
		if block != nil {
			_, err := add_new_contact(block)
			if err != nil {
				conn.Close()
				return
			}
		}
	}
}

// Handle incoming connections from other users
func tls_connection_handler(conn *tls.Conn) {

	// get the connection state
	state := conn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		fmt.Printf("no peer certificate\n")
	}

	// get the client certificate
	clientCert := state.PeerCertificates[0]

	// extract the host name from the certificate
	hostName := clientCert.Subject.CommonName

	// extract the id from the certificate
	id := clientCert.DNSNames[0]

	// construct the user id
	username := hostName + "#" + id[len(id)-4:]

	// open the correct inbox file
	inboxPath := filepath.Join("inbox", id+".txt")
	file, err := os.Create(inboxPath)
	if err != nil {
		fmt.Printf("failed to open the inbox file: %v", err)
	}

	// create connection to add to the store
	connection := ConnectionInfo{
		cert:   clientCert,
		conn:   conn,
		active: false,
	}

	// add connection to the store
	store.Add(id, &connection)

	// persistently read messages from the connection and write them to the inbox
	for {
		buffer := make([]byte, 1024)

		n, err := conn.Read(buffer)
		if err != nil {
			break
		}

		if connection.active {
			fmt.Printf("\n%s: %s\nMe: ", username, string(buffer[:n]))
		}

		err = write_to_inbox(file, username, string(buffer[:n]), &connection.InboxMutex)
		if err != nil {
			fmt.Printf("error while writing the incoming message to inbox: %v", err)
		}
	}

	store.Remove(id)
}

func establish_tls_chat(userID HostID, ip net.IP) error {

	// initialize the *tls.Conn
	var conn *tls.Conn

	// boolean for whether the connection was in the store
	found := false

	// inboxMutex mutex lock
	var inboxMutex *sync.Mutex

	// active bool
	var active *bool

	// check whether a connection already exists with the user
	store.TLStoreMutex.Lock()
	for idKey := range store.connections {
		if idKey == userID.ID { // there is already an existing connection with the user, being handled by a tls_connection_handler routine

			fmt.Print("An open connection with the user was found, getting details from store\n")

			conn = store.connections[idKey].conn

			// get the request and check whether it is a certificate for that user
			cert := store.connections[idKey].cert
			if cert.DNSNames[0] != userID.ID {
				return fmt.Errorf("the certificate used to authenticate did not belong to the identity that the user identified itself as")
			}

			// get the inboxMutex
			inboxMutex = &store.connections[idKey].InboxMutex // assign the mutex lock associated to this connections inbox to the initalized variable
			found = true                                      // the connection was found within the store

			// set the active bool to true so the tls connection handler prints the messages
			active = &store.connections[idKey].active
			*active = true

			break
		}
	}
	store.TLStoreMutex.Unlock() // unlock the store mutex

	// open the correct inbox file
	inboxPath := filepath.Join("inbox", userID.ID+".txt")
	file, err := os.Create(inboxPath)
	if err != nil {
		return fmt.Errorf("failed to open the inbox file: %v", err)
	}

	// construct the user id
	username := userID.Hostname + "#" + userID.ID[len(userID.ID)-4:]

	// make a new connection or use the connection assigned to conn
	if !found { // if an open connection does not exist with the user, create one
		cert, err := tls.LoadX509KeyPair("my.crt", "my.key")
		if err != nil {
			return fmt.Errorf("failed to load server certificate and key: %v", err)
		}

		config := &tls.Config{
			Certificates:          []tls.Certificate{cert},
			VerifyPeerCertificate: verify_peer_cert,
			InsecureSkipVerify:    true,
		}

		destination := ip.String() + ":6969"

		conn, err = tls.Dial("tcp", destination, config)
		if err != nil {
			return fmt.Errorf("connection failed: %v", err)
		}

		err = conn.Handshake()
		if err != nil {
			return fmt.Errorf("tls handshake failed: %v", err)
		}

		fmt.Printf("the tls connection was successful\n")

		// handle incoming and outgoing messages

		// go routine to read incoming messages

		// make mutex to synchronize incoming vs outgoing messages
		inboxMutex = new(sync.Mutex)

		go func(file *os.File, inboxMutex *sync.Mutex, username string, conn *tls.Conn) {
			for {
				buffer := make([]byte, 1024)

				n, err := conn.Read(buffer)
				if err != nil {
					if err == io.EOF {
						fmt.Printf("The user has closed the connection. You may now initiate a new connection.\n")
					} else {
						fmt.Printf("Error while reading from connection: %v\n", err)
					}
					break
				}

				err = write_to_inbox(file, "Me", string(buffer[:n]), inboxMutex)
				if err != nil {
					fmt.Printf("Error while writing inbound message to inbox: %v\n", err)
				}

				fmt.Printf("\n%s: %s\nMe: ", username, string(buffer[:n]))
			}
		}(file, inboxMutex, username, conn)

		// go routine for writing to connection

		// take input to write to the connection
		var input string
		// reader to take input
		scan := bufio.NewReader(os.Stdin)

		fmt.Printf("You are now chatting with %s. Enter $quit to quit.\n", username)

		for {
			fmt.Print("Me: ")

			// scan the input and trim newlines/whitespace
			input, err = scan.ReadString('\n')
			if err != nil {
				fmt.Printf("Error reading input: %v\n", err)
			}

			input = strings.TrimSpace(input)

			if strings.ToLower(input) != "$quit" {
				_, err := conn.Write([]byte(input))
				if err != nil {
					fmt.Printf("error writing to connection: %v\n", err)
					continue
				}

				err = write_to_inbox(file, username, input, inboxMutex)
				if err != nil {
					fmt.Printf("Error while writing outbound message to inbox: %v\n", err)
				}

			} else {
				conn.Close()
				break
			}
		}

	} else { // the connection already existed, so just handle outgoing messages
		// take input to write to the connection
		var input string
		fmt.Printf("You are now chatting with %s. Enter $quit to quit.\n", username)

		scan := bufio.NewReader(os.Stdin)

		for {
			fmt.Print("Me: ")

			// scan the input and trim newlines/whitespace
			input, err = scan.ReadString('\n')
			if err != nil {
				fmt.Printf("Error reading input: %v\n", err)
			}

			input = strings.TrimSpace(input)

			if strings.ToLower(input) != "$quit" {
				_, err := conn.Write([]byte(input))
				if err != nil {
					return fmt.Errorf("error writing to connection: %v", err)
				}

				write_to_inbox(file, username, input, inboxMutex)

			} else {
				// set the active bool back to false so the tls connection handler stops printing messages
				*active = false
				break
			}
		}
	}

	return nil
}

func verify_peer_cert(raw [][]byte, verifiedChains [][]*x509.Certificate) error {

	// check if certificates were provided
	if raw == nil {
		return fmt.Errorf("verification failed: no certificates provided")
	}

	certBytesPro := raw[0]

	// decode the block
	block1, _ := pem.Decode(certBytesPro)
	if block1 != nil {
		return fmt.Errorf("verification failed: unable to decode certificate")
	}

	cert1, err := x509.ParseCertificate(certBytesPro)
	if err != nil {
		return fmt.Errorf("verification failed: unable to parse certificate: %v", err)
	}

	// extract the id and host from the certificate
	id := cert1.DNSNames[0]

	host := cert1.Subject.CommonName

	//fmt.Printf("verifying peer certificate: \ncertificate id: %s\ncertificate host: %s\n", id, host)

	// look for matches of the id in the hostids file
	found, pair, err := check_contact(id)
	if err != nil {
		return fmt.Errorf("verification failed: error while checking hostid file: %v", err)
	}

	if found { // the id was found within our contacts

		if pair.Hostname != host { // the host in the certificate did not match the host in our contacts
			return fmt.Errorf("verification failed: the claimed id on the certificate belonged to a host not matching the certificate host")
		}

		// retrieve the matching certificate in the contacts file and check for equality
		files, err := os.ReadDir("contacts")
		if err != nil {
			log.Fatalf("Failed to read contacts directory: %v", err)
		}

		for _, file := range files {
			if id == file.Name()[:len(file.Name())-4] {

				// read the certificate to compare from the file
				certBytes, err := os.ReadFile(filepath.Join("contacts", file.Name()))
				if err != nil {
					return fmt.Errorf("verification failed: failed to read certificate from matching file %s: %v", file.Name(), err)
				}

				block2, _ := pem.Decode(certBytes)
				if block2 == nil {
					return fmt.Errorf("verification failed: failed to decode the retrieved certificate")
				}
				cert2, err := x509.ParseCertificate(block2.Bytes)
				if err != nil {
					return fmt.Errorf("verification failed: failed to parse the retrieved certificate: %v", err)
				}

				if !reflect.DeepEqual(cert1.PublicKey, cert2.PublicKey) {
					return fmt.Errorf("verification failed: the certificate corresponding to the id was not equal to the provided certificate")
				}
			}
		}
	} else {
		return fmt.Errorf("verification failed: the id was not found in hostids")
	}

	return nil
}

func write_to_inbox(file *os.File, username string, message string, inboxMutex *sync.Mutex) error {
	inboxMutex.Lock()
	defer inboxMutex.Unlock()

	_, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("error seeking to end of file: %v", err)
	}

	if _, err := file.Write([]byte(username + ": " + message + "\n")); err != nil {
		return fmt.Errorf("failed to write the message to the file")
	}
	return nil
}

func check_contact(checkID string) (bool, HostID, error) {
	var match HostID
	found := false

	file, err := os.Open("hostids.txt")
	if err != nil {
		return false, match, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	//fmt.Printf("Checking the contact file\n")
	for scanner.Scan() {
		line := scanner.Text()

		parts := strings.Fields(line)
		hostname := parts[0]
		id := parts[1]

		// Process the hostname and ID pair
		//fmt.Printf("Hostname: %s, ID: %s\n", hostname, id)
		if checkID == id {
			//fmt.Printf("Match found\n")
			match.Hostname = hostname
			match.ID = id
			found = true
			break
		}
	}

	// Check for errors during scanning
	if err := scanner.Err(); err != nil {
		return false, match, fmt.Errorf("error scanning file: %v", err)
	}

	if found {
		return true, match, nil
	} else {
		return false, match, nil
	}
}

func add_new_contact(block *pem.Block) (HostID, error) {
	// create HostID to hold the passed certificates contact
	var pair HostID

	// parse the certiicate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return pair, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// extract the host name from the certificate
	hostName := cert.Subject.CommonName

	// extract the id from the certificate
	id := cert.DNSNames[0]

	//fmt.Printf("You have added user with id %s\n", id)

	// lock the host id file
	addHostIdMutex.Lock()

	pair = HostID{Hostname: hostName, ID: id}

	// write the HostID pair to the hostids file
	file, err := os.Create("hostids.txt")
	if err != nil {
		return pair, fmt.Errorf("error opening hostids file: %v", err)
	}

	_, err = file.Seek(0, io.SeekEnd)
	if err != nil {
		return pair, fmt.Errorf("error seeking end of hostids file: %v", err)
	}

	if _, err = file.Write([]byte(hostName + " " + id)); err != nil {
		return pair, fmt.Errorf("error writing contact to file: %v", err)
	}

	// unlock the host id file
	addHostIdMutex.Unlock()

	// create inbox entry
	inboxPath := filepath.Join("inbox", id+".txt")

	_, err = os.Create(inboxPath)
	if err != nil {
		return pair, fmt.Errorf("failed to create inbox file")
	}

	// write the contact to the certificate directory
	contactPath := filepath.Join("contacts", id+".crt")

	err = os.WriteFile(contactPath, pem.EncodeToMemory(block), 0644)
	if err != nil {
		return pair, fmt.Errorf("failed to add new contact to contacts: %v", err)
	}

	return pair, nil
}

func get_id() (string, error) {
	// read the unique id
	file, err := os.Open("id.txt")
	if err != nil {
		return "nil", fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var id string
	for scanner.Scan() {
		_, err := fmt.Sscanf(scanner.Text(), "%s", &id)
		if err != nil {
			return "nil", fmt.Errorf("error reading id: %v", err)
		}
		break
	}

	return id, nil

}

func generate_identifier() error {
	file, err := os.Create("id.txt")
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	random := rand.Intn(999000)
	random = random + 1000

	_, err = fmt.Fprintf(file, "%d", random)
	if err != nil {
		return fmt.Errorf("error writing user id to file: %v", err)
	}

	return nil
}

// generate the self signed certificate
func generate_self_signed() error {
	name, _ := os.Hostname()

	// get id
	id, err := get_id()
	if err != nil {
		return fmt.Errorf("failed to get the id: %v", err)
	}

	config := selfca.Certificate{
		IsCA:       true,
		CommonName: name,
		Hosts:      []string{id},
		NotBefore:  time.Now(),
		NotAfter:   time.Now().Add(time.Duration(365*24) * time.Hour),
	}

	certificate, key, err := selfca.GenerateCertificate(config)
	if err != nil {
		return fmt.Errorf("the certificate failed to generate: %v", err)
	}

	err = selfca.WriteCertificate("my", certificate, key)
	if err != nil {
		return fmt.Errorf("failed to write the certificate: %v", err)
	}

	return nil
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

	// generate unique identifier if not exists
	_, err := os.Stat("id.txt")
	if os.IsNotExist(err) {
		err = generate_identifier()
		if err != nil {
			log.Fatalf("failed to generate identifier: %v\n", err)
		}
	}

	// generate hostids.txt file
	if _, err := os.Stat("hostids.txt"); os.IsNotExist(err) {
		_, err := os.Create("hostids.txt")
		if err != nil {
			log.Fatalf("failed to create hostids file: %v\n", err)
		}
	}

	// generate contacts directory
	if _, err := os.Stat("contacts"); os.IsNotExist(err) {
		err := os.Mkdir("contacts", 0755)
		if err != nil {
			log.Fatalf("failed to create contacts directory: %v", err)
		}
	}

	// generate inbox directory
	if _, err := os.Stat("inbox"); os.IsNotExist(err) {
		err := os.Mkdir("inbox", 0755)
		if err != nil {
			log.Fatalf("failed to create inbox directory: %v", err)
		}
	}

	// setup http server for tls

	// initialize the tls connection store
	store = NewTLSConnectionStore()

	// generate self signed certificate if not already done
	_, err1 := os.Stat("my.crt")
	_, err2 := os.Stat("my.key")
	if err1 == nil && err2 == nil {

	} else if os.IsNotExist(err1) || os.IsNotExist(err2) {
		err = generate_self_signed()
		if err != nil {
			fmt.Printf("Failed to generate certificate: %v\n", err)
		}
	} else {
		fmt.Printf("Error checking for certificate existence\n")
	}

	cert, err := tls.LoadX509KeyPair("my.crt", "my.key")
	if err != nil {
		log.Fatalf("Failed to load server certificate and key: %v", err)
	}

	// configure the tls setup
	tlsConfig := &tls.Config{
		Certificates:          []tls.Certificate{cert},
		MinVersion:            tls.VersionTLS12,
		MaxVersion:            tls.VersionTLS13,
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verify_peer_cert,
	}

	// start the go routine for the tls server
	go func() {
		server, err := tls.Listen("tcp", ":6969", tlsConfig)
		if err != nil {
			log.Fatalf("tls server error: %v", err)
		}
		defer server.Close()

		for {
			conn, err := server.Accept()
			if err != nil {
				fmt.Printf("error accepting tls connection: %v", err)
				continue
			}

			tlsConn, ok := conn.(*tls.Conn)
			if !ok {
				fmt.Printf("error casting the net connection\n")
				continue
			}

			err = tlsConn.Handshake()
			if err != nil {
				fmt.Printf("tls handshake failed: %v", err)
				continue
			}

			go tls_connection_handler(tlsConn)
		}
	}()

	// start tcp server for certificate exchange

	go func() {
		tcpListener, err := net.Listen("tcp", ":7777")
		if err != nil {
			log.Fatalf("tcp server error: %v\n", err)
			return
		}
		defer tcpListener.Close()

		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				fmt.Printf("TCP connection error: %v\n", err)
				continue
			}

			// Handle TCP connection in a separate goroutine
			go tcp_connection_handler(conn)
		}
	}()

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

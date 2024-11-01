package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Generate RSA keys
func generateKeys() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Encrypt AES key with RSA public key
func encryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// Decrypt AES key with RSA private key
func decryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Generate AES key
func generateAESKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256 key
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Start Ngrok and return the public URL by querying Ngrok's API
func startNgrok() (string, error) {
	// Start ngrok process
	cmd := exec.Command("ngrok", "tcp", "5555")
	err := cmd.Start()
	if err != nil {
		return "", err
	}

	// Give ngrok time to start
	time.Sleep(2 * time.Second)

	// Fetch the public URL from Ngrok API
	url := "http://127.0.0.1:4040/api/tunnels"
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("error fetching ngrok URL: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	// Parse JSON to extract the public URL
	var ngrokData map[string]interface{}
	err = json.Unmarshal(body, &ngrokData)
	if err != nil {
		return "", fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	tunnels := ngrokData["tunnels"].([]interface{})
	if len(tunnels) == 0 {
		return "", fmt.Errorf("no active tunnels found")
	}

	// Extract the public URL from the first tunnel
	tunnel := tunnels[0].(map[string]interface{})
	publicURL := tunnel["public_url"].(string)

	return publicURL, nil
}

// Function to handle peer connection (server-side)
func handleConnection(conn net.Conn, privateKey *rsa.PrivateKey, roomCode, username string) {
	defer conn.Close()

	// Send the room code to the client for verification
	fmt.Println("Sending room code to client...")
	conn.Write([]byte(roomCode + "\n"))

	// Receive verification response from client
	reader := bufio.NewReader(conn)
	clientResponse, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading from client:", err)
		return
	}
	clientResponse = strings.TrimSpace(clientResponse)
	if clientResponse != "OK" {
		fmt.Println("Client failed room code verification.")
		return
	}

	// Send the server's public RSA key to the client
	encoder := gob.NewEncoder(conn)
	err = encoder.Encode(&privateKey.PublicKey)
	if err != nil {
		fmt.Println("Error sending public key:", err)
		return
	}

	// Receive the encrypted AES key length first
	var aesKeyLength uint32
	if err := binary.Read(conn, binary.LittleEndian, &aesKeyLength); err != nil {
		fmt.Println("Error reading AES key length:", err)
		return
	}

	// Now read the encrypted AES key based on the length
	encryptedAESKey := make([]byte, aesKeyLength)
	_, err = io.ReadFull(conn, encryptedAESKey)
	if err != nil {
		fmt.Println("Error reading AES key from client:", err)
		return
	}

	fmt.Println("Received encrypted AES key.")

	// Decrypt the AES key using the private RSA key
	aesKey, err := decryptWithPrivateKey(encryptedAESKey, privateKey)
	if err != nil {
		fmt.Println("Error decrypting AES key:", err)
		return
	}

	fmt.Println("Secure connection established with AES key.")

	// Handle encrypted messages from the client
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				fmt.Println("Connection closed.")
				return
			}
			encryptedMessage := string(buf[:n])
			decryptedMessage, err := decryptMessage(encryptedMessage, aesKey)
			if err != nil {
				fmt.Println("Error decrypting message:", err)
				continue
			}
			// Parse username and message
			receivedMessage := strings.SplitN(string(decryptedMessage), ": ", 2)
			if len(receivedMessage) == 2 {
				// Display the message from the client
				fmt.Printf("%s: %s\n", receivedMessage[0], receivedMessage[1])
			}
		}
	}()

	// Handle sending messages to the client
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("You: ")
		if !scanner.Scan() {
			break
		}
		message := scanner.Text()
		// Include the username when sending the message
		fullMessage := fmt.Sprintf("%s: %s", username, message)
		encryptedMessage, err := encryptMessage([]byte(fullMessage), aesKey)
		if err != nil {
			fmt.Println("Error encrypting message:", err)
			continue
		}
		conn.Write([]byte(encryptedMessage))
	}
}

// Client function to connect to peer
func connectToPeer(address, inputRoomCode, username string) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("Error connecting to peer:", err)
		return
	}
	defer conn.Close()

	// Receive the room code from the server
	reader := bufio.NewReader(conn)
	serverRoomCode, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading room code:", err)
		return
	}
	serverRoomCode = strings.TrimSpace(serverRoomCode)
	fmt.Println("Server room code received.")

	// Verify room code
	if serverRoomCode != inputRoomCode {
		fmt.Println("Invalid room code.")
		conn.Write([]byte("FAILED\n"))
		return
	}
	conn.Write([]byte("OK\n"))

	// Receive the server's public RSA key
	decoder := gob.NewDecoder(conn)
	var serverPublicKey rsa.PublicKey
	err = decoder.Decode(&serverPublicKey)
	if err != nil {
		fmt.Println("Error receiving public key:", err)
		return
	}

	// Generate the AES key and encrypt it with server's public key
	aesKey, _ := generateAESKey()
	encryptedAESKey, err := encryptWithPublicKey(aesKey, &serverPublicKey)
	if err != nil {
		fmt.Println("Error encrypting AES key:", err)
		return
	}

	// Send the length of the encrypted AES key first
	aesKeyLength := uint32(len(encryptedAESKey))
	if err := binary.Write(conn, binary.LittleEndian, aesKeyLength); err != nil {
		fmt.Println("Error sending AES key length:", err)
		return
	}

	// Send the encrypted AES key to the server
	conn.Write(encryptedAESKey)
	fmt.Println("Encrypted AES key sent to server.")

	// Handle receiving messages from the server
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				fmt.Println("Connection closed.")
				return
			}
			encryptedMessage := string(buf[:n])
			decryptedMessage, err := decryptMessage(encryptedMessage, aesKey)
			if err != nil {
				fmt.Println("Error decrypting message:", err)
				continue
			}
			// Parse username and message
			receivedMessage := strings.SplitN(string(decryptedMessage), ": ", 2)
			if len(receivedMessage) == 2 {
				// Display the message from the host
				fmt.Printf("%s: %s\n", receivedMessage[0], receivedMessage[1])
			}
		}
	}()

	// Handle sending messages to the server
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("You: ")
		if !scanner.Scan() {
			break
		}
		message := scanner.Text()
		// Include the username when sending the message
		fullMessage := fmt.Sprintf("%s: %s", username, message)
		encryptedMessage, err := encryptMessage([]byte(fullMessage), aesKey)
		if err != nil {
			fmt.Println("Error encrypting message:", err)
			continue
		}
		conn.Write([]byte(encryptedMessage))
	}
}

func main() {
	// Generate RSA keys for this peer
	privateKey, _ := generateKeys()

	// Generate temporary username
	username := generateUsername()

	// Generate random room code
	roomCode := "ABC123" // Example room code

	// Host or Join
	fmt.Println("Do you want to host a room or join a room? (host/join)")
	var choice string
	fmt.Scanln(&choice)

	if choice == "host" {
		// Host a room (server)
		ln, err := net.Listen("tcp", ":5555")
		if err != nil {
			fmt.Println("Error hosting room:", err)
			return
		}
		fmt.Println("Room hosted. Waiting for peers to join...")

		// Start Ngrok and get the public URL
		ngrokURL, err := startNgrok()
		if err != nil {
			fmt.Println("Error starting Ngrok:", err)
			return
		}
		fmt.Printf("Ngrok public URL: %s\n", ngrokURL)

		// Accept a peer connection
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			return
		}
		handleConnection(conn, privateKey, roomCode, username)
	} else if choice == "join" {
		// Join a room (client)
		fmt.Print("Enter the host Ngrok URL or IP address: ")
		var address string
		fmt.Scanln(&address)

		fmt.Print("Enter the room code: ")
		var inputRoomCode string
		fmt.Scanln(&inputRoomCode)

		connectToPeer(address+":5555", inputRoomCode, username)
	} else {
		fmt.Println("Invalid choice. Please choose 'host' or 'join'.")
	}
}

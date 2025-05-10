package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mdp/qrterminal"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
)

const secretFile = "secret.txt"

var usersSecrets = make(map[string]string)

// create or use existent Secret
// generate TOTP with the secret that we have
// Provision a TOTP key for user alice@google.com, to use with a service provided by Example, Inc: otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
// verify if the TOTP is valid

func main() {
	// -------------------------------------------- basic judgement
	// secret := getOrCreateSecret()            --- cautam si luam, sau generam, secretul user - ului
	// fmt.Println("Your secret key:", secret)  --- afisam secretul, pentru a ne verifica
	// generateTOTPWithSecret(secret)           --- generam Time-Based One-Time Password - ul pentru secretul user - ului AICI facem QR CODE - ul
	// verifyOTP(secret)                        --- verificam si validam logarea
	// --------------------------------------------

	if !fileExists(secretFile) {
		_, errs := os.Create(secretFile)
		if errs != nil {
			fmt.Println("Failed to create file:", errs)
			return
		}
	}

	loadDataFromFile(secretFile)

	var username string

	fmt.Printf("Type your username: ")
	_, err := fmt.Scanln(&username)
	if err != nil {
		fmt.Println("Error reading username from stdin:", err)
		os.Exit(1)
	}

	fmt.Printf("The username that has been read is: %s \n", username)

	secret := getOrCreateSecretForAUser(username)
	fmt.Println("Your secret key:", secret)

	generateTOTPWithSecret(secret, username)
	verifyOTP(secret, username)

}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func loadDataFromFile(filename string) {

	// if !fileExists(filename) {
	// 	fmt.Println("The file does not exist! (loadDataFromFile) \n")
	// 	return // No file to load
	// }
	// bonus check, because we have checked this in the main function, before anything else

	f, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening the file (loadDataFromFile): ", err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 2 {
			username := parts[0]
			secret := parts[1]
			usersSecrets[username] = secret
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading from the file (loadDataFromFile):", err)
		f.Close()
		os.Exit(1)
	}

	f.Close()
}

func getOrCreateSecretForAUser(username string) string {

	for name, secret := range usersSecrets {
		if name == username {
			fmt.Println("This user has been found! ")
			fmt.Printf("This user's secret is: %s \n", secret)

			return secret
		}
	}

	fmt.Println("This user has not been found! ")
	fmt.Println("We are generating a secret for him! ")

	// Generate and save a new secret if no existing one is found
	newSecret := gotp.RandomSecret(16)
	usersSecrets[username] = newSecret

	// Append to the secrets file
	f, err := os.OpenFile(secretFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Println("Error opening secret file for appending (getOrCreateSecretForAUser):", err)
		os.Exit(1)
	}

	if _, err := f.WriteString(fmt.Sprintf("%s %s\n", username, newSecret)); err != nil {
		fmt.Println("Error writing new secret to file (getOrCreateSecretForAUser):", err)
		f.Close()
		os.Exit(1)
	}

	f.Close()

	return newSecret
}

func generateTOTPWithSecret(secret string, accountName string) { // Time-Based One-Time Password
	issuer := "mySSCApp"

	uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, accountName, secret, issuer) // Uniform Resource Identifier
	fmt.Println("Scan this QR code if you haven't added it yet.")

	// Save QR code as a PNG file
	qrcode.WriteFile(uri, qrcode.Medium, 256, "qr.png")

	// Display QR Code in the terminal
	qrterminal.GenerateWithConfig(uri, qrterminal.Config{
		Level:     qrterminal.M,
		Writer:    os.Stdout,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
		QuietZone: 1,
	})

	fmt.Println("\nScan the QR code with your authenticator app OR use existing app to generate OTPs.")
}

func verifyOTP(secret string, username string) {
	totp := gotp.NewDefaultTOTP(secret)

	// Wait for user input
	fmt.Printf("Enter the OTP from your authenticator app, %s: ", username)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	userInput := scanner.Text()

	// Validate OTP
	if totp.Verify(userInput, time.Now().Unix()) {
		fmt.Println("✅ Authentication successful! Access granted.")
	} else {
		fmt.Println("❌ Authentication failed! Invalid OTP.")
	}
}

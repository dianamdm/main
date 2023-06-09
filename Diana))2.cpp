#include <iostream>
#include <string>
#include <openssl/sha.h>

// Function to calculate SHA-256 hash
std::string sha256(const std::string& str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.length());
    SHA256_Final(hash, &sha256);

    std::string hashedString;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        hashedString += hash[i];
    }

    return hashedString;
}

// Function for user sign-up
void signUp()
{
    std::string username, password;

    std::cout << "Enter username: ";
    std::cin >> username;
    std::cout << "Enter password: ";
    std::cin >> password;

    // Hash the password
    std::string hashedPassword = sha256(password);

    // Store the username and hashed password in a database or file
    // ... (implementation of storing the credentials)
    std::cout << "Sign-up successful!" << std::endl;
}

// Function for user sign-in
void signIn()
{
    std::string username, password;

    std::cout << "Enter username: ";
    std::cin >> username;
    std::cout << "Enter password: ";
    std::cin >> password;

    // Hash the entered password
    std::string hashedPassword = sha256(password);

    // Retrieve the stored hashed password for the given username from the database or file
    // ... (implementation of retrieving stored credentials)

    // Compare the entered hashed password with the stored hashed password
    // to determine if the sign-in is successful
    // ... (implementation of password comparison)

    if (hashedPassword == storedHashedPassword)
    {
        std::cout << "Sign-in successful!" << std::endl;
    }
    else
    {
        std::cout << "Invalid username or password." << std::endl;
    }
}

int main()
{
    int choice;
    std::cout << "1. Sign up" << std::endl;
    std::cout << "2. Sign in" << std::endl;
    std::cout << "Enter your choice: ";
    std::cin >> choice;

    if (choice == 1)
    {
        signUp();
    }
    else if (choice == 2)
    {
        signIn();
    }
    else
    {
        std::cout << "Invalid choice." << std::endl;
    }

    return 0;
}
    

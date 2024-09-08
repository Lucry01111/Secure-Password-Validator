#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#define NUM_COMMON_PASSWORDS 40
#define MIN_PASSWORD_LENGTH 8
#define MAX_PASSWORD_LENGTH 255
#define HASH_SIZE 101 // Size of the hash table; increase if needed

typedef struct Node {
    char password[MAX_PASSWORD_LENGTH + 1];
    struct Node* next;
} Node;

Node* hash_table[HASH_SIZE];

/* Hash function */
unsigned int hash(const char* str) {
    unsigned int hash = 0;
    while (*str) {
        hash = (hash * 31) + (unsigned char)*str++;
    }
    return hash % HASH_SIZE;
}

/* Insert a password into the hash table */
void insert_into_hash_table(const char* password) {
    unsigned int index = hash(password);
    Node* new_node = (Node*)malloc(sizeof(Node));
    if (!new_node) {
        exit(EXIT_FAILURE);
    }
    strcpy(new_node->password, password);
    new_node->next = hash_table[index];
    hash_table[index] = new_node;
}

/* Check if a password is in the hash table */
bool is_common_password(const char* password) {
    unsigned int index = hash(password);
    Node* current = hash_table[index];
    while (current) {
        if (strcmp(password, current->password) == 0) {
            return true;
        }
        current = current->next;
    }
    return false;
}

/* Check for lowercase letter */
bool has_lowercase(const char* password) {
    while (*password) {
        if (islower((unsigned char)*password)) return true;
        ++password;
    }
    return false;
}

/* Check for uppercase letter */
bool has_uppercase(const char* password) {
    while (*password) {
        if (isupper((unsigned char)*password)) return true;
        ++password;
    }
    return false;
}

/* Check for number */
bool has_number(const char* password) {
    while (*password) {
        if (isdigit((unsigned char)*password)) return true;
        ++password;
    }
    return false;
}

/* Check for special character */
bool has_special(const char* password) {
    while (*password) {
        if (!isalnum((unsigned char)*password)) return true;
        ++password;
    }
    return false;
}

/* Calculate password strength */
int password_strength(const char* password) {
    bool length_criteria = strlen(password) >= MIN_PASSWORD_LENGTH;
    bool criteria[5] = {
        length_criteria,
        has_lowercase(password),
        has_uppercase(password),
        has_number(password),
        has_special(password)
    };

    if (is_common_password(password)) {
        return 0; // Password is common, so strength score is 0
    }
    int score = 0;
    for (int i = 0; i < 5; ++i) {
        if (criteria[i]) ++score;
    }
    return score;
}

/* Suggest improvements based on criteria */
void suggest_improvements(const bool criteria[5]) {
    if (!criteria[0]) {
        printf("- Increase the length of the password to at least %d characters.\n", MIN_PASSWORD_LENGTH);
    }
    if (!criteria[1]) {
        printf("- Include at least one lowercase letter.\n");
    }
    if (!criteria[2]) {
        printf("- Include at least one uppercase letter.\n");
    }
    if (!criteria[3]) {
        printf("- Include at least one number.\n");
    }
    if (!criteria[4]) {
        printf("- Include at least one special character.\n");
    }
}

/* Free memory allocated for hash table */
void free_hash_table() {
    for (int i = 0; i < HASH_SIZE; ++i) {
        Node* current = hash_table[i];
        while (current) {
            Node* temp = current;
            current = current->next;
            free(temp);
        }
    }
}

int main() {
    // Initialize hash table
    memset(hash_table, 0, sizeof(hash_table));

    // Populate hash table with common passwords
    const char* common_passwords[NUM_COMMON_PASSWORDS] = {
        "12345", "1234", "1234567", "123456", "123456789", "111111", "admin", "admin123", "Password", "Pass@123", "password", "qwerty",
        "1q2w3e4r", "qwertyuiop", "abc123", "abcd1234", "welcome", "login", "letmein", "monkey", "123123", "qwert", "iloveyou",
        "123321", "1q2w3e4r5t", "123qwe", "admin1", "password1", "q1w2e3r4t5", "sunshine", "football", "princess", "dragon",
        "password123", "starwars", "1234qwer", "qwe123", "1q2w3e", "hello123", "welcome1", "abc12345", "qwerty123", "123qweas",
        "letmein123", "passw0rd", "qwerty1", "654321", "123456a", "password1234", "admin1234", "password12345", "letmein1", "pass123", "ciao"
    };

    // Insert common passwords into hash table
    for (int i = 0; i < NUM_COMMON_PASSWORDS; ++i) {
        insert_into_hash_table(common_passwords[i]);
    }

    char password[MAX_PASSWORD_LENGTH + 1];
    printf("Enter your password: ");
    if (fgets(password, sizeof(password), stdin) == NULL) {
        return 1;
    }

    // Remove newline character if present
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
    }

    // Check for empty or overly long password
    if (strlen(password) == 0) {
        return 1;
    }
    if (strlen(password) > MAX_PASSWORD_LENGTH) {
        return 1;
    }

    // Check if the password is common
    int score = password_strength(password);
    const char* strength;

    if (score == 0) {
        strength = "Very Weak, the password is commonly used, change it!"; // Since the score is 0
    } else if (score <= 2) {
        strength = "Weak";
    } else if (score <= 4) {
        strength = "Medium";
    } else {
        strength = "Strong";
    }

    printf("Password strength: %s (Score: %d/5)\n", strength, score);
    if (strcmp(strength, "Strong") != 0 || is_common_password(password)) {
        printf("\nSuggestions to improve your password:\n");
        bool criteria[5] = {
            strlen(password) >= MIN_PASSWORD_LENGTH,
            has_lowercase(password),
            has_uppercase(password),
            has_number(password),
            has_special(password)
        };
        suggest_improvements(criteria);
    } else {
        printf("Your password is strong!\n");
    }

    // Free hash table memory
    free_hash_table();
    return 0;
}

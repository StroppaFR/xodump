#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char password[20];
    printf("Enter password: ");
    fgets(password, 20, stdin);
    if (strcmp(password, "S3cr3tP4ssw0rd\n") == 0) {
        printf("Good password!\n");
    } else {
        printf("Wrong password!\n");
    }
    return 0;
}

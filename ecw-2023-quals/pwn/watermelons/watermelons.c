#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
    char watermelon[32];
    char recipient[16];
    unsigned int msg_size;
    char* msg;
} Gift;


char* watermelons[] = {
    "Classic Watermelon",
    "Seedless Watermelon",
    "Yellow Watermelon",
    "Sugar Baby Watermelon",
    "Mini Watermelon"
};

const char n_watermelons = 5;

char *watermelon_file = NULL;



void gift_watermelon(char *watermelon_name) {
    
    int choice;
    unsigned int msg_size;

    Gift* gift = (Gift *)malloc(sizeof(Gift));
    memset(gift, 0, sizeof(Gift));

    strncpy(gift->watermelon, watermelon_name, strlen(watermelon_name));

    printf("\nWe have three different sizes of envelopes for a custom message:\n");
    printf("1. Small (16 bytes)\n");
    printf("2. Medium (32 bytes)\n");
    printf("3. Large (64 bytes)\n\n");

    printf("Which one would you like? ");
    scanf("%d", &choice);
    getchar();

    if (choice < 1 || choice > 3) {
        printf("Invalid envelope choice!");
        free(gift);
        return;
    }

    msg_size = 16 * (1 << (choice - 1));
    gift->msg_size = msg_size;

    printf("Who's the lucky recipient of this watermelon? ");
    scanf("%16s", gift->recipient);
    getchar();

    gift->msg = (char *)malloc(gift->msg_size);
    memset(gift->msg, 0, gift->msg_size);

    printf("Enter your message: ");
    fread(gift->msg, 1, msg_size, stdin);

    printf("Thank you for your purchase. We will carefully transport your gift to %s!\n", gift->recipient);
    printf("Message: %.*s\n\n", gift->msg_size, gift->msg);

    free(gift->msg);
    free(gift);

}


void buy_watermelon() {
    
    int choice;

    printf("\nA wide variety of watermelons awaits you:\n");
    for (int i = 0; i < n_watermelons; i++) {
        printf("%d. %s\n", i + 1, watermelons[i]);
    }
    
    printf("\nEnter the number of the watermelon you want to buy: ");
    scanf("%d", &choice);
    getchar();

    if (choice < 1 || choice > n_watermelons) {
        printf("Invalid watermelon choice!\n");
        return;
    }

    printf("Would you like to make this a gift for someone? (y/n) ");

    int is_gift = getchar();
    getchar();

    if ((char)is_gift == 'y') {
        gift_watermelon(watermelons[choice - 1]);
    } else {
        printf("Thank you for purchasing a %s!\n\n", watermelons[choice - 1]);
    }

}


void show_watermelon() {

    FILE *fptr;
    int c;

    if (watermelon_file == NULL) {
        watermelon_file = (char *)malloc(32);
        strcpy(watermelon_file, "watermelon.txt");
    }

    fptr = fopen(watermelon_file, "r");
    if (!fptr) {
        printf("Problem opening watermelon file (%s)\n", watermelon_file);
        return;
    }

    while ((c = fgetc(fptr)) != EOF) {
        printf("%c", c);
    };
  
    fclose(fptr);

}


void exit_shop() {
    printf("Goodbye!\n");
    exit(0);
}


int main() {
    
    int choice;

    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    while (1) {

        printf("========== Romy's Watermelons ==========\n");
        printf(">>>> Welcome, traveler, to my shop! <<<<\n");
        printf("1. Buy a watermelon\n");
        printf("2. Show the latest watermelon\n");
        printf("3. Exit\n");
        printf("========================================\n");

        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar();

        switch (choice) {
            case 1:
                buy_watermelon();
                break;
            case 2:
                show_watermelon();
                break;
            case 3:
                exit_shop();
            default:
                printf("Invalid choice!\n");
        }

    }

    return 0;

}

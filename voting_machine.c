#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define MAX_VOTERS_LIST 100
#define MAX_CAND 10

struct voter
{
    int id;
    char name[50];
    char pin[10];
    int hasvoted;
};

struct candidate
{
    int id;
    char name[50];
    char party[50];
    int votes;
};

struct voter voters[MAX_VOTERS_LIST];
struct candidate candidates[MAX_CAND];
int votercount = 0, candidatecount = 0;

void clearInputBuffer()
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void clearscreen()
{
    #ifdef _WIN32
        system("cls");
    #else
        system("clear");
    #endif
}

void pause()
{
    printf("\nPress Enter to continue.....");
    clearInputBuffer();
}

int calculatechecksum(char str[])
{
    int sum = 0, i = 0;
    while (str[i] != '\0')
    {
        sum += str[i];
        i++;
    }
    return sum;
}

int pinExists(char *pin, int currentVoterId)
{
    int i;
    for (i = 0; i < votercount; i++)
    {
        if (voters[i].id != currentVoterId && strcmp(voters[i].pin, pin) == 0)
        {
            return 1;
        }
    }
    return 0;
}

int voterIdExists(int id)
{
    int i;
    for (i = 0; i < votercount; i++)
    {
        if (voters[i].id == id)
        {
            return 1;
        }
    }
    return 0;
}

int candidateIdExists(int id)
{
    int i;
    for (i = 0; i < candidatecount; i++)
    {
        if (candidates[i].id == id)
        {
            return 1;
        }
    }
    return 0;
}

void loadvoters()
{
    FILE *f = fopen("voters.txt", "r");
    if (f == NULL) return;

    char line[150];
    while (votercount < MAX_VOTERS_LIST && fgets(line, sizeof(line), f))
    {
        if (sscanf(line, "%d %49s %9s %d",
                &voters[votercount].id,
                voters[votercount].name,
                voters[votercount].pin,
                &voters[votercount].hasvoted) == 4)
        {
            votercount++;
        }
    }
    fclose(f);
}

void loadcandidates()
{
    FILE *f = fopen("candidates.txt", "r");
    if (f == NULL) return;

    char line[200];
    while (candidatecount < MAX_CAND && fgets(line, sizeof(line), f))
    {
        line[strcspn(line, "\n")] = '\0';

        char *token;
        char tempLine[200];
        strcpy(tempLine, line);

        token = strtok(tempLine, "|");
        if (token == NULL) continue;
        candidates[candidatecount].id = atoi(token);

        token = strtok(NULL, "|");
        if (token == NULL) continue;
        strncpy(candidates[candidatecount].name, token, 49);
        candidates[candidatecount].name[49] = '\0';

        token = strtok(NULL, "|");
        if (token == NULL) continue;
        strncpy(candidates[candidatecount].party, token, 49);
        candidates[candidatecount].party[49] = '\0';

        token = strtok(NULL, "|");
        if (token == NULL) continue;
        candidates[candidatecount].votes = atoi(token);

        candidatecount++;
    }
    fclose(f);
}

void savevoters()
{
    FILE *f = fopen("voters.txt", "w");
    if (f == NULL)
    {
        printf("Error: Could not save voter data!\n");
        return;
    }

    int i;
    for (i = 0; i < votercount; i++)
    {
        fprintf(f, "%d %s %s %d\n",
                voters[i].id,
                voters[i].name,
                voters[i].pin,
                voters[i].hasvoted);
    }
    fclose(f);
}

void savecandidates()
{
    FILE *f = fopen("candidates.txt", "w");
    if (f == NULL)
    {
        printf("Error: Could not save candidate data!\n");
        return;
    }

    int i;
    for (i = 0; i < candidatecount; i++)
    {
        fprintf(f, "%d|%s|%s|%d\n",
                candidates[i].id,
                candidates[i].name,
                candidates[i].party,
                candidates[i].votes);
    }
    fclose(f);
}

void logvote(int voterid, int candidateid)
{
    FILE *f = fopen("vote_log.txt", "a");
    if (f == NULL)
    {
        printf("Warning: Could not log vote!\n");
        return;
    }

    time_t now = time(NULL);
    char record[100];
    sprintf(record, "%d %d %ld", voterid, candidateid, now);
    int checksum = calculatechecksum(record);
    fprintf(f, "%s %d\n", record, checksum);
    fclose(f);
}

void logtamperattempt(int voterid, char *votername)
{
    FILE *f = fopen("tamper_log.txt", "a");
    if (f == NULL)
    {
        printf("Warning: Could not log tampering attempt!\n");
        return;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(f, "%d|%s|%02d-%02d-%04d|%02d:%02d:%02d\n",
            voterid, votername,
            t->tm_mday, t->tm_mon + 1, t->tm_year + 1900,
            t->tm_hour, t->tm_min, t->tm_sec);
    fclose(f);
}

void checktamper()
{
    FILE *f = fopen("vote_log.txt", "r");
    char line[100];
    int linenum = 0;
    int datatamperedcount = 0;

    printf("\n");
    printf("========================================\n");
    printf("    TAMPERING DETECTION REPORT\n");
    printf("========================================\n\n");

    if (f != NULL)
    {
        printf("--- Checking Vote Log for Data Tampering ---\n\n");
        while (fgets(line, sizeof(line), f))
        {
            linenum++;

            int voterid, candidateid, storedchecksum;
            long timestamp;

            char dataString[100];
            int n = sscanf(line, "%d %d %ld %d", &voterid, &candidateid, &timestamp, &storedchecksum);
            if (n != 4)
            {
                printf("!!! Invalid line format at line %d !!!\n\n", linenum);
                datatamperedcount++;
                continue;
            }

            sprintf(dataString, "%d %d %ld", voterid, candidateid, timestamp);

            int calculatedchecksum = calculatechecksum(dataString);

            if (calculatedchecksum != storedchecksum)
            {
                printf("!!! DATA TAMPERING DETECTED at line %d !!!\n", linenum);
                printf("    Voter ID: %d\n", voterid);
                printf("    Candidate ID: %d\n", candidateid);
                printf("    Stored Checksum: %d\n", storedchecksum);
                printf("    Calculated Checksum: %d\n", calculatedchecksum);

                time_t t = (time_t)timestamp;
                struct tm *tm_info = localtime(&t);
                printf("    Time of Vote: %02d-%02d-%04d %02d:%02d:%02d\n\n",
                       tm_info->tm_mday, tm_info->tm_mon + 1, tm_info->tm_year + 1900,
                       tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
                datatamperedcount++;
            }
        }
        fclose(f);

        if (linenum > 0 && datatamperedcount == 0)
        {
            printf("No data tampering detected in vote log.\n\n");
        }
    }
    else
    {
        printf("No vote log found.\n\n");
    }

    FILE *tf = fopen("tamper_log.txt", "r");
    int unauthorizedcount = 0;

    if (tf != NULL)
    {
        printf("--- Unauthorized Voting Attempts ---\n\n");

        while (fgets(line, sizeof(line), tf))
        {
            int voterid;
            char votername[50], date[20], time[20];

            if (sscanf(line, "%d|%49[^|]|%19[^|]|%19s", &voterid, votername, date, time) == 4)
            {
                unauthorizedcount++;
                printf("Attempt #%d:\n", unauthorizedcount);
                printf("  Voter ID   : %d\n", voterid);
                printf("  Name       : %s\n", votername);
                printf("  Date       : %s\n", date);
                printf("  Time       : %s\n\n", time);
            }
        }
        fclose(tf);

        if (unauthorizedcount == 0)
        {
            printf("No unauthorized voting attempts detected.\n\n");
        }
    }
    else
    {
        printf("--- Unauthorized Voting Attempts ---\n");
        printf("No unauthorized attempts detected.\n\n");
    }

    printf("========================================\n");
    printf("SUMMARY:\n");
    printf("  Data Tampering Cases    : %d\n", datatamperedcount);
    printf("  Unauthorized Attempts   : %d\n", unauthorizedcount);
    printf("  Total Security Issues   : %d\n", datatamperedcount + unauthorizedcount);
    printf("========================================\n");

    if (datatamperedcount + unauthorizedcount == 0)
    {
        printf("SYSTEM STATUS: SECURE ✓\n");
    }
    else
    {
        printf("SYSTEM STATUS: COMPROMISED ✗\n");
    }
    printf("========================================\n");
}

void viewResults()
{
    int i;
    printf("\n");
    printf("===============================================================\n");
    printf("                       VOTE RESULTS                            \n");
    printf("===============================================================\n");

    if (candidatecount == 0)
    {
        printf("No candidates found in the system.\n");
        printf("===============================================================\n");
        return;
    }

    printf("%-5s | %-25s | %-15s | %-8s\n", "ID", "Candidate Name", "Party", "Votes");
    printf("---------------------------------------------------------------\n");

    for (i = 0; i < candidatecount; i++)
    {
        printf("%-5d | %-25s | %-15s | %-8d\n",
               candidates[i].id,
               candidates[i].name,
               candidates[i].party,
               candidates[i].votes);
    }
    printf("===============================================================\n");
}

void showMaxVoted()
{
    if (candidatecount == 0)
    {
        printf("\nNo candidates found.\n");
        return;
    }

    int maxVotes = candidates[0].votes;
    int maxIndex = 0;
    int i;

    for (i = 1; i < candidatecount; i++)
    {
        if (candidates[i].votes > maxVotes)
        {
            maxVotes = candidates[i].votes;
            maxIndex = i;
        }
    }

    printf("\n");
    printf("===============================================================\n");
    printf("                   HIGHEST VOTED CANDIDATE                     \n");
    printf("===============================================================\n");
    printf("Candidate Name : %s\n", candidates[maxIndex].name);
    printf("Party          : %s\n", candidates[maxIndex].party);
    printf("Total Votes    : %d\n", candidates[maxIndex].votes);
    printf("===============================================================\n");
}

void showMinVoted()
{
    if (candidatecount == 0)
    {
        printf("\nNo candidates found.\n");
        return;
    }

    int minVotes = candidates[0].votes;
    int minIndex = 0;
    int i;

    for (i = 1; i < candidatecount; i++)
    {
        if (candidates[i].votes < minVotes)
        {
            minVotes = candidates[i].votes;
            minIndex = i;
        }
    }

    printf("\n");
    printf("===============================================================\n");
    printf("                   LOWEST VOTED CANDIDATE                      \n");
    printf("===============================================================\n");
    printf("Candidate Name : %s\n", candidates[minIndex].name);
    printf("Party          : %s\n", candidates[minIndex].party);
    printf("Total Votes    : %d\n", candidates[minIndex].votes);
    printf("===============================================================\n");
}

void adminpanel()
{
    int choice;
    do
    {
        clearscreen();
        printf("========================================\n");
        printf("           ADMIN PANEL                  \n");
        printf("========================================\n");
        printf("1. Add Voter\n");
        printf("2. Add Candidate\n");
        printf("3. View Results\n");
        printf("4. Check Tamper\n");
        printf("5. Highest Voted Candidate\n");
        printf("6. Lowest Voted Candidate\n");
        printf("0. Logout\n");
        printf("========================================\n");
        printf("Enter choice: ");

        if (scanf("%d", &choice) != 1)
        {
            clearInputBuffer();
            printf("\nInvalid input! Please enter a number.\n");
            pause();
            continue;
        }
        clearInputBuffer();

        if (choice == 1)
        {
            if (votercount >= MAX_VOTERS_LIST)
            {
                printf("\nVoter list is full! Cannot add more voters.\n");
                pause();
                continue;
            }

            struct voter v;
            printf("\n--- Add New Voter ---\n");
            printf("Enter Voter ID: ");

            if (scanf("%d", &v.id) != 1)
            {
                clearInputBuffer();
                printf("\nInvalid ID! Please enter a number.\n");
                pause();
                continue;
            }
            clearInputBuffer();

            if (voterIdExists(v.id))
            {
                printf("\n!!! ERROR: Voter ID already exists !!!\n");
                printf("Please use a different ID.\n");
                pause();
                continue;
            }

            printf("Enter Name: ");
            fgets(v.name, sizeof(v.name), stdin);
            v.name[strcspn(v.name, "\n")] = '\0';

            if (strlen(v.name) == 0)
            {
                printf("\nName cannot be empty!\n");
                pause();
                continue;
            }

            while (1)
            {
                printf("Enter PIN (4-9 digits): ");
                scanf("%s", v.pin);
                clearInputBuffer();

                if (strlen(v.pin) < 4 || strlen(v.pin) > 9)
                {
                    printf("\n!!! PIN must be 4-9 digits !!!\n\n");
                    continue;
                }

                if (pinExists(v.pin, -1))
                {
                    printf("\n!!! WARNING: This PIN already exists !!!\n");
                    printf("Please choose a different PIN.\n\n");
                }
                else
                {
                    break;
                }
            }

            v.hasvoted = 0;
            voters[votercount++] = v;
            savevoters();
            printf("\n✓ Voter added successfully!\n");
            pause();
        }
        else if (choice == 2)
        {
            if (candidatecount >= MAX_CAND)
            {
                printf("\nCandidate list is full! Cannot add more candidates.\n");
                pause();
                continue;
            }

            struct candidate c;
            printf("\n--- Add New Candidate ---\n");
            printf("Enter Candidate ID: ");

            if (scanf("%d", &c.id) != 1)
            {
                clearInputBuffer();
                printf("\nInvalid ID! Please enter a number.\n");
                pause();
                continue;
            }
            clearInputBuffer();

            if (candidateIdExists(c.id))
            {
                printf("\n!!! ERROR: Candidate ID already exists !!!\n");
                printf("Please use a different ID.\n");
                pause();
                continue;
            }

            printf("Enter Name: ");
            fgets(c.name, sizeof(c.name), stdin);
            c.name[strcspn(c.name, "\n")] = '\0';

            if (strlen(c.name) == 0)
            {
                printf("\nName cannot be empty!\n");
                pause();
                continue;
            }

            printf("Enter Party: ");
            fgets(c.party, sizeof(c.party), stdin);
            c.party[strcspn(c.party, "\n")] = '\0';

            if (strlen(c.party) == 0)
            {
                printf("\nParty cannot be empty!\n");
                pause();
                continue;
            }

            c.votes = 0;
            candidates[candidatecount++] = c;
            savecandidates();
            printf("\n✓ Candidate added successfully!\n");
            pause();
        }
        else if (choice == 3)
        {
            viewResults();
            pause();
        }
        else if (choice == 4)
        {
            checktamper();
            pause();
        }
        else if (choice == 5)
        {
            showMaxVoted();
            pause();
        }
        else if (choice == 6)
        {
            showMinVoted();
            pause();
        }
        else if (choice != 0)
        {
            printf("\nInvalid choice! Please try again.\n");
            pause();
        }
    }
    while (choice != 0);
}

void voterpanel()
{
    int id, i, j, cid;
    char pin[10];
    int found = 0;
    int voterIndex = -1;

    printf("\n--- Voter Login ---\n");
    printf("Enter Voter ID: ");

    if (scanf("%d", &id) != 1)
    {
        clearInputBuffer();
        printf("\nInvalid ID! Please enter a number.\n");
        pause();
        return;
    }
    clearInputBuffer();

    for (i = 0; i < votercount; i++)
    {
        if (voters[i].id == id)
        {
            found = 1;
            voterIndex = i;
            break;
        }
    }

    if (!found)
    {
        printf("\n✗ Voter ID not found!\n");
        printf("Your voter registration is still saved.\n");
        printf("Please check your ID and try again.\n");
        pause();
        return;
    }

    printf("Enter PIN: ");
    scanf("%s", pin);
    clearInputBuffer();

    if (strcmp(voters[voterIndex].pin, pin) == 0)
    {
        if (candidatecount == 0)
        {
            printf("\n✗ No candidates available for voting!\n");
            printf("Please contact admin to add candidates first.\n");
            pause();
            return;
        }

        if (voters[voterIndex].hasvoted)
        {
            printf("\n");
            printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
            printf("!!!   UNAUTHORIZED VOTING ATTEMPT   !!!\n");
            printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
            printf("\n✗ You have already cast your vote.\n");
            printf("This attempt has been logged for security.\n");
            printf("\nVoter ID: %d\n", voters[voterIndex].id);
            printf("Name: %s\n", voters[voterIndex].name);
            logtamperattempt(voters[voterIndex].id, voters[voterIndex].name);
            pause();
            return;
        }

        printf("\n===============================================\n");
        printf("            CANDIDATE LIST                     \n");
        printf("===============================================\n");
        for (j = 0; j < candidatecount; j++)
        {
            printf("%d. %s (%s)\n",
                   candidates[j].id,
                   candidates[j].name,
                   candidates[j].party);
        }
        printf("===============================================\n");
        printf("\nEnter Candidate ID to vote: ");

        if (scanf("%d", &cid) != 1)
        {
            clearInputBuffer();
            printf("\nInvalid input!\n");
            pause();
            return;
        }
        clearInputBuffer();

        for (j = 0; j < candidatecount; j++)
        {
            if (candidates[j].id == cid)
            {
                candidates[j].votes++;
                voters[voterIndex].hasvoted = 1;
                savecandidates();
                savevoters();
                logvote(id, cid);
                printf("\n");
                printf("*\n");
                printf("*     VOTE CAST SUCCESSFULLY!              *\n");
                printf("*\n");
                printf("\n✓ Thank you for voting!\n");
                printf("Your vote has been recorded securely.\n");
                pause();
                return;
            }
        }
        printf("\n✗ Invalid candidate ID!\n");
        pause();
        return;
    }
    else
    {
        printf("\n✗ Incorrect PIN!\n");
        printf("Your voter data is still saved.\n");
        printf("Please try again with correct PIN.\n");
        pause();
        return;
    }
}

int main()
{
    loadvoters();
    loadcandidates();
    int choice;

    do
    {
        clearscreen();
        printf("===============================================\n");
        printf("    Created By Team Binary Ballot          \n");
        printf("===============================================\n");
        printf("      DIGITAL VOTING MACHINE SYSTEM            \n");
        printf("===============================================\n");
        printf("\n");
        printf("1. Admin Login\n");
        printf("2. Voter Login\n");
        printf("0. Exit\n");
        printf("\n");
        printf("Enter choice: ");

        if (scanf("%d", &choice) != 1)
        {
            clearInputBuffer();
            printf("\nInvalid input! Please enter a number.\n");
            pause();
            continue;
        }
        clearInputBuffer();

        if (choice == 1)
        {
            char pass[20];
            printf("\nEnter admin password: ");
            scanf("%s", pass);
            clearInputBuffer();

            if (strcmp(pass, "admin123") == 0)
            {
                adminpanel();
            }
            else
            {
                printf("\n✗ Incorrect password!\n");
                pause();
            }
        }
        else if (choice == 2)
        {
            voterpanel();
        }
        else if (choice != 0)
        {
            printf("\nInvalid choice! Please try again.\n");
            pause();
        }
    }
    while (choice != 0);

    printf("\n");
    printf("===============================================\n");
    printf("Thank you for using the voting system!\n");
    printf("===============================================\n");
    printf("\n");
    printf("Team Members:\n");
    printf("  - Anika Tabassom orin (322)\n");
    printf("  - Mostofa Sayaed Rizon (947)\n");
    printf("  - Sayed Assaduzzaman (955)\n");
    printf("  - Shahinur Alam Aorko (971)\n");
    printf("  - Soyaib Al Shifat (983)\n");
    printf("\n");
    printf("Stay Aware of Corruption.\n");
    printf("\n");
    printf("(c) 2025 Binary Ballot. All rights reserved.\n");
    printf("===============================================\n");

return 0;
}
// Adding code for voting system

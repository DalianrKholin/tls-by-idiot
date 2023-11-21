//
// Created by osado on 17.11.2023.
//
#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#define MAX 65535
#define PORT 7777
#define SA struct sockaddr

volatile int32_t counter = 0;
int sockfd;
int32_t mapPidFd[10][3];


int8_t len(const char tab[]){
    int8_t res = 0;
    for (int8_t i = 0;; i++,res++) {
        if (tab[i]=='\0'){
            return res;
        }
    }
}
/*
 * obracanie słowa
 * */
char* wspakFunc(char tab[]){
    char *res = (char*)malloc(MAX* sizeof(char ));
    int8_t ln= len(tab);
    int8_t resT= ln;
    for (int8_t i = 0; i <= ln; ++i) {
        res[ln-1-i]= tab[i];
    }
    res[resT]='\r';
    res[resT+1]='\n';
    res[resT+2]='\0';
    return res;
}

/*
 * nasza main funkcja wspak
 * */
void func(SSL* cert)
{
    char buff[MAX];
    char response[MAX];
    for (;;) {
        bzero(buff, MAX);
        SSL_read(cert, buff, sizeof(buff));
        char* pog = wspakFunc(buff);
        printf("%s\n",pog);
        strcpy(response, pog);
        SSL_write(cert, response, len(response));
        if (strncmp("exit", buff, 4) == 0) {
            return;
        }
    }
}

void makeNewClient(pid_t pid, int32_t connfd){
    for (int i = 0; i < 10; ++i) {
        if(mapPidFd[i][2]==0){
            mapPidFd[i][0]=pid;
            mapPidFd[i][1]=connfd;
            mapPidFd[i][2]=1;
            counter++;
            return;
        }
    }
}

/*
 * proces który umiera wysyła nam SIGUSR1, teraz chcemy pogrzebać nasz proces który umarł,a następnie ze struktóry
 * sygnału wyciągamy jaki był pid procesu który i z wcześniej stworzonej tablicy, gdzie mamy zmapowany pid->fileDescryptor
 * zamykamy ten deskryptor
 * jeżeli nie ma już podprocesów, czytaj klientów serrwera, to zamykamy socket oraz kończymy działanie serwera
 * */
void sigUsr(int signo, siginfo_t *info, void *context) {
    counter--;
    wait(NULL);
    for (int i= 0; i< 10;i++){
        if(mapPidFd[i][0]==info->si_pid && mapPidFd[i][2]==1){
            close(mapPidFd[i][1]);
            mapPidFd[i][2]=0;
        }
    }
    if (counter==0){
        close(sockfd);
        exit(0);
    }
}

/*obsługa ssl*/
SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}
void configure_context(SSL_CTX *ctx)
{
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}
/*obsługa ssl*/
//openssl genpkey -algorithm rsa -out key.pem nowy klucz
//openssl req -new -key key.pem -x509 -days 365 -out cert.pem nowy certyfikat
/*czyszczenie wszystkich połączeń dla procesu*/
void closeConn(struct ssl_st* ssl, int connfd){
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(connfd);
    pid_t parent_pid = getppid();
    if (kill(parent_pid, SIGUSR1) == -1) {
        perror("cant send SIGUSR1");
        exit(EXIT_FAILURE);
    }

    exit(0);
}
int main(){
    struct sockaddr_in  servaddr;
    struct sigaction sa; //akcja na sigusr1
    sa.sa_sigaction = sigUsr;
    if (sigaction(SIGUSR1,&sa,NULL) == -1) {
        perror("signal error\n");
        exit(EXIT_FAILURE);
    }
    SSL_CTX *ctx = create_context();
    configure_context(ctx);
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        printf("socket bind failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully binded..\n");

    while (1){
        unsigned int length;
        struct sockaddr_in  cli;
        int connfd;
        const char reply[] = "test\n";

        if ((listen(sockfd, 10)) != 0) { // n - oznacza liczbę możliwych połączeń w kolejce
            printf("Listen failed...\n");
            exit(0);
        }
        else{ printf("Server listening..\n");}
        length = sizeof(cli);
        connfd = accept(sockfd, (SA *) &cli, &length);
        pid_t pid;


        if ((pid = fork())==0){
            if (connfd < 0) {
                printf("server accept failed...\n");
                exit(0);
            } else{
                printf("server accept the client...\n");
            }

            SSL *ssl= SSL_new(ctx);
            SSL_set_fd(ssl, connfd);

            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                printf("sie nie udalo sie\n");
                closeConn(ssl,connfd);
            } else {
                SSL_write(ssl, reply, strlen(reply));
            }
            func(ssl);
            closeConn(ssl,connfd);
        }
        if (connfd>0){
            makeNewClient(pid,connfd);
        }
    }
}













/*
 * */









#include <iostream>
#include <iostream>
#include <fstream>

#include <openssl/rand.h>	//RAND Library
#include <openssl/ssl.h>	//SSL Library
#include <openssl/bio.h>	//BIO Library
#include <openssl/err.h>	//ERROR Library
#include <openssl/sha.h>

#define BUFFER_SIZE 256

using namespace std;

void errors()
{
    char buf[BUFFER_SIZE];
    int err;
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        printf("*** %s\n", buf);
    }
}

void pause(int duration)
{
	int temp = time(NULL) + duration;
	while(temp > time(NULL));
}

//Outputs the HEX values of the buffer
string buff2hex(const unsigned char* buff, const int len)
{
    string s = "";
    for(uint i = 0; i < len; i++)
    {
        char temp[EVP_MAX_MD_SIZE];
        sprintf(temp, "%02x", buff[i] & 0xFF);
        s += temp;
    }
    return s;
}

void Send_file(SSL* ssl, RSA* rsaPrivateKey, BIO* server, char* fileName)
{

    
    BIO* g= BIO_new_file("rsaprivatekey.pem","r");
    BIO* read_file= BIO_new_file(fileName,"r");
    if(!read_file)
    {
        cout << endl << "ERROR: NO FILE FOUND" << endl;
        
        string error= "File not Found";
        SSL_write(ssl, error.c_str(), 128);
        SSL_shutdown(ssl);
        exit(EXIT_FAILURE);
    }
    
    //BIO object that holds the filename
    BIO* fileRead = BIO_new_file(fileName, "r");
    //encrypt file and send to client
    int bytesRead = 1;
    int bytesSent = 0;
    while( bytesRead > 0 )
    {
        //storing text
        int maxLineSize = RSA_size(rsaPrivateKey) - 11;
        char lineRead[maxLineSize];
        memset(lineRead, 0, maxLineSize);
        
        //record number of bytes
        bytesRead = BIO_gets(fileRead, lineRead, maxLineSize);
        
        //store encrypted text
        char encryptedLine[bytesRead];
        memset(encryptedLine, 0, bytesRead);
        
        //encrypt line and store result
        int encLineSize = RSA_private_encrypt(bytesRead, (const unsigned char*) 					(lineRead), (unsigned char*) encryptedLine, 						rsaPrivateKey, RSA_PKCS1_PADDING);
        
        //check for errors
        if( encLineSize == -1 )
        {
            errors();
            SSL_shutdown(ssl);
            exit(EXIT_FAILURE);
        }
        
        //ssl_write to client and save bytesSent
        int temp = SSL_write(ssl, encryptedLine, encLineSize);
        BIO_flush(server);
        bytesSent += temp;
        
    }
    
    
}


void receive_file(SSL* ssl, char* filename)
{
    
    char fileOutput[128];
    BIO *output_file= BIO_new_file(filename,"w");
    
    char encryptedFileOutput[128];
    
    int actual_read = 0;
    while((actual_read=SSL_read(ssl,encryptedFileOutput,128))>1)
    {
        string s = encryptedFileOutput;
        if(s=="File not Found")
        {
            cout << endl << "ERROR: FILE NOT FOUND" << endl;
            SSL_shutdown(ssl);
            exit(EXIT_FAILURE);
        }
        
        BIO *rsaPublicKeyfile2 = BIO_new_file("rsapublickey.pem","r");
        RSA *rsapub = PEM_read_bio_RSA_PUBKEY(rsaPublicKeyfile2, NULL, NULL, NULL );
        
        int rsaDecryptedFile = RSA_public_decrypt(128,(unsigned char *) encryptedFileOutput, (unsigned char*)fileOutput,rsapub,RSA_PKCS1_PADDING);
        errors();
        BIO_write(output_file,fileOutput,rsaDecryptedFile);
    }
}

//your_client_app_name -server serveraddress(2) -port portnumber(4) action(5) filename(6)
int main(int argc, char *argv[])
{
	SSL_library_init();
	ERR_load_crypto_strings();
    SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	if(argc != 7)
	{
		cout << endl << "INCORRECT PARAMETERS!!!" << endl;
		cout << "CORRECT PARAMETERS: a.out -server serveraddress -port portnumber filename" << endl;
		cout << "PLEASE TRY AGAIN!!" << endl << endl;
		return 0;
	}

	//Storing Passed In Arguments
	string server = argv[2];
	string port = argv[4];
    string action = argv[5];
    
	string string_serverinfo = server + ":" + port;

	char* serverinfo = new char[string_serverinfo.length()+1];
	strcpy(serverinfo,string_serverinfo.c_str());

	//1. Establish an SSL connection with the server.
	cout << endl << "ESTABLISHING CONNECTION WITH SERVER" << endl;

	//Create SSL Context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);	//Given from assignment instructions
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		cout << endl << "ERROR: COULD NOT CREATE SSL CONTEXT" << endl;
		errors();
		exit(EXIT_FAILURE);
	}

	//Create BIO object
	BIO* client = BIO_new_connect(serverinfo);
	if (BIO_do_connect(client) != 1)
	{
		cout << endl << "ERROR: COULD NOT CONNECT TO SERVER" << endl;
		errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
	SSL* ssl=SSL_new(ctx);
        if (!ssl)
        {
		cout << endl << "ERROR: COULD NOT CREATE SSL OBJECT" << endl;
		errors();
                exit( EXIT_FAILURE );
        }
	SSL_set_bio(ssl, client, client);
        if (SSL_connect( ssl ) <= 0)
        {
		cout << endl << "ERROR: COULD NOT CONNECT TO SSL" << endl;
		errors();
                exit(EXIT_FAILURE);
        }
    
	cout << endl << "CONNECTED TO: " << serverinfo << endl;

	//2. Seed a cryptographically secure PRNG and use it to generate a random number (challenge).
	cout << endl << "GENERATING CHALLENGE" << endl;

	//Creating random numbers (challenge)
	int randNumSize = 50;
	char randNum[randNumSize];
	if( RAND_bytes((unsigned char*)randNum,randNumSize) == -1 )
	{
		errors();
		exit(EXIT_FAILURE);
	}

	//Writing the Challenge
	int challengeSize = randNumSize;
	char challenge[challengeSize];
	memset(challenge, 0, challengeSize);
	for( int i = 0; i < randNumSize; i++)
	{
		challenge[i] = randNum[i];
	}

	//3. Encrypt the challenge using the server’s RSA public key, and send the encrypted challenge to the server.
	cout << endl << "ENCRYPT WITH PUBLIC KEY" << endl;

	//get the public key from file & storing it
	BIO* rsaPublicKeyFile = BIO_new_file("rsapublickey.pem", "r" );
	RSA* rsaPublicKey = PEM_read_bio_RSA_PUBKEY(rsaPublicKeyFile, NULL, 0, NULL);

    
	//Create the signature & encrypting
	int encryptedChallengeSize = RSA_size(rsaPublicKey)-11;
	char encryptedChallenge[encryptedChallengeSize];
	memset(encryptedChallenge, 0, encryptedChallengeSize);  
	int encryptBufferSize = RSA_public_encrypt(randNumSize, (const unsigned char*)challenge, (unsigned char*) encryptedChallenge, rsaPublicKey, RSA_PKCS1_PADDING);

	for( int i = 0; i < randNumSize; i++)
	{
		challenge[i] = randNum[i];
	}

	string challenge_1 = buff2hex((const unsigned char*)randNum,randNumSize).c_str();
	string challenge_2 = buff2hex((const unsigned char*)encryptedChallenge,encryptedChallengeSize).c_str();

	//SEG FAULTS IF randNumSize is TOO BIG!
	challengeSize = SSL_write(ssl, encryptedChallenge, encryptBufferSize);

	//check to make sure the challenges were sent
	int check = BIO_flush(client);
	if( check == -1 || check == 0 )
	{
		cout << "ERROR: FLUSHING DID NOT RUN CORRECTLY" << endl;
		errors();
		exit(EXIT_FAILURE);
	}	

	cout << endl << "Original Value: " << challenge_1 << endl;
	cout << endl << "Encrypted Value: " << challenge_2 << endl;


	//4. Hash the un-encrypted challenge using SHA1.
	cout << endl << "HASH UN-ENCRYPTED CHALLENGE w/ SHA-1" << endl;

	//Creating a hash buffer
	char hashBuffer[BUFFER_SIZE];
	memset(hashBuffer, 0, sizeof(hashBuffer));
    
	BIO* binfile;
	BIO* boutfile;
	BIO* hash;
	//make the hash encrypted challenge
	binfile = BIO_new(BIO_s_mem());
    
	//store hash
	int bioWritten = BIO_write(binfile, challenge, BUFFER_SIZE);
    
	//make a new hash
	hash = BIO_new(BIO_f_md());
	BIO_set_md(hash, EVP_sha1());
	//chain hash
	BIO_push(hash, binfile);

	//get the value from the hash stream and record that size
	int bioRead = BIO_gets(hash, hashBuffer, BUFFER_SIZE);

    
	//5. Receive the signed hash of the random challenge from the server, and recover the hash using the RSA public key.
	cout << endl << "RECEIVE SIGNED HASH FROM SERVER, THEN RECOVER HASH USING RSA PUBLIC KEY" << endl;

	//Receiving the signed key from the server
	int readChallengeSize = 0;
	char readChallenge[BUFFER_SIZE];
	memset(readChallenge, 0, sizeof(readChallenge));
	readChallengeSize = SSL_read(ssl, readChallenge, BUFFER_SIZE);
    
	cout << "RECEIVED SIGNATURE: " << buff2hex((const unsigned char*)readChallenge, readChallengeSize).c_str() << endl;
    
	//decrypt the number sent from the server
	//create a new buffer to store the decrypted value
	int bufferSize = readChallengeSize;
	char decryptedSigned[bufferSize];
	memset(decryptedSigned, 0, bufferSize);
    
	//decrypt the buffer and store the size of the new key
	int decryptedBufferSize = RSA_public_decrypt(bufferSize, (const unsigned char*) 					readChallenge, (unsigned char*) decryptedSigned, 						rsaPublicKey, RSA_PKCS1_PADDING);    

	//check if there is an error
	if( decryptedBufferSize == -1 )
	{
		errors();
		exit(EXIT_FAILURE);
	}
    
	cout << endl << "COMPARE HASHES TO MAKE SURE THEY ARE THE SAME" << endl;

	string clientHash = hashBuffer;
	string serverHash= decryptedSigned;

	//if not same then Server could not be authenticated
	if( clientHash != serverHash )
	{
		cout << endl << "ERROR: GENERATED KEY NOT THE SAME AS VERIFIED KEY" << endl;
		exit(EXIT_FAILURE);
	}
    
	//print the outputs
	cout << endl << "The client hash is: " << buff2hex((const unsigned char*)hashBuffer,bioRead).c_str() << endl;
	cout << endl << "The server hash is: " << buff2hex((const unsigned char*)decryptedSigned,decryptedBufferSize).c_str() << endl;


    
    
    BIO* rsaPrivateKeyFile = BIO_new_file("rsaprivatekey.pem","r");
    RSA* rsaPrivateKey;
    rsaPrivateKey = PEM_read_bio_RSAPrivateKey(rsaPrivateKeyFile,NULL, 0, NULL);
    char* todo = argv[5];		//action
    SSL_write(ssl, todo, BUFFER_SIZE);	//sending filename to server
    
    char* filename = argv[6];		//filename
    SSL_write(ssl, filename, BUFFER_SIZE);	//sending filename to server

    //string action2 = todo;
    //check if action is to send or receive a file.
    if(action == "send")
    {
        cout << endl << "Client sending file...." << endl;
        //void Send_file(SSL* ssl, RSA* rsaPrivateKey, BIO* server, char* fileName)
        Send_file(ssl, rsaPrivateKey, client, filename);
        cout << endl << "File Sent!" << endl;
    }
    else if(action == "receive")
    {
        cout << endl << "Client Receiving file...." << endl;
        receive_file(ssl, filename);
        cout << endl << "File Received!" << endl;
    }


	SSL_shutdown(ssl);
	SSL_CTX_free(ctx);
        SSL_free(ssl);


	return 0;
}

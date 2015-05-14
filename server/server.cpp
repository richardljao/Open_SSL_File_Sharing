#include <iostream>
#include <fstream>

#include <openssl/ssl.h>	//SSL Library
#include <openssl/bio.h>	//BIO Library
#include <openssl/sha.h>	//SHA1 Hash Library
#include <openssl/rsa.h>        //RSA Library
#include <openssl/pem.h>        //PEM library
#include <openssl/err.h>	//ERROR Library

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
    
    cout << endl << "Bytes Sent = " << bytesSent << endl;

    
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


//your_server_app_name -port portnumber
//use -port 4444 preferably
int main(int argc, char *argv[])
{
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	if(argc != 3)
	{
		cout << endl << "INCORRECT PARAMETERS!!!" << endl;
		cout << "CORRECT PARAMETERS: a.out -port portnumber" << endl;
		return 0;
	}

	char* port = argv[2];



	//1. Wait for client connection request, and establish an SSL connection with the client.
	cout << endl << "Waiting for request...." << endl;

	//Make Diffle-Helman object and generate the parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
        DH_check(dh, &dh_err);

        if (dh_err != 0)
        {
                printf("Error during Diffie-Helman parameter generation.\n");
	        errors();
                exit(EXIT_FAILURE);
        }


	//Create SSL Context
	SSL_CTX* ctx = SSL_CTX_new( SSLv23_method() );
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);	//Given from assignment instructions

        SSL_CTX_set_tmp_dh(ctx, dh);
        if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
        {
		cout << endl << "ERROR: COULD NOT CREATE SSL CONTEXT" << endl;
        	errors();
                exit(EXIT_FAILURE);
        }

	//Create BIO object
        BIO* server = BIO_new( BIO_s_accept() );
        BIO_set_accept_port( server, port );
        BIO_do_accept( server );

        //Create SSL object
        SSL* ssl = SSL_new( ctx );
        if (!ssl)
        {
		cout << endl << "ERROR: COULD NOT CREATE SSL OBJECT" << endl;
		errors();
		string error= "COULD NOT CREATE SSL OBJECT";
		SSL_write(ssl, error.c_str(), 128);
		SSL_shutdown(ssl);
                exit( EXIT_FAILURE );
        }
        SSL_set_accept_state( ssl );
        SSL_set_bio( ssl, server, server );
        if (SSL_accept( ssl ) <= 0)
        {
		cout << endl << "ERROR: COULD NOT CONNECT TO SSL" << endl;
		errors();
		string error= "COULD NOT CONNECT TO SSL";
		SSL_write(ssl, error.c_str(), 128);
		SSL_shutdown(ssl);
                exit(EXIT_FAILURE);
        }

	cout << endl << "CONNECTED TO PORT: " << port << endl;



	//2. Receive an encrypted challenge from the client and decrypt it using the RSA private key.
	cout << endl << "GET ENCRYPTED CHALLENGE & DECRYPT w/ RSA PRIVATE KEY" << endl;

	//SSL_read
	string challenge = "";
	int bufferSize = 0;
	char buffer[BUFFER_SIZE];
	memset(buffer, 0, BUFFER_SIZE);
  
	//read what writen from the client
	bufferSize = SSL_read(ssl, buffer, BUFFER_SIZE);

    cout << endl << "RECEIVED CHALLENGE: " << buff2hex((const unsigned char*)buffer,bufferSize).c_str() << endl;
  
	//decrypt the challenge using the rsa private key
	BIO* rsaPrivateKeyFile = BIO_new_file("rsaprivatekey.pem","r");
	RSA* rsaPrivateKey;
	rsaPrivateKey = PEM_read_bio_RSAPrivateKey(rsaPrivateKeyFile,NULL, 0, NULL); 

	//create a new buffer for challenge
	int challengeSize = bufferSize;
	char decryptedChallenge[challengeSize];
	memset(decryptedChallenge, 0, challengeSize);

  
	//decrypt the buffer and store the size of the new key
	int decryptedChallengeSize = RSA_private_decrypt(challengeSize, (const unsigned char*) 			buffer,(unsigned char*) decryptedChallenge, rsaPrivateKey, RSA_PKCS1_PADDING);  

	if( decryptedChallengeSize == -1 )
	{
		errors();
		cout << endl << "ERROR: DECRYPTING CHALLENGE FAILED" << endl;
		string error= "DECRYPTING CHALLENGE FAILED";
		SSL_write(ssl, error.c_str(), 128);
		SSL_shutdown(ssl);
		exit(EXIT_FAILURE);
	}

	cout << endl << "Size of the decrypted challenge: " << decryptedChallengeSize << endl;
    cout <<endl << "Challenge after decrypt: " << buff2hex((const unsigned char*)decryptedChallenge,decryptedChallengeSize).c_str() << endl;
	challenge = decryptedChallenge;



	//3. Hash the challenge using SHA1.
	cout << endl << "HASH THE CHALLENGE USING SHA-1" << endl;

	char hashBuffer[BUFFER_SIZE];
	memset(hashBuffer, 0, sizeof(hashBuffer));

	BIO* binfile;
	BIO* boutfile;
	BIO* hash;
	//create a new bio stream
	binfile = BIO_new(BIO_s_mem());
  
	int bioWritten = BIO_write(binfile, buffer, bufferSize);

	hash = BIO_new(BIO_f_md());
	BIO_set_md(hash, EVP_sha1()); 
	BIO_push(hash, binfile);

	int bioRead = BIO_gets(hash, hashBuffer, BUFFER_SIZE); 

	int mdlen = bioRead;
	string sHash = hashBuffer;

	cout << endl << "SHA1 hash: " << buff2hex((const unsigned char*)sHash.c_str(),mdlen) << endl;



	cout << endl << "SIGN THE HASH" << endl;

	//creating encrypted Hash
	int hashEncryptedSize = RSA_size(rsaPrivateKey) - 11;
	char hashEncryptedBuffer[hashEncryptedSize];
	memset(hashEncryptedBuffer, 0, hashEncryptedSize);  
  
	//signing hash
	int encryptedHashSize = RSA_private_encrypt(mdlen, (const unsigned char*)   					(hashBuffer),(unsigned char*) hashEncryptedBuffer, 					rsaPrivateKey, RSA_PKCS1_PADDING);

	int signatureSize = encryptedHashSize;
	char* signature=hashEncryptedBuffer;  


	cout << endl << "SIGNED HASH: " << buff2hex((const unsigned char*)hashEncryptedBuffer, encryptedHashSize).c_str() << endl;





	//5. Send the signed hash to the client.
	cout << endl << "SENDING SIGNED HASH TO CLIENT" << endl;

	int sentHashSize = SSL_write(ssl, hashEncryptedBuffer, signatureSize);
	int check = BIO_flush(server);
	if( check == -1 || check == 0 )
	{
		cout << endl << "ERROR: DID NOT FLUSH CORRECTLY" << endl;
		errors();
		string error= "DID NOT FLUSH CORRECTLY";
		SSL_write(ssl, error.c_str(), 128);
		SSL_shutdown(ssl);
		exit(EXIT_FAILURE);
	}
    // get action
    //6. Receive a filename request from the client.
    cout << endl << "RECEIVE ACTION AND FILENAME REQUEST FROM CLIENT" << endl;
    char todo[BUFFER_SIZE];
    memset(todo,0,sizeof(todo));
    SSL_read(ssl,todo,BUFFER_SIZE);
    
    cout << endl << "Client Action: " << todo << endl;
   
    
    char fileName[BUFFER_SIZE];
    memset(fileName,0,sizeof(fileName));
    SSL_read(ssl,fileName,BUFFER_SIZE);
    
    cout << endl << "File Name: " << fileName << endl;
    
    string test = todo;
    if( test == "receive")
    {
        cout << endl << "Sending file......." << endl;
        //client is receiving file
        Send_file(ssl, rsaPrivateKey, server, fileName);
        cout << endl << "File Sent!" << endl;
    }
    else if(test == "send")
    {
        //server is receiving file.
        cout << endl << "Receiving file......." << endl;
        receive_file(ssl, fileName);
        cout << endl << "File Received" << endl;
    }

	SSL_shutdown(ssl);
        BIO_free_all(server);

	return 0;
}

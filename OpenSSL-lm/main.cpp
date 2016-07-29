//
//  main.cpp
//  OpenSSL-lm
//
//  Created by 刘伟 on 16/7/29.
//  Copyright © 2016年 Linkim. All rights reserved.
//

#include <iostream>
#include "LMRSACryptor.h"

unsigned char* makeAlphaString( int dataSize );

int main(int argc, const char * argv[]) {
    
    char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"\
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwGlZJw33h1GE+jLVIhNJ\n"\
    "czI304XKiBOpkw1ENBJr/rYOzDXqgBsVLxW6b4SDYqJiHnW/PodwK5IMlWesiUGk\n"\
    "ApJ8lH/GbT28oNFQYg1Oc0NtLjaZ+p2iU6wL9lO9XOMJjMxcXYv4FFusu6y9a7TG\n"\
    "SyntkhSb2X2y2CSxjJtj+oHMRW4wiytakmqMklRCqL8TuKTL5IeJshrty61eRC1f\n"\
    "oVdZMYVYYHm9uEhubVfrsRaNg+kAb+J1ThzdlQESomtalIsNeh3X3bB+Z0kaZziQ\n"\
    "+P4VRwXwUaq2InN5CT3pXDjQCjbxlVwf2rTwtvU442/Gxysi5+PnbOiViVwjDIIa\n"\
    "/QIDAQAB\n"\
    "-----END PUBLIC KEY-----\n";
    
    char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
    "MIIEogIBAAKCAQEAwGlZJw33h1GE+jLVIhNJczI304XKiBOpkw1ENBJr/rYOzDXq\n"\
    "gBsVLxW6b4SDYqJiHnW/PodwK5IMlWesiUGkApJ8lH/GbT28oNFQYg1Oc0NtLjaZ\n"\
    "+p2iU6wL9lO9XOMJjMxcXYv4FFusu6y9a7TGSyntkhSb2X2y2CSxjJtj+oHMRW4w\n"\
    "iytakmqMklRCqL8TuKTL5IeJshrty61eRC1foVdZMYVYYHm9uEhubVfrsRaNg+kA\n"\
    "b+J1ThzdlQESomtalIsNeh3X3bB+Z0kaZziQ+P4VRwXwUaq2InN5CT3pXDjQCjbx\n"\
    "lVwf2rTwtvU442/Gxysi5+PnbOiViVwjDIIa/QIDAQABAoIBAAh525KL2/abEbeP\n"\
    "27G3lcm8UZdA0o4yB4tRz0pX8Wf0DyzRxzXDe6hqVZ8qADutGZNr7nPLtZZFxcYj\n"\
    "Hgeh2569Yz2Lb2tKh++xqM/Y9DbBpqKdhyTyIr962cANKk9YNQh9zCfWzaPf8fkG\n"\
    "gAWpnf6bpzqDK+Zl0iYRX7zo73uOfqoiN7bW0VwbWqlK1G9KRP/bOGEpCgwceDw9\n"\
    "CNrDhn47dkrKLOHVezGXRH3u/i2NdbUfhrlAoWruwlVvfLrsIn9szJxor45QNnnh\n"\
    "eslQsw8e9XcD9DyC4dk7WL1M/grylUk30KPLsAunsMWK49457NoG6rGaxltxx+4k\n"\
    "oPvjCAUCgYEA4AnaffEGDcR2UI3SHfeEHUz4s3Lyd0gnoSKtrlSEDdDm+uEjROgD\n"\
    "fpK65A5Gw7m9dfvbHLcsNWnBzWtQ6B1BHbi8W9S6A28Nka8RvOHHrSLlPzSMbnJh\n"\
    "RVnc5kh+pwtz27bNFORsUZLpZXz7K7RYZoUfaM3cqA2/XuCx9X7gw0sCgYEA29xw\n"\
    "3M49C/2viHxDNZ5Hy2chY7GRPZWe2ggIXnaWrOc7YkgvB3+zbchQ+CGSyWRcFXC2\n"\
    "YexgiBxhsKT1wo8FC9x9jfscXLkkfsGenFH3o+szHsle4gqjPBn5F4c4zL1tab87\n"\
    "O4R7evxbgvWNCRg7XtfsoJsvELXIWVY81Rmk5dcCgYBh4cw1BA3qC/DJRv0LHK37\n"\
    "AzsRY+ItXTf7PaR2KvS6+I9CAwUewONt9Ht00gv2zXrKRmw3woutFnSW5BEoKEff\n"\
    "zWt2D53pjCZ4hO2SAW705O8Vy0ajppN68kUB06CKKQXIc7hsLVRp227faVhvgs6w\n"\
    "k+7iIjcKsV7v++mkYXefuwKBgA/s0LP9sEhNEMjXD1sz4sll5/I7q2SFkOMED+8f\n"\
    "sdxGR3Pf/KATbOC30L2YWPSDc3QOHPfM0lUpkR3lZPO5vkjUqLd/B9fjhTQ1PBLg\n"\
    "kQprf+Fr/pZq5NX2n6dHoSKbWfB97IFsIDGRU+ORe6y795jwFPCxLOCN+jwWVgOt\n"\
    "ftczAoGAd5XO9Afh9sLT64y+D9+P8vNM18heyud3Tk8cz6giiOaqOvDomHuvDEdy\n"\
    "v7f945oeqyqo2Wx7iQOcWiYm82AvhxbKB+bCkDJDr8ngWU0Da+N+i+bWRYzInP2u\n"\
    "u+49IvQ5abSAyC2rqpraVJn7PdHhIfYPTxr0LShlOg30SAjFtrs=\n"\
    "-----END RSA PRIVATE KEY-----\n";
    
//    char* rxOverHTTP = (char*)"mS1/m2zmkCmjHjlb3wW0G8iEAg+EiAo52wbtgNOszzPOHuLDMjgrwk3a45aiPXUIRLmtkbnx9SghQ5bpwqY5q2VE9gh/XZa/MrRMZgKOZX4R2fZ61x1jwjrjnbUGoKOjWq3/0iJKSBrs1eQ9vX5pFrNwRQvOUcr2hisKqfyPFxtUVELa4F0d9llRop6jBl8A/cjNsiLYZ3TguvRUX9E8PW3/I4XXsxwZ0SvZWnCh+2HTxnGQdunfkSWhIUEl71jg7Y0vumPg1juXX7DJHWknqin6Pe46xaFrpAKUvI6B5bPLMBRk7BH5ladLTvTI2QqkBev4Vl3dmKzCbNCoRu6P4w==";
//    
//    // LOAD PUBLIC KEY
//    RSA *pubKey = loadPUBLICKeyFromString(publicKey);
//    // Now we got the data at the server.  Time to decrypt it.
//    int rBinLen ;
//    unsigned char* rBin = public_decrypt_base64( pubKey, rxOverHTTP, &rBinLen ) ;
//    printf("Decrypted %d bytes, the recovered data is:\n%.*s\n\n", rBinLen, rBinLen, rBin ) ; // rBin is not necessarily NULL
//    // terminated, so we only print rBinLen chrs
//    
//    RSA_free(pubKey) ;
    
    ERR_load_crypto_strings();
    
    puts( "We are going to: private_decrypt_base64( unbase64( base64( public_encrypt_base64( <<binary data>> ) ) ) )" );
    
    // String to encrypt, INCLUDING NULL TERMINATOR:
    int dataSize=37 ; // 128 for NO PADDING, __ANY SIZE UNDER 128 B__ for RSA_PKCS1_PADDING
    unsigned char *str = makeAlphaString( dataSize ) ;
    printf( "\nThe original data is:\n%s\n\n", (char*)str ) ;
    
    // LOAD PUBLIC KEY
    RSA *pubKey = loadPUBLICKeyFromString( publicKey ) ;
    
    int asciiB64ELen ;
    char* asciiB64E = public_encrypt_base64( pubKey, str, dataSize, &asciiB64ELen ) ;
    
    RSA_free( pubKey ) ; // free the public key when you are done all your encryption
    
    printf( "Sending base64_encoded ( public_encrypt ( <<binary data>> ) ):\n%s\n", asciiB64E ) ;
    puts( "<<----------------  SENDING DATA ACROSS INTERWEBS  ---------------->>" ) ;
    
    char* rxOverHTTP = asciiB64E ; // Simulate Internet connection by a pointer reference
    printf( "\nRECEIVED some base64 string:\n%s\n", rxOverHTTP ) ;
    puts( "\n * * * What could it be?" ) ;
    
    // Now decrypt this very string with the private key
    RSA *privKey = loadPRIVATEKeyFromString( privateKey ) ;
    
    // Now we got the data at the server.  Time to decrypt it.
    int rBinLen ;
    unsigned char* rBin = private_decrypt_base64( privKey, rxOverHTTP, &rBinLen ) ;
    printf("Decrypted %d bytes, the recovered data is:\n%.*s\n\n", rBinLen, rBinLen, rBin ) ; // rBin is not necessarily NULL
    // terminated, so we only print rBinLen chrs
    
    RSA_free(privKey) ;
    
    bool allEq = true ;
    for( int i = 0 ; i < dataSize ; i++ )
        allEq &= (str[i] == rBin[i]) ;
    
    if( allEq ) puts( "DATA TRANSFERRED INTACT!" ) ;
    else puts( "ERROR, recovered binary does not match sent binary" ) ;
    free( str ) ; 
    free( asciiB64E ) ; // rxOverHTTP  
    free( rBin ) ;
    
    ERR_free_strings();
    
    return 0;
}


unsigned char* makeAlphaString( int dataSize )
{
    unsigned char* s = (unsigned char*) malloc( dataSize ) ;
    
    int i;
    for( i = 0 ; i < dataSize ; i++ )
        s[i] = 65 + i ;
    s[i-1]=0;//NULL TERMINATOR ;)
    
    return s ;
}
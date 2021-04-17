#define BIND_RESPONSE "\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00"

// Packet
//
// 30 packet id [ldap]
// 0c size du packet en byte
// {
//
//  Message ID (message count)
//  02 (int)
//  01 (taille du int)
//  01 (valeur) [premier message]
//
//  ElementContainer ou Op(eration)
//  61 (type) [bind response]
//  07 (taille du ContentElement en byte)
//  {
//
//    Element[0]
//    0a (type) [enum]
//    01 (taille)
//    00 (valeur) [=success]
//
//    Element[1]
//    04 (type: string) [  matchedDN     LDAPDN,]
//    00 (taille)
//
//    Element[2]
//    04 (type: string) [errorMessage  ErrorMessage]
//    00 (taille)
//
//  }
//
// }
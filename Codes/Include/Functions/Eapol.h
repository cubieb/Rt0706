#ifndef _Eapol_h_
#define _Eapol_h_

CxxBeginNameSpace(Router)

/*
EAP  : Extensible Authentication Protocol
EAPOL: Eap Over Lan.  
*/
struct WpaHandshake
{
    uchar_t stmac[6];     /* supplicant MAC           */
    uchar_t snonce[32];   /* supplicant nonce         */
    uchar_t anonce[32];   /* authenticator nonce      */
    uchar_t keymic[16];   /* eapol frame MIC          */
    uchar_t eapol[256];   /* eapol frame contents     */
    uint32_t eapol_size;  /* eapol frame size         */
    uchar_t keyver;       /* key version (TKIP / AES) */
    uchar_t state;        /* handshake completion     */
};

CxxEndNameSpace
#endif
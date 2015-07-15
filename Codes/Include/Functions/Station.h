#ifndef _Station_h_
#define _Station_h_

CxxBeginNameSpace(Router)

class St
{
public:
    St(const Mac&);
    const Mac& GetMac() const;

private:
    St();
    Mac mac;
    
    /* Handshake Information, 
    EAP  : Extensible Authentication Protocol
    EAPOL: Eap Over Lan.  */
    uint8_t  stmac[6];     /* supplicant MAC           */
    uint8_t  snonce[32];   /* supplicant nonce         */
    uint8_t  anonce[32];   /* authenticator nonce      */
    uint8_t  keymic[16];   /* eapol frame MIC          */
    uint8_t  eapol[256];   /* eapol frame contents     */
    uint32_t eapol_size;   /* eapol frame size         */
    uint8_t  keyver;       /* key version (TKIP / AES) */
    uint8_t  state;        /* handshake completion     */
};

CxxEndNameSpace

#endif
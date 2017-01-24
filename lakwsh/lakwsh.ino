/* 
 * RST/Reset   RST          9
 * SPI SS      SDA(SS)      10
 * SPI MOSI    MOSI         11 / ICSP-4
 * SPI MISO    MISO         12 / ICSP-1
 * SPI SCK     SCK          13 / ICSP-3
 */

#include <SPI.h>
#include <MFRC522.h>
#define RST_PIN    9
#define SS_PIN     10
MFRC522 mfrc522(SS_PIN,RST_PIN);
MFRC522::MIFARE_Key key;
MFRC522::StatusCode status;

void setup(){
    Serial.begin(9600);
    SPI.begin();          // 初始化SPI介面
    mfrc522.PCD_Init();   // 初始化MFRC522卡片
    beep(1,500);
    Serial.println("Init finished.\n");
    key={0x6C,0x61,0x6B,0x77,0x73,0x68};   //密碼B
}

void loop(){
    if(!detect()){
        delay(1000);
        return;
    }
    //if(!ReadAll()) Serial.println("Failed");         //讀取卡內所有數據
    //if(!ResetCard()) Serial.println("Failed");       //清除卡內除權限控制塊外所有數據
    //
    /**-------------------更改密碼------------------
    key={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};      //原卡KeyB用於獲取權限寫入數據
    // 权限控制 0F00FF0F KeyB无敌 KeyA无用
    // 前6個位為新寫入的KeyA，中間4位為權限控制，最後6位為KeyB
    byte data[]={0x00,0x00,0x00,0x00,0x00,0x00,0x0F,0x00,0xFF,0x0F,0x6C,0x61,0x6B,0x77,0x73,0x68};
    // 共有16個扇區，每個扇區一套獨立密碼保護
    //只會更改權限控制塊，扇區內另外3個數據塊不會被改動
    for(byte i=1;i<17;i++){
        if(!ChangePwd(i,data)){break;}
    }
    ----------------------------------------------**/
    /**-------------------讀取某塊------------------
    byte Block=60;         //讀取第60塊
    if(!GetAuth(Block)){
        Serial.print("無法獲取第");
        Serial.println(Block);
        Serial.println("塊的權限");
    }else{
        Read(Block);
    }
    ----------------------------------------------**/
    /**-------------------寫入某塊------------------
    byte Block=60;         //寫入第60塊
    byte data[]={0x12,0x34,0x56,0x78,0x90,0xAB,0xCD,0xEF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};   //要寫入的數據
    if(!GetAuth(Block)){
        Serial.print("無法獲取第");
        Serial.println(Block);
        Serial.println("塊的權限");
    }else{
        if(!Write(Block,data)){
            Serial.print("無法寫入數據到第");
            Serial.println(Block);
            Serial.println("塊");
        }else{
            Read(Block);
        }
    }
    ----------------------------------------------**/
    Serial.println("Finished.\n");
    beep(2,100);
    HaltCard(1000);
    return;
}

bool ReadAll(){
    for(byte Block=3;Block<64;Block+=4){
        if(!GetAuth(Block)){
            Serial.print("Auth Error in Block: ");
            Serial.println(Block);
            Serial.println();
            return false;
        }
        for(char i=3;i+1>0;i--) Read(Block-i);
    }
    return true;
}

bool ResetCard(){
    byte data[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    for(byte Block=3;Block<64;Block+=4){
        if(!GetAuth(Block)){
            Serial.print("Auth Error in Block: ");
            Serial.println(Block);
            Serial.println();
            return false;
        }
        for(byte i=3;i>0;i--){
            if(Block-i==0) continue;
            if(!Write(Block-i,data)){
                Serial.print("Write Error in Block: ");
                Serial.println(Block-i);
                Serial.println();
                return false;
            }
            Read(Block-i);
        }
    }
    return true;
}

bool ChangePwd(byte sector,byte data[]){
    if(!GetAuth(sector*4-1)){
        Serial.print("Auth Error in Block: ");
        Serial.println(sector*4-1);
        Serial.println();
        return false;
    }
    if(Write(sector*4-1,data)) return true;
    return false;
}

//-----------------------------------Basic Function-----------------------------------//

void beep(byte btime,unsigned long blong){
    for(byte i=0;i<btime;i++){
        tone(8,2489,blong);
        delay(blong+100);
    }
}

bool detect(){
    if(!mfrc522.PICC_IsNewCardPresent()) return false;    // 是否感應到卡片
    if(!mfrc522.PICC_ReadCardSerial()) return false;      // 是否已讀取到卡片的ID
    MFRC522::PICC_Type piccType=mfrc522.PICC_GetType(mfrc522.uid.sak);
    if(piccType!=MFRC522::PICC_TYPE_MIFARE_1K) return false;
    beep(1,200);
    return true;
}

void HaltCard(int delaytime){
    // Halt PICC
    mfrc522.PICC_HaltA();
    // Stop encryption on PCD  也可省略
    mfrc522.PCD_StopCrypto1();
    delay(delaytime);
    return;
}

bool Read(byte Block){
    byte buffer[18];
    byte size=sizeof(buffer);
    status=(MFRC522::StatusCode)mfrc522.MIFARE_Read(Block,buffer,&size);
    if(status!=MFRC522::STATUS_OK) return false;
    Serial.print("Block ");
    Serial.print(Block);
    Serial.print(": ");
    PrintHex(buffer,16);
    return true;
}

bool Write(byte Block,byte data[]){
    status=(MFRC522::StatusCode)mfrc522.MIFARE_Write(Block,data,16);
    if(status!=MFRC522::STATUS_OK) return false;
    return true;
}

bool GetAuth(byte Block){
    status=(MFRC522::StatusCode)mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B,Block,&key,&(mfrc522.uid));
    if(status!=MFRC522::STATUS_OK) return false;
    beep(1,100);
    return true;
}

void PrintHex(byte *buffer,byte bufferSize){
    for(byte i=0;i<bufferSize;i++){
        Serial.print(buffer[i]<0x10?" 0":" ");
        Serial.print(buffer[i],HEX);
    }
    Serial.println();
}

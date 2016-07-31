#include <Servo.h>
#include <sha256.h>
#include <IRremote.h>

//#define ISREMOTE

const int RECV_PIN = 7; // Digital IR input pin
// Hack to allow an IR transmitter to be bodged directly onto
// the ardunio pro mini PCB
const int IR_GND = 8;
const int IR_VCC = 9;

IRrecv irrecv(RECV_PIN);
IRsend irsend; //IR LED on pin 3

decode_results results;

bool failAuth;

const long authTimeout = 10000;//ms

char input[35];
int inPos;

const int lock_pos = 165;
const int unlock_pos = 20;
Servo lock;
const int lockPin = 10;

const int safe_off = 13;
const int button_led = 12;
const int buttonInput = 11;

bool locked = true;

const char *authmode_off = "off";
const char *authmode_repeat = "repeat";
const char *authmode_hmac_sha256 = "hmac_sha256";

bool awaiting_response = false;

//By default, on boot, the authorisation mode is hmac_sha256
char *curAuthMode = (char *)authmode_hmac_sha256;

#define CHALLENGE_LENGTH (28)
char challenge[CHALLENGE_LENGTH];

char *genChallenge(){
  for (int i = 0; i<= CHALLENGE_LENGTH-2; i++){
    challenge[i] = random(32, 126);
    if ((challenge[i] == '/') || (challenge[i] == '|')){
      challenge[i] = '!';
    }
  }
  challenge[CHALLENGE_LENGTH-1] = '\0';
  return challenge;
}

void setup()
{
  // Seed the random number generator with ludicrous amounts of
  // bogus analog read data.
  randomSeed(analogRead(0) *
             analogRead(1) *
             analogRead(2) *
             analogRead(3) *
             analogRead(4));
#ifdef ISREMOTE
  Serial.begin(9600);
#endif
  input[32] = '\0';
  
  lock.attach(lockPin);
  lock.write(lock_pos);
  
  irrecv.enableIRIn(); // Start the receiver
  
  pinMode(IR_GND, OUTPUT);
  pinMode(IR_VCC, OUTPUT); 
  digitalWrite(IR_GND, LOW);
  digitalWrite(IR_VCC, HIGH);
  digitalWrite(safe_off, HIGH);
  pinMode(buttonInput, INPUT);
  pinMode(button_led, OUTPUT);
  digitalWrite(button_led, LOW);
}

void sendData(char startByte, const char *data){
  irsend.sendNEC(startByte, 32);
  int msgLen = strlen(data);
  if (msgLen>32){
    //Serial.println("Outgoing message too long.");
  }
  delay(50);
  for(int i = 0; i<= msgLen; i++){
    irsend.sendNEC(data[i], 32);
    delay(50);
  }
  irsend.sendNEC('\\', 32);
  irrecv.enableIRIn();
  irrecv.resume();
}

// Replace each byte in a sequence with the ascii char for the hex value
// of the last four bits
void inplace_hex_string(char *target, int len){
  for (int i = 0; i<= len-1; i++){
    target[i] = 0x30 + (target[i] & 0xf);
    if (target[i] > 0x39) { target[i] += 7;}
  }
  target[len] = '\0';
}

void sendCommand(const char *command){
  sendData('|', command);
}

void sendCR(const char *cr){
  sendData('/', cr);
}

bool cr = false, com = false;

void command_lock(){
  //Serial.println("Locking");
  lock.write(lock_pos);
  delay(1000);
  digitalWrite(safe_off, HIGH);
}

void command_unlock(){
  //Serial.println("Unocking for two seconds");
  digitalWrite(safe_off, LOW);
  delay(1000);
  lock.write(unlock_pos);
  delay(5000);
  lock.write(lock_pos);  
  delay(1000);
  digitalWrite(safe_off, HIGH);
}

void command_unlock_hard(){
  //Serial.println("Warning! Hard unlock");
  digitalWrite(safe_off, LOW);
  delay(1000);
  lock.write(unlock_pos);
}

void command_ping(){
  //Serial.println("Sending pong");
  sendCommand("pong");
}

void command_authmode_off(){
  curAuthMode = (char *)authmode_off;
}

void command_authmode_repeat(){
  curAuthMode = (char *)authmode_repeat;
}

void command_authmode_hmac_sha256(){
  curAuthMode = (char *)authmode_hmac_sha256;
}

void command_query_authmode(){
  char reply[33];
  reply[0] = '\0';
  strcat(reply, "RES:");
  strcat(reply, curAuthMode);
  sendCommand(reply);
}

bool gotcr;

bool authorise(){
  gotcr = false;
  if (curAuthMode == (char *)authmode_off){
    //Serial.println("Auth disabled, access granted");
    return true; // No authorisation enabled, allways allowed in.
  }
  else{
    //Serial.print("Auth mode is '"); Serial.print(curAuthMode); Serial.println("'");
    //Serial.print("Sending auth challenge...");
    char * thisChallenge = genChallenge();
    sendCR(thisChallenge);
    awaiting_response = true;
    //Serial.println(" [Done]");
    char *expectedReply;
    if (curAuthMode == (char *)authmode_repeat){
      expectedReply = thisChallenge;
    }
    else if (curAuthMode == (char *)authmode_hmac_sha256){
      Sha256.initHmac((uint8_t *)secretkey, ); // key, and length of key in bytes
      Sha256.print(thisChallenge);
      expectedReply = (char *)Sha256.resultHmac();
      inplace_hex_string(expectedReply, 30);
    }
    else{
      //Serial.println("Unexpected fault, access denied");
      awaiting_response = false;
      return false; //Something's wrong, nobody gets in
    }
    //Serial.print("Expecting: ");
    //Serial.println(expectedReply);
    long startWait = millis();
    long endWait = startWait + authTimeout;
    while (millis() < endWait){
      
      if (irrecv.decode(&results)) {
        handle(&results);
        irrecv.resume(); // Receive the next value
      }
      if (com){
        //Serial.println("Incorrect (com), access denied");
        awaiting_response = false;
        return false; // incorrect response
      }
      if (gotcr){
        bool correct = strcmp(input, (char *)expectedReply) == 0;
        if (correct){
          //Serial.println("access granted");
        }
        else{
          //Serial.println("Incorrect (cr), access denied");
        }
        awaiting_response = false;
        return correct;
      }
    }
    //Serial.println("Timeout");
    awaiting_response = false;
    return false;
  }
}

typedef struct {
  const char *text;
  void (*function)(void);
  bool needsAuth;
} command;

#define NUM_COMMANDS (8)
command commands[NUM_COMMANDS] = {
  {.text="ping",                 .function=command_ping,                 .needsAuth=false},
  {.text="query_authmode",       .function=command_query_authmode,       .needsAuth=false},
  {.text="lock",                 .function=command_lock,                 .needsAuth=true},
  {.text="unlock",               .function=command_unlock,               .needsAuth=true},
  {.text="unlock_hard",          .function=command_unlock_hard,          .needsAuth=true},  
  {.text="authmode off",         .function=command_authmode_off,         .needsAuth=true},
  {.text="authmode repeat",      .function=command_authmode_repeat,      .needsAuth=true},
  {.text="authmode hmac_sha256", .function=command_authmode_hmac_sha256, .needsAuth=true}
};


bool pressButtonNow(){
  unsigned long endTime = millis()+5000;
  unsigned long toggleTime = millis()+200;
  int buttonState = 0;
  while(millis() < endTime){
    if (millis()>toggleTime){
      toggleTime += 200;
      digitalWrite(button_led, buttonState = !buttonState);
    }
    if (digitalRead(buttonInput) == LOW){
      digitalWrite(button_led, LOW);
      return true;
    }
  }
  digitalWrite(button_led, LOW);
  return false;
}

void handleCommand(){
  //Serial.println(input);
  digitalWrite(safe_off, LOW);
  for (int i = 0; i<= NUM_COMMANDS -1; i++){
    if (strcmp(input, commands[i].text) == 0){
      //Serial.println("Command is valid");
      if (commands[i].needsAuth){
        //Serial.println("Requires authentication");
        if (!authorise()){
          //Serial.println("Auth failed.");
          digitalWrite(safe_off, HIGH);
          return;
        }
      }
      //Serial.println("Awaiting button press...");
      if (pressButtonNow()){
        //Serial.println("Pressed");
        commands[i].function();
      }
      else{
        //Serial.println("Timeout");
      }
    }
  }
  digitalWrite(safe_off, HIGH);
}

void handleCR(){
  gotcr = true;
  //Serial.println("Got CR");
  //Serial.println(input);
  //If we are waiting for a response...
  if (awaiting_response){
  }
  else{
    char *expectedReply;
    if (curAuthMode == (char *)authmode_repeat){
        expectedReply = input;
    }
    else if (curAuthMode == (char *)authmode_hmac_sha256){
      Sha256.initHmac((uint8_t *)secretkey, ); // key, and length of key in bytes
      Sha256.print(input);
      expectedReply = (char *)Sha256.resultHmac();
      inplace_hex_string(expectedReply, 30);
    }
    //Serial.println("Respond:");
    //Serial.println((char *)expectedReply);
    if (failAuth){
      sendCR("wrong_response");
    }
    else{
      sendCR((char *)expectedReply);
    }
  }
}

void handle(decode_results *results) {
  //Serial.println("Handle!");
  if (results->decode_type == NEC){
    char inByte = results->value;
    if (inByte == '/'){
       // Start challenge or response
       cr = true;
       inPos = 0;
    }
    else if (inByte == '|'){
       // Start command
       com = true;
       inPos = 0;         
    }
    else if (inByte == '\\'){
      input[inPos] = '\0';
      // End
      if (com){
        com = false;
        //Decode command
        handleCommand();
        
      }
      if (cr){
        cr = false;
        //Respond to challenge or verify response
        handleCR();

      }
    }
    else if (cr || com){
      if (inPos > 31){
        //Error
        cr = false;
        com = false;
        //Serial.println("Incoming message too long.");
      }
      else{
        input[inPos++] = inByte;
      }
    }
    //Serial.print("Got byte: ");
    //Serial.println(inByte);
    //Serial.println();
  }
  
}

unsigned long lastTime = millis();

void loop() {
  if (irrecv.decode(&results)) {
    handle(&results);
    irrecv.resume(); // Receive the next value
  }

#ifdef ISREMOTE
  char nextChar = Serial.read();
  if (nextChar == 'u'){
    lastTime = millis();
    Serial.println("send unlock!\n");
    failAuth = false;
    sendCommand("unlock");
    irrecv.enableIRIn();
    irrecv.resume();
  }
  if (nextChar == 'U'){
    Serial.println("send unlock and fail!\n");
    failAuth = true;
    sendCommand("unlock");
    irrecv.enableIRIn();
    irrecv.resume();
  }
  if (nextChar == 'h'){
    Serial.println("send hard unlock!\n");
    failAuth = false;
    sendCommand("unlock_hard");
    irrecv.enableIRIn();
    irrecv.resume();
  }
  if (nextChar == 'l'){
    Serial.println("send lock!\n");
    failAuth = false;
    sendCommand("lock");
    irrecv.enableIRIn();
    irrecv.resume();
  }
#endif
  
}

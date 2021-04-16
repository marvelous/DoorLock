# DoorLock
Arduino code running on an ESP8266 that opens the door lock in the PTL, using LDAP and RFID

## Build steps

### With `Arduino IDE`

Install the following libraries:

    MFRC522

Click on the `Upload` button and you're done!

### With `arduino-cli`
Install libraries, compile and upload:

    arduino-cli lib install MFRC522
    arduino-cli compile --fqbn esp8266:esp8266:d1_mini
    arduino-cli upload -p /dev/ttyUSB0 --fqbn esp8266:esp8266:d1_mini


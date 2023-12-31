# EZSteggo
Easy steganography script for obfuscating data for exfiltration

```
                                             .^:                                                    
                                           .!JYY?:                                                  
                                          ^J5YYY5Y!       .:~!7^                                    
                            ~77!~:.      !Y55Y5Y5557.  :~7JY555Y^                                   
                           :Y5555YJ?~.  ~5555Y5Y5Y55~.?Y555YYYYY7                                   
                           ~5YYY55555Y. .?55P5P555Y! :55555YYYYYJ                                   
                           !5Y5555Y555:   !5PP55PJ:   J5P555Y555?                                   
                           ~55555Y5PP5::^~!7?????7!!!~755PPP5Y?^:!7??JJJ?~                          
                  .~7????7~ ^7?Y5P5J??7777!!~~~~~!!!77777?JJ~. .Y555555557                          
                  .?5555555!  .^7?77!~~~~~~~~~!!!!!!!!!!!!!!!!^7PPP55555Y:                       ^: 
                   ^Y55555P5^~777!~~~!!!!!!!!!!!!!!!!!!!!!!!!!!7?YPPP555!                      :!?: 
                    ~YYY55Y?777!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!7J7~^:   .!J!    :?!. ^Y7..^~!7:  
                     .:~7?77!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!~^.  :Y555!  .J557 ^??!!!77:   
                ...:^!7777!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!7J?!~~?JJJ~:::~??!!!!!!77!.    
     .^~~~!!!!!!!!77777!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!777?77!!!!!7??!!!!!!!!!!!!!!!!!7?7:      
   .~!77777!!!!!!!!!!!!!!!!!!!!7777?7!!!!!!!!!!!!!!!!!!!!!!!!!!???7!!!7???!!!!!!!!!!!!!7?J7^        
  :!!7!!7Y?!!!!!!!7!!!!!77!!!!!~~~~!??!!!!!!!!!!!!!!!!!~~!!~!~~!???7!!7??J?77!7?777??JJ?!:          
 .~!!7~!5G?!!77!~~~~!77!!!!7!!!~!~~~7?7!!!!!!!!!!!!!!!!~!!~~~~~~7??7!7???JJJJJJJJJJJ?!^.            
 :7!!!!!777!~^.      .^!7!!7~~~~!!!~7??!!!!!!!!!!!!!!7!~~~~~~~!7???77???JYYYYYYJ?!^:                
 .~7!7!!!^:.           .^77?~~~~!7!~7??7!!!!!!!!!!!!!?!~~~!~~~!7??????JYYYJ?7~:.                    
   .:..                   :~^~!~~~!~????77!!!!!!!!!7777~!!~~~!!!??7!!!~^:.                          
                            :!!~~~~7?J???????????????JJ?!~!!~~~!??.                                 
                            .~~~~~~7?:^^~~!!!!!!!!!~~~^^:.:~!~~~??.                                 
                             ~!~~~!?~                      :!~~~!?:                                 
                             ~!~~~!J^                      :!~~~!?^                                 
                            .~~~~~!?:                      ^~~~~!?:                                 
                          :?JJ?7!!7~                     .?J??7!7^                                  
                          .~!7?7^:.                      .~!77~:.                                   

 _____ ______  _____ _                         
|  ___|___  / /  ___| |                        
| |__    / /  \ `--.| |_ ___  __ _  __ _  ___  
|  __|  / /    `--. \ __/ _ \/ _` |/ _` |/ _ \ 
| |___./ /___ /\__/ / ||  __/ (_| | (_| | (_) |
\____/\_____/ \____/ \__\___|\__, |\__, |\___/ 
                              __/ | __/ |      
                             |___/ |___/
```


AES Encrypted data steganography tool - encode and decode images with encrypted data

USAGE:

 -- Clone repo // Navigate to project folder // Create a conda/VENV // Load requirements.txt //
 -- Place your target image in the folder, "test.png" is default hardcoded image name but can be adjusted
 -- You can also use the demo image / testtext files to jump right into testing --

For encoding: python SteggoCLI.py /path/to/image.png your_AES_key --encode "your secret data"

For decoding: python SteggoCLI.py /path/to/image.png your_AES_key --decode

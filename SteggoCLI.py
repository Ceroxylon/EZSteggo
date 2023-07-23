import argparse
from stegano import lsb
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64

"""

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

For encoding: python SteggoCLI.py /path/to/image.png your_AES_key --encode "your secret data"

For decoding: python SteggoCLI.py /path/to/image.png your_AES_key --decode

"""


def aes_encrypt(message, key):
    cipher = AES.new(hashlib.sha256(key.encode()).digest(), AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')

def aes_decrypt(ciphertext, key):
    ct = base64.b64decode(ciphertext.encode('utf-8'))
    cipher = AES.new(hashlib.sha256(key.encode()).digest(), AES.MODE_CBC, iv=ct[:16])
    plaintext = unpad(cipher.decrypt(ct[16:]), AES.block_size)
    return plaintext.decode()

def encode(image_name, secret_data, key):
    secret_data = aes_encrypt(secret_data, key)
    secret_image = lsb.hide(image_name, secret_data)
    secret_image.save(image_name.split(".")[0] + "_encoded.png")

def decode(image_name, key):
    secret_data = lsb.reveal(image_name)
    decoded_data = aes_decrypt(secret_data, key)
    print(decoded_data)
    return decoded_data

def main():
    parser = argparse.ArgumentParser(description="EZ Image Steganography")
    parser.add_argument('image', help='Image file path')
    parser.add_argument('key', help='AES key')
    parser.add_argument('-e', '--encode', metavar='DATA', help='Data to hide in the image')
    parser.add_argument('-d', '--decode', action='store_true', help='Decode the image')

    args = parser.parse_args()

    if args.encode:
        encode(args.image, args.encode, args.key)
    elif args.decode:
        decode(args.image, args.key)
    else:
        print("Either --encode or --decode must be specified.")

if __name__ == "__main__":
    main()
